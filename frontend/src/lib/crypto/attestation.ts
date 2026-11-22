// The researcher's browser verifies the enclave before any query leaves it
// (ADR 0010). This module only fetches, caches and hands the bytes to the
// wasm export, which runs all five checks; the verified keys live in worker
// memory and nowhere else.

import type { AttestationTrust } from "../../config/attestation";
import { toB64 } from "../encoding";
import { verifyAttestationBundle, type VerifiedEnclave } from "./envelope";

export type { VerifiedEnclave };

/** Caps copied from `enclave-check`. */
const MAX_FETCH_BYTES = 256 * 1024;
const FETCH_TIMEOUT_MS = 10_000;
/** The backend's CLOCK_SKEW_LEEWAY_SECS: a token this close to `exp` is expired. */
const CLOCK_SKEW_LEEWAY_SECS = 60;

export interface AttestationDeps {
  apiBaseUrl: string;
  trust: AttestationTrust;
  fetch: typeof fetch;
  now: () => number;
}

const base64url = (bytes: Uint8Array) =>
  toB64(bytes.buffer as ArrayBuffer)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");

/** The body as text, or null when it is longer than `MAX_FETCH_BYTES`. */
async function readCapped(response: Response): Promise<string | null> {
  const declared = Number(response.headers.get("content-length"));
  if (declared > MAX_FETCH_BYTES) return null;
  const reader = response.body?.getReader();
  if (!reader) return "";
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > MAX_FETCH_BYTES) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
  const all = new Uint8Array(total);
  let at = 0;
  for (const chunk of chunks) {
    all.set(chunk, at);
    at += chunk.length;
  }
  return new TextDecoder().decode(all);
}

class TimeoutError extends Error {}
/** A refusal with its final message; `fetchBundle` passes these through. */
class Refusal extends Error {}

/** Run `run` with a signal aborted after `FETCH_TIMEOUT_MS`. The timeout also
 *  wins the race against a fetch or body stream that ignores the signal. */
async function withTimeout<T>(run: (signal: AbortSignal) => Promise<T>): Promise<T> {
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      controller.abort();
      reject(new TimeoutError());
    }, FETCH_TIMEOUT_MS);
  });
  try {
    return await Promise.race([run(controller.signal), timeout]);
  } finally {
    clearTimeout(timer);
  }
}

async function fetchBundle(deps: AttestationDeps, challenge: Uint8Array): Promise<string> {
  const url = `${deps.apiBaseUrl}/api/v1/attestation?nonce=${base64url(challenge)}`;
  try {
    return await withTimeout(async (signal) => {
      // The endpoint is unauthenticated: no credentials, no Authorization.
      const response = await deps.fetch(url, { credentials: "omit", signal });
      if (!response.ok) throw new Refusal(`enclave attestation unavailable (${response.status})`);
      const body = await readCapped(response);
      if (body === null) throw new Refusal("enclave attestation response too large");
      return body;
    });
  } catch (err) {
    if (err instanceof Refusal) throw new Error(err.message, { cause: err });
    const why = err instanceof TimeoutError ? "timeout" : "unreachable";
    throw new Error(`enclave attestation unavailable (${why})`, { cause: err });
  }
}

async function fetchKeySet(deps: AttestationDeps): Promise<string> {
  const unreachable = new Error("attestation key set unreachable");
  let body: string | null;
  try {
    body = await withTimeout(async (signal) => {
      const response = await deps.fetch(deps.trust.jwksUrl, { credentials: "omit", signal });
      if (!response.ok) throw unreachable;
      return readCapped(response);
    });
  } catch {
    throw unreachable;
  }
  if (body === null) throw unreachable;
  return body;
}

/** Fetch the enclave's bundle for a fresh challenge and the issuer's key set,
 *  then verify. Rejects with the refusal's message. */
export async function attestEnclave(deps: AttestationDeps): Promise<VerifiedEnclave> {
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const [bundle, keySet] = await Promise.allSettled([
    fetchBundle(deps, challenge),
    fetchKeySet(deps),
  ]);
  if (bundle.status === "rejected") throw bundle.reason as Error;
  if (keySet.status === "rejected") throw keySet.reason as Error;
  const enclave = await verifyAttestationBundle(bundle.value, challenge, keySet.value, deps.trust);
  if (isExpiring(enclave, deps)) {
    throw new Error("the enclave's attestation expires too soon; check this device's clock");
  }
  return enclave;
}

const isExpiring = (enclave: VerifiedEnclave, deps: AttestationDeps) =>
  deps.now() / 1000 >= enclave.expiresAt - CLOCK_SKEW_LEEWAY_SECS;

/** The verified enclave, attested again when it is within a minute of
 *  expiring. One attestation at a time; a result from before `invalidate()`
 *  or `clear()` is returned to its caller but never cached. */
export class EnclaveCache {
  private cached: VerifiedEnclave | null = null;
  private inFlight: Promise<VerifiedEnclave> | null = null;
  private generation = 0;

  constructor(private readonly deps: () => AttestationDeps | null) {}

  current(): Promise<VerifiedEnclave> {
    const deps = this.deps();
    if (!deps) {
      return Promise.reject(new Error("enclave verification is not configured in this build"));
    }
    if (this.cached && !isExpiring(this.cached, deps)) {
      return Promise.resolve(this.cached);
    }
    if (this.inFlight) return this.inFlight;
    const generation = this.generation;
    const attempt = attestEnclave(deps).then((enclave) => {
      if (generation === this.generation) this.cached = enclave;
      return enclave;
    });
    const settled = () => {
      if (this.inFlight === attempt) this.inFlight = null;
    };
    attempt.then(settled, settled);
    this.inFlight = attempt;
    return attempt;
  }

  /** Drop the cached enclave, e.g. after the server refused its key. */
  invalidate(): void {
    this.cached = null;
    this.inFlight = null;
    this.generation += 1;
  }

  /** Drop everything on a session change. */
  clear(): void {
    this.invalidate();
  }
}
