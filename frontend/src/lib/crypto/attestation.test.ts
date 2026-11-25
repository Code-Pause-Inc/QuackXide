// The enclave cache against the shared attestation vectors
// (fixtures/attestation/bundles.json). A stub fetch serves the bundle and the
// key set and mints the token for the nonce it is asked about; the checks
// themselves run in the wasm module.

import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import fixture from "../../../../fixtures/attestation/bundles.json";
import type { AttestationTrust } from "../../config/attestation";
import { claimsFor, testIssuer } from "../../test/attestationTokens";
import { attestEnclave, type AttestationDeps, EnclaveCache } from "./attestation";
import { loadEnvelopeModule } from "./envelope";
import envelopeWasmInline from "./wasm/envelope_bg.wasm?url&inline";

type Vector = (typeof fixture.bundles)["bound"];
const { bound, other, loosened } = fixture.bundles;

const API = "https://api.test";
const JWKS_URL = "https://issuer.test/jwks";
const DIGEST = fixture.simulator.image_digest;
const trust: AttestationTrust = {
  issuer: "https://issuer.test",
  jwksUrl: JWKS_URL,
  imageDigests: [DIGEST],
  release: true,
};

const fromB64url = (s: string) =>
  Uint8Array.from(atob(s.replaceAll("-", "+").replaceAll("_", "/")), (c) => c.charCodeAt(0));
const nowSecs = () => Math.floor(Date.now() / 1000);

interface StubOptions {
  /** Vector whose bundle is served (default bound). */
  bundle?: Vector;
  /** Vector the token's claims are built from (default: the bundle's). */
  claims?: Vector;
  claimOverrides?: Record<string, unknown>;
  /** Replaces the challenge the token carries. */
  tokenChallenge?: Uint8Array;
  /** The token's signer; the served key set is `served`'s (default: same). */
  signer?: Awaited<ReturnType<typeof testIssuer>>;
  served?: Awaited<ReturnType<typeof testIssuer>>;
  bundleResponse?: () => Response | Promise<Response>;
  /** Holds the first bundle request until this resolves. */
  holdFirst?: Promise<void>;
  jwksResponse?: () => Response;
}

interface Call {
  url: string;
  init: RequestInit | undefined;
}

async function stub(options: StubOptions = {}) {
  const issuer = await testIssuer();
  const signer = options.signer ?? issuer;
  const served = options.served ?? issuer;
  const calls: Call[] = [];
  const mintedExp: number[] = [];
  let bundleRequests = 0;
  const fetchStub = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    calls.push({ url, init });
    if (url === JWKS_URL) return options.jwksResponse?.() ?? new Response(served.jwks);
    if (!url.startsWith(`${API}/api/v1/attestation?nonce=`)) return new Response("", { status: 404 });
    if (options.bundleResponse) return options.bundleResponse();
    bundleRequests += 1;
    if (bundleRequests === 1) await options.holdFirst;
    const challenge = fromB64url(new URL(url).searchParams.get("nonce")!);
    const vector = options.bundle ?? bound;
    const claims = claimsFor(
      options.claims ?? vector,
      options.tokenChallenge ?? challenge,
      nowSecs(),
      options.claimOverrides,
    );
    mintedExp.push(claims.exp as number);
    const token = await signer.mint(claims);
    return new Response(JSON.stringify({ ...vector.bundle, token }));
  }) as typeof fetch;
  return { calls, mintedExp, fetch: fetchStub };
}

let clock = Date.now();
const deps = (fetchStub: typeof fetch, overrides: Partial<AttestationDeps> = {}): AttestationDeps => ({
  apiBaseUrl: API,
  trust,
  fetch: fetchStub,
  now: () => clock,
  ...overrides,
});

afterEach(() => {
  clock = Date.now();
});

beforeAll(async () => {
  await loadEnvelopeModule(envelopeWasmInline);
});

describe("attestEnclave", () => {
  it("a_bound_bundle_verifies", async () => {
    const s = await stub();
    const enclave = await attestEnclave(deps(s.fetch));
    expect(enclave.keyId).toBe(bound.bundle.key_id);
    expect(enclave.requestKey).toEqual({
      suite: bound.bundle.request_key.suite,
      publicKey: bound.bundle.request_key.public_key,
    });
    expect(enclave.signingKeys).toEqual({
      ed25519: bound.bundle.signing_keys.ed25519,
      mlDsa65: bound.bundle.signing_keys.ml_dsa_65,
    });
    expect(enclave.expiresAt).toBe(s.mintedExp[0]);
    expect(s.calls).toHaveLength(2);
    for (const { init } of s.calls) {
      expect(new Headers(init?.headers).has("Authorization")).toBe(false);
      expect(init?.signal).toBeDefined();
    }
    expect(s.calls[1]!.init?.credentials).toBe("omit");
    expect(new URL(s.calls[0]!.url).searchParams.get("nonce")).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  const refusals: [string, StubOptions | (() => Promise<StubOptions>), string][] = [
    ["image digest not allowed", {}, "check 3"],
    ["debug image", { claimOverrides: { dbgstat: "enabled" } }, "check 2"],
    ["wrong hardware", { claimOverrides: { hwmodel: "GCP_AMD_SEV" } }, "check 2"],
    [
      "signature by another key, same kid",
      async () => ({ signer: await testIssuer() }),
      "check 1",
    ],
    [
      "two hours old",
      { claimOverrides: { iat: nowSecs() - 7200, nbf: nowSecs() - 7200, exp: nowSecs() - 6600 } },
      "check 1",
    ],
    ["another challenge", { tokenChallenge: new Uint8Array(32) }, "check 4"],
    ["other's binding nonce with bound's keys", { claims: other }, "check 5 (binding)"],
    ["loosened", { bundle: loosened }, "check 5 (configuration)"],
  ];

  it.each(refusals)("refuses %s", async (name, options, prefix) => {
    const resolved = typeof options === "function" ? await options() : options;
    const s = await stub(resolved);
    const refused = name === "image digest not allowed" ? { ...trust, imageDigests: ["sha256:00"] } : trust;
    const cache = new EnclaveCache(() => deps(s.fetch, { trust: refused }));
    const err = await cache.current().then(
      () => null,
      (e: unknown) => e,
    );
    const message = String(err instanceof Error ? err.message : err);
    expect(message.startsWith(prefix), message).toBe(true);
    expect(s.calls.at(-1)!.url).toBe(JWKS_URL);
    expect(s.calls).toHaveLength(2);
    // The cache stayed empty: the next call attests again.
    await cache.current().catch(() => undefined);
    expect(s.calls).toHaveLength(4);
  });

  it("refuses an unknown kid after fetching the key set once more, past the cache", async () => {
    const s = await stub({ signer: await testIssuer("other-kid") });
    await expect(attestEnclave(deps(s.fetch))).rejects.toThrow(/^check 1/);
    expect(s.calls.map((c) => c.url)).toEqual([expect.stringContaining(API), JWKS_URL, JWKS_URL]);
    expect(s.calls[1]!.init?.cache).toBeUndefined();
    expect(s.calls[2]!.init?.cache).toBe("reload");
    expect(s.calls[2]!.init?.credentials).toBe("omit");
  });

  it("verifies against a key set rotated since it was cached", async () => {
    const cached = await testIssuer();
    const rotated = await testIssuer("other-kid");
    let keySetFetches = 0;
    const s = await stub({
      signer: rotated,
      jwksResponse: () => new Response(keySetFetches++ === 0 ? cached.jwks : rotated.jwks),
    });
    const enclave = await attestEnclave(deps(s.fetch));
    expect(enclave.keyId).toBe(bound.bundle.key_id);
    expect(keySetFetches).toBe(2);
  });

  it("bundle_unavailable", async () => {
    const s = await stub({ bundleResponse: () => new Response("", { status: 503 }) });
    await expect(attestEnclave(deps(s.fetch))).rejects.toThrow(
      "enclave attestation unavailable (503)",
    );
  });

  it("oversized_bundle", async () => {
    const s = await stub({ bundleResponse: () => new Response("x".repeat(300 * 1024)) });
    await expect(attestEnclave(deps(s.fetch))).rejects.toThrow(
      "enclave attestation response too large",
    );
  });

  it("oversized_key_set", async () => {
    const s = await stub({ jwksResponse: () => new Response("x".repeat(300 * 1024)) });
    await expect(attestEnclave(deps(s.fetch))).rejects.toThrow("attestation key set unreachable");
  });

  it("key_set_fetch_failure", async () => {
    const s = await stub({ jwksResponse: () => new Response("", { status: 500 }) });
    await expect(attestEnclave(deps(s.fetch))).rejects.toThrow("attestation key set unreachable");
  });

  describe("timeouts", () => {
    afterEach(() => vi.useRealTimers());

    const never = () => new ReadableStream<Uint8Array>({ start: () => undefined });
    it.each([
      ["a bundle fetch that never resolves", () => new Promise<Response>(() => undefined)],
      ["a bundle body that never ends", () => new Response(never())],
    ])("%s is refused after 10 s", async (_name, bundleResponse) => {
      vi.useFakeTimers();
      const s = await stub({ bundleResponse });
      const cache = new EnclaveCache(() => deps(s.fetch));
      const outcome = cache.current().then(
        () => "resolved",
        (e: unknown) => (e as Error).message,
      );
      await vi.advanceTimersByTimeAsync(10_000);
      expect(await outcome).toBe("enclave attestation unavailable (timeout)");
      void cache.current().catch(() => undefined);
      expect(s.calls).toHaveLength(4);
    });
  });

  it("a network failure on the bundle is unreachable", async () => {
    const s = await stub({ bundleResponse: () => Promise.reject(new TypeError("offline")) });
    await expect(attestEnclave(deps(s.fetch))).rejects.toThrow(
      "enclave attestation unavailable (unreachable)",
    );
  });

  it("an enclave expiring within a minute by the device clock is refused", async () => {
    const s = await stub();
    const cache = new EnclaveCache(() => deps(s.fetch, { now: () => Date.now() + 3600_000 }));
    await expect(cache.current()).rejects.toThrow(
      "the enclave's attestation expires too soon; check this device's clock",
    );
    await cache.current().catch(() => undefined);
    expect(s.calls).toHaveLength(4);
  });

  it("html_key_set", async () => {
    const s = await stub({ jwksResponse: () => new Response("<html>502 Bad Gateway</html>") });
    await expect(attestEnclave(deps(s.fetch))).rejects.toThrow("attestation key set");
  });
});

describe("EnclaveCache", () => {
  it("two current() calls inside the lifetime attest once", async () => {
    const s = await stub();
    const cache = new EnclaveCache(() => deps(s.fetch));
    const first = await cache.current();
    expect(await cache.current()).toBe(first);
    expect(s.calls).toHaveLength(2);
  });

  it("attests again one minute before exp", async () => {
    const s = await stub();
    const cache = new EnclaveCache(() => deps(s.fetch));
    const first = await cache.current();
    clock = (first.expiresAt - 61) * 1000;
    await cache.current();
    expect(s.calls).toHaveLength(2);
    // The fresh token expires as soon as the first, so it is refused too;
    // the point is that the cache did not hand back the old one.
    clock = (first.expiresAt - 60) * 1000;
    await cache.current().catch(() => undefined);
    expect(s.calls).toHaveLength(4);
  });

  it("invalidate() makes the next call attest again", async () => {
    const s = await stub();
    const cache = new EnclaveCache(() => deps(s.fetch));
    await cache.current();
    cache.invalidate();
    await cache.current();
    expect(s.calls).toHaveLength(4);
  });

  it("two concurrent current() calls attest once", async () => {
    const s = await stub();
    const cache = new EnclaveCache(() => deps(s.fetch));
    const [a, b] = await Promise.all([cache.current(), cache.current()]);
    expect(a).toBe(b);
    expect(s.calls).toHaveLength(2);
  });

  it.each(["clear", "invalidate"] as const)(
    "%s() during an attestation: the next current() attests anew",
    async (drop) => {
      let release!: () => void;
      const s = await stub({ holdFirst: new Promise<void>((r) => (release = r)) });
      const cache = new EnclaveCache(() => deps(s.fetch));
      const old = cache.current();
      cache[drop]();
      const fresh = cache.current();
      expect(s.calls).toHaveLength(4);
      release();
      const [oldEnclave, freshEnclave] = await Promise.all([old, fresh]);
      expect(freshEnclave).not.toBe(oldEnclave);
      // Only the new attestation was cached.
      expect(await cache.current()).toBe(freshEnclave);
      expect(s.calls).toHaveLength(4);
    },
  );

  it("a failed attestation is not remembered", async () => {
    const s = await stub({ bundleResponse: () => new Response("", { status: 503 }) });
    const cache = new EnclaveCache(() => deps(s.fetch));
    await expect(cache.current()).rejects.toThrow("(503)");
    await expect(cache.current()).rejects.toThrow("(503)");
    expect(s.calls).toHaveLength(4);
  });

  it("deps() returning null is refused", async () => {
    const cache = new EnclaveCache(() => null);
    await expect(cache.current()).rejects.toThrow(
      "enclave verification is not configured in this build",
    );
  });
});
