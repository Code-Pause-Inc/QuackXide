// Enclave evidence verified in real browsers (vitest `browser` project): the
// wasm module loads by URL as in the app, tokens are minted with Web Crypto,
// and only `fetch` is stubbed. The node suite (attestation.test.ts) covers
// the refusals in depth; this checks the checks run in each engine.

import { describe, expect, it } from "vitest";
import fixture from "../../../../fixtures/attestation/bundles.json";
import type { AttestationTrust } from "../../config/attestation";
import { claimsFor, testIssuer } from "../../test/attestationTokens";
import { attestEnclave } from "./attestation";

const { bound } = fixture.bundles;
const API = "https://api.test";
const JWKS_URL = "https://issuer.test/jwks";

const trust = (imageDigests: string[]): AttestationTrust => ({
  issuer: "https://issuer.test",
  jwksUrl: JWKS_URL,
  imageDigests,
  release: true,
});

const fromB64url = (s: string) =>
  Uint8Array.from(atob(s.replaceAll("-", "+").replaceAll("_", "/")), (c) => c.charCodeAt(0));

/** Serves `bound`'s bundle with a token minted for the nonce it is asked about. */
async function stubFetch(): Promise<typeof fetch> {
  const issuer = await testIssuer();
  return (async (input: RequestInfo | URL) => {
    const url = String(input);
    if (url === JWKS_URL) return new Response(issuer.jwks);
    if (!url.startsWith(`${API}/api/v1/attestation?nonce=`)) return new Response("", { status: 404 });
    const challenge = fromB64url(new URL(url).searchParams.get("nonce")!);
    const claims = claimsFor(bound, challenge, Math.floor(Date.now() / 1000));
    return new Response(JSON.stringify({ ...bound.bundle, token: await issuer.mint(claims) }));
  }) as typeof fetch;
}

const deps = async (imageDigests: string[]) => ({
  apiBaseUrl: API,
  trust: trust(imageDigests),
  fetch: await stubFetch(),
  now: () => Date.now(),
});

describe("attestEnclave in a browser", () => {
  it("verifies a bound bundle", async () => {
    const enclave = await attestEnclave(await deps([fixture.simulator.image_digest]));
    expect(enclave.keyId).toBe(bound.bundle.key_id);
  });

  it("names the failed check", async () => {
    await expect(attestEnclave(await deps(["sha256:00"]))).rejects.toThrow("check 3");
  });
});
