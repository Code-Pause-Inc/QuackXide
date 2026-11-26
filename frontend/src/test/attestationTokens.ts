// Test-only: mints RS256 attestation tokens the way the backend's
// TokenSigner::sign_at does (platform-enclave/src/simulated_token.rs). It
// never verifies one; every check runs in the wasm module under test.

import fixture from "../../../fixtures/attestation/bundles.json";

const AUDIENCE = "urn:platform:browser-attestation";
const LIFETIME_SECS = 600;

const encoder = new TextEncoder();

function b64url(bytes: Uint8Array): string {
  let bin = "";
  for (const byte of bytes) bin += String.fromCharCode(byte);
  return btoa(bin).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

const jsonB64url = (value: unknown) => b64url(encoder.encode(JSON.stringify(value)));

export async function testIssuer(
  kid = "test-kid",
): Promise<{ jwks: string; mint(claims: Record<string, unknown>): Promise<string> }> {
  const pair = await crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"],
  );
  const { n, e } = await crypto.subtle.exportKey("jwk", pair.publicKey);
  const jwks = JSON.stringify({ keys: [{ kty: "RSA", use: "sig", alg: "RS256", kid, n, e }] });
  return {
    jwks,
    async mint(claims) {
      const signingInput = `${jsonB64url({ alg: "RS256", typ: "JWT", kid })}.${jsonB64url(claims)}`;
      const signature = await crypto.subtle.sign(
        "RSASSA-PKCS1-v1_5",
        pair.privateKey,
        encoder.encode(signingInput),
      );
      return `${signingInput}.${b64url(new Uint8Array(signature))}`;
    },
  };
}

/** The claims `sign_at` signs for a bundle vector: two nonces (the challenge,
 *  then the vector's binding nonce), the container's environment and the
 *  simulator's image digest. `overrides` replace top-level claims. */
export function claimsFor(
  vector: { env: Record<string, string>; binding_nonce: string },
  challenge: Uint8Array,
  nowSecs: number,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    iss: "https://issuer.test",
    aud: AUDIENCE,
    iat: nowSecs,
    nbf: nowSecs,
    exp: nowSecs + LIFETIME_SECS,
    eat_nonce: [b64url(challenge), vector.binding_nonce],
    hwmodel: "GCP_INTEL_TDX",
    swname: "CONFIDENTIAL_SPACE",
    dbgstat: "disabled-since-boot",
    submods: {
      confidential_space: { support_attributes: ["STABLE"] },
      container: { image_digest: fixture.simulator.image_digest, env: vector.env },
    },
    ...overrides,
  };
}
