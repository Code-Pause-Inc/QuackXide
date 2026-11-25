// What the browser trusts about the enclave's attestation, compiled in at
// build time (never fetched from the API). Release builds must set all three
// values (releaseEnvProblems enforces it). Only development and test fall back
// to the simulator's, which the Rust side pins in
// fixtures/attestation/bundles.json; any other build without them verifies
// nothing.

/** Google Confidential Space's attestation signing key set (the page CSP allows only this exact URL beyond `'self'`). */
export const GOOGLE_CS_JWKS_URL =
  "https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com";

export interface AttestationTrust {
  issuer: string;
  jwksUrl: string;
  imageDigests: string[];
  /** False only in development and test: the simulator's policy applies. */
  release: boolean;
}

/** The simulator's issuer, the development default. */
const SIMULATOR_ISSUER = "http://sim-attestation:8070";
const DEV_JWKS_URL = "/sim-attestation/jwks";
const DEV_IMAGE_DIGEST = "sha256:5155a7ab1d7e4c94d5bb3e1c6f0a3a4d6c7b8e9f00112233445566778899aabb";

/** The trust values for this build, or null when a build other than
 *  development or test lacks one (the caller must then refuse to verify). */
export function resolveAttestationTrust(
  env: Record<string, string | undefined>,
  mode: string,
): AttestationTrust | null {
  const release = mode !== "development" && mode !== "test";
  const issuer = env.VITE_ATTESTATION_ISSUER?.trim() || (release ? "" : SIMULATOR_ISSUER);
  const jwksUrl = env.VITE_ATTESTATION_JWKS_URL?.trim() || (release ? "" : DEV_JWKS_URL);
  const listed = (env.VITE_ATTESTATION_IMAGE_DIGESTS ?? "")
    .split(",")
    .map((digest) => digest.trim())
    .filter((digest) => digest !== "");
  const digests = listed.length > 0 ? listed : release ? [] : [DEV_IMAGE_DIGEST];
  if (!issuer || !jwksUrl || digests.length === 0) return null;
  return { issuer, jwksUrl, imageDigests: digests, release };
}
