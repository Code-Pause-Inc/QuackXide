// Release build gate (ADR 0009). `vite build --mode release` refuses a
// bundle that would ship development paths: the IndexedDB-only local vault,
// a baked-in development token, or an API base URL (the page calls its own
// origin only). Pure, so vite.config.ts and tests share it.

import { SIMULATOR_ISSUER } from "./attestation";

export interface ReleaseEnv {
  readonly VITE_VAULT_MODE?: string;
  readonly VITE_DEV_JWT?: string;
  readonly VITE_ADMIN_JWT?: string;
  readonly VITE_API_BASE_URL?: string;
  readonly VITE_ATTESTATION_ISSUER?: string;
  readonly VITE_ATTESTATION_JWKS_URL?: string;
  readonly VITE_ATTESTATION_IMAGE_DIGESTS?: string;
}

const IMAGE_DIGEST = /^sha256:[0-9a-f]{64}$/;

/** Every reason the release build must fail; empty means it may proceed.
 *  Reasons name variables only, never their values. */
export function releaseEnvProblems(env: ReleaseEnv): string[] {
  const problems: string[] = [];
  if (env.VITE_VAULT_MODE?.trim().toLowerCase() !== "http") {
    problems.push('VITE_VAULT_MODE must be explicitly "http" (the local vault is development-only)');
  }
  for (const key of ["VITE_DEV_JWT", "VITE_ADMIN_JWT"] as const) {
    if (env[key]?.trim()) {
      problems.push(`${key} must be empty (development tokens never ship)`);
    }
  }
  if (env.VITE_API_BASE_URL?.trim()) {
    problems.push("VITE_API_BASE_URL must be empty (the page calls its own origin, ADR 0005)");
  }
  const issuer = env.VITE_ATTESTATION_ISSUER?.trim();
  const jwksUrl = env.VITE_ATTESTATION_JWKS_URL?.trim();
  const digests = env.VITE_ATTESTATION_IMAGE_DIGESTS?.trim();
  if (!issuer) {
    problems.push("VITE_ATTESTATION_ISSUER must be set (the enclave attestation issuer to trust)");
  } else if (issuer === SIMULATOR_ISSUER) {
    problems.push("VITE_ATTESTATION_ISSUER must not be the simulator's issuer");
  }
  if (!jwksUrl) {
    problems.push("VITE_ATTESTATION_JWKS_URL must be set (the issuer's key set)");
  } else if (!jwksUrl.startsWith("https://")) {
    problems.push("VITE_ATTESTATION_JWKS_URL must be an https:// URL");
  }
  if (!digests) {
    problems.push("VITE_ATTESTATION_IMAGE_DIGESTS must be set (comma-separated enclave image digests)");
  } else if (!digests.split(",").every((digest) => IMAGE_DIGEST.test(digest.trim()))) {
    problems.push("VITE_ATTESTATION_IMAGE_DIGESTS must each be sha256: plus 64 lowercase hex characters");
  }
  return problems;
}
