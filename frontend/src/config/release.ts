// Release build gate (ADR 0009). `vite build --mode release` refuses a
// bundle that would ship development paths: the IndexedDB-only local vault,
// a baked-in development token, or an API base URL (the page calls its own
// origin only). Pure, so vite.config.ts and tests share it.

export interface ReleaseEnv {
  readonly VITE_VAULT_MODE?: string;
  readonly VITE_DEV_JWT?: string;
  readonly VITE_ADMIN_JWT?: string;
  readonly VITE_API_BASE_URL?: string;
}

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
  return problems;
}
