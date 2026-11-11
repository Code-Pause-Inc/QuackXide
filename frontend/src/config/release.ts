// Release build gate (ADR 0009). `vite build --mode release` refuses a
// bundle that would ship development paths: the IndexedDB-only local vault
// or a baked-in development token. Pure, so vite.config.ts and tests share it.

export interface ReleaseEnv {
  readonly VITE_VAULT_MODE?: string;
  readonly VITE_DEV_JWT?: string;
  readonly VITE_ADMIN_JWT?: string;
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
  return problems;
}
