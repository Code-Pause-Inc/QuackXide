// Vault backend selection: "local" keeps ciphertext in IndexedDB (offline
// demo), "http" uses the drive API. Only where ciphertext is stored changes,
// never what leaves the crypto worker.

export type VaultMode = "local" | "http";

export interface VaultRuntimeConfig {
  mode: VaultMode;
  /** DEV ONLY: bearer token from the backend `devtoken` binary. Never put
   *  production credentials in env files. */
  devJwt: string | null;
}

export interface VaultEnv {
  readonly VITE_VAULT_MODE?: string;
  readonly VITE_DEV_JWT?: string;
}

export function resolveVaultConfig(env: VaultEnv): VaultRuntimeConfig {
  const mode: VaultMode = env.VITE_VAULT_MODE?.trim().toLowerCase() === "http" ? "http" : "local";
  const devJwt = env.VITE_DEV_JWT?.trim() || null;
  return { mode, devJwt };
}
