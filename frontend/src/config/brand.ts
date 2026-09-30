// Customer-visible names, domains, and endpoints resolve from env at build
// time; none are hardcoded (scripts/check.sh enforces this on the bundle).

export interface BrandConfig {
  publicName: string;
  domainName: string;
  supportEmail: string;
  apiBaseUrl: string;
  features: {
    /** Default visibility of zero-knowledge features in the UI. */
    zkEnabled: boolean;
  };
}

/** The subset of env read here; `import.meta.env` satisfies it. */
export interface BrandEnv {
  readonly VITE_APP_PUBLIC_NAME?: string;
  readonly VITE_APP_DOMAIN_NAME?: string;
  readonly VITE_APP_SUPPORT_EMAIL?: string;
  readonly VITE_API_BASE_URL?: string;
  readonly VITE_FEATURE_ZK_ENABLED?: string;
}

function parseBool(raw: string | undefined, fallback: boolean): boolean {
  if (raw === undefined || raw.trim() === "") return fallback;
  return ["1", "true", "on", "yes"].includes(raw.trim().toLowerCase());
}

function nonEmpty(raw: string | undefined, fallback: string): string {
  const trimmed = raw?.trim();
  return trimmed ? trimmed : fallback;
}

export function resolveBrand(env: BrandEnv): BrandConfig {
  return {
    publicName: nonEmpty(env.VITE_APP_PUBLIC_NAME, "Confidential Drive"),
    domainName: nonEmpty(env.VITE_APP_DOMAIN_NAME, "localhost"),
    supportEmail: nonEmpty(env.VITE_APP_SUPPORT_EMAIL, "support@localhost"),
    apiBaseUrl: nonEmpty(env.VITE_API_BASE_URL, "http://127.0.0.1:8080"),
    features: {
      zkEnabled: parseBool(env.VITE_FEATURE_ZK_ENABLED, false),
    },
  };
}

export const brand: BrandConfig = resolveBrand(import.meta.env);
