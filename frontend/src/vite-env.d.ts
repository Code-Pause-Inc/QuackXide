/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_APP_PUBLIC_NAME?: string;
  readonly VITE_APP_DOMAIN_NAME?: string;
  readonly VITE_APP_SUPPORT_EMAIL?: string;
  readonly VITE_API_BASE_URL?: string;
  readonly VITE_FEATURE_ZK_ENABLED?: string;
  readonly VITE_VAULT_MODE?: string;
  readonly VITE_DEV_JWT?: string;
  readonly VITE_ADMIN_JWT?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
