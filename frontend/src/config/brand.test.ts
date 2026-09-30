import { describe, expect, it } from "vitest";
import { resolveBrand } from "./brand";

describe("resolveBrand", () => {
  it("falls back to neutral defaults when env is empty", () => {
    const brand = resolveBrand({});
    expect(brand.publicName).toBe("Confidential Drive");
    expect(brand.domainName).toBe("localhost");
    expect(brand.apiBaseUrl).toBe("http://127.0.0.1:8080");
    expect(brand.features.zkEnabled).toBe(false);
  });

  it("uses configured brand values verbatim", () => {
    const brand = resolveBrand({
      VITE_APP_PUBLIC_NAME: "Acme Vault",
      VITE_APP_DOMAIN_NAME: "vault.example",
      VITE_APP_SUPPORT_EMAIL: "help@vault.example",
      VITE_API_BASE_URL: "https://api.vault.example",
    });
    expect(brand.publicName).toBe("Acme Vault");
    expect(brand.domainName).toBe("vault.example");
    expect(brand.supportEmail).toBe("help@vault.example");
    expect(brand.apiBaseUrl).toBe("https://api.vault.example");
  });

  it("treats whitespace-only overrides as unset", () => {
    const brand = resolveBrand({ VITE_APP_PUBLIC_NAME: "   " });
    expect(brand.publicName).toBe("Confidential Drive");
  });

  it("parses the ZK user toggle in common spellings", () => {
    expect(resolveBrand({ VITE_FEATURE_ZK_ENABLED: "true" }).features.zkEnabled).toBe(true);
    expect(resolveBrand({ VITE_FEATURE_ZK_ENABLED: "1" }).features.zkEnabled).toBe(true);
    expect(resolveBrand({ VITE_FEATURE_ZK_ENABLED: "on" }).features.zkEnabled).toBe(true);
    expect(resolveBrand({ VITE_FEATURE_ZK_ENABLED: "false" }).features.zkEnabled).toBe(false);
    expect(resolveBrand({ VITE_FEATURE_ZK_ENABLED: "garbage" }).features.zkEnabled).toBe(false);
  });
});
