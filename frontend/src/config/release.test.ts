import { describe, expect, it } from "vitest";

import { releaseEnvProblems, type ReleaseEnv } from "./release";

const DIGEST = `sha256:${"a".repeat(64)}`;
const VALID: ReleaseEnv = {
  VITE_VAULT_MODE: "http",
  VITE_ATTESTATION_ISSUER: "https://attest.example",
  VITE_ATTESTATION_JWKS_URL: "https://attest.example/jwks",
  VITE_ATTESTATION_IMAGE_DIGESTS: DIGEST,
};

describe("releaseEnvProblems", () => {
  it("accepts the http vault with no tokens", () => {
    expect(releaseEnvProblems(VALID)).toEqual([]);
    expect(releaseEnvProblems({ ...VALID, VITE_VAULT_MODE: " HTTP ", VITE_DEV_JWT: "  " })).toEqual([]);
  });

  it("refuses an unset, local or unknown vault mode", () => {
    for (const mode of [undefined, "", "local", "https"]) {
      const problems = releaseEnvProblems({ ...VALID, VITE_VAULT_MODE: mode });
      expect(problems).toHaveLength(1);
      expect(problems[0]).toContain("VITE_VAULT_MODE");
    }
  });

  it("refuses baked-in development tokens without echoing them", () => {
    const problems = releaseEnvProblems({
      ...VALID,
      VITE_DEV_JWT: "token-value",
      VITE_ADMIN_JWT: "admin-value",
    });
    expect(problems).toHaveLength(2);
    expect(problems.join(" ")).toContain("VITE_DEV_JWT");
    expect(problems.join(" ")).toContain("VITE_ADMIN_JWT");
    expect(problems.join(" ")).not.toContain("token-value");
  });

  it("refuses a cross-origin API base without echoing it", () => {
    const problems = releaseEnvProblems({
      ...VALID,
      VITE_API_BASE_URL: "https://api.example",
    });
    expect(problems).toHaveLength(1);
    expect(problems[0]).toContain("VITE_API_BASE_URL");
    expect(problems[0]).not.toContain("api.example");
  });

  it("accepts an empty or blank API base (same origin)", () => {
    for (const base of [undefined, "", "   "]) {
      expect(releaseEnvProblems({ ...VALID, VITE_API_BASE_URL: base })).toEqual([]);
    }
  });

  it("refuses each missing attestation variable", () => {
    for (const key of [
      "VITE_ATTESTATION_ISSUER",
      "VITE_ATTESTATION_JWKS_URL",
      "VITE_ATTESTATION_IMAGE_DIGESTS",
    ] as const) {
      const problems = releaseEnvProblems({ ...VALID, [key]: undefined });
      expect(problems.some((p) => p.includes(key))).toBe(true);
    }
  });

  it("refuses a key-set URL that is not https", () => {
    const problems = releaseEnvProblems({
      ...VALID,
      VITE_ATTESTATION_JWKS_URL: "http://attest.example/jwks",
    });
    expect(problems).toHaveLength(1);
    expect(problems[0]).toContain("VITE_ATTESTATION_JWKS_URL");
  });

  it("refuses an issuer that is not https, the simulator's included", () => {
    for (const issuer of ["http://sim-attestation:8070", "http://sim-attestation:8070/", "http://attest.example"]) {
      const problems = releaseEnvProblems({ ...VALID, VITE_ATTESTATION_ISSUER: issuer });
      expect(problems).toHaveLength(1);
      expect(problems[0]).toContain("VITE_ATTESTATION_ISSUER");
    }
  });

  it("refuses a malformed image digest", () => {
    for (const bad of ["sha256:abc", `sha256:${"A".repeat(64)}`, "a".repeat(64), `${DIGEST},sha256:zz`]) {
      const problems = releaseEnvProblems({ ...VALID, VITE_ATTESTATION_IMAGE_DIGESTS: bad });
      expect(problems).toHaveLength(1);
      expect(problems[0]).toContain("VITE_ATTESTATION_IMAGE_DIGESTS");
    }
  });
});
