import { describe, expect, it } from "vitest";

import { releaseEnvProblems } from "./release";

describe("releaseEnvProblems", () => {
  it("accepts the http vault with no tokens", () => {
    expect(releaseEnvProblems({ VITE_VAULT_MODE: "http" })).toEqual([]);
    expect(releaseEnvProblems({ VITE_VAULT_MODE: " HTTP ", VITE_DEV_JWT: "  " })).toEqual([]);
  });

  it("refuses an unset, local or unknown vault mode", () => {
    for (const mode of [undefined, "", "local", "https"]) {
      const problems = releaseEnvProblems({ VITE_VAULT_MODE: mode });
      expect(problems).toHaveLength(1);
      expect(problems[0]).toContain("VITE_VAULT_MODE");
    }
  });

  it("refuses baked-in development tokens without echoing them", () => {
    const problems = releaseEnvProblems({
      VITE_VAULT_MODE: "http",
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
      VITE_VAULT_MODE: "http",
      VITE_API_BASE_URL: "https://api.example",
    });
    expect(problems).toHaveLength(1);
    expect(problems[0]).toContain("VITE_API_BASE_URL");
    expect(problems[0]).not.toContain("api.example");
  });

  it("accepts an empty or blank API base (same origin)", () => {
    for (const base of [undefined, "", "   "]) {
      expect(releaseEnvProblems({ VITE_VAULT_MODE: "http", VITE_API_BASE_URL: base })).toEqual([]);
    }
  });
});
