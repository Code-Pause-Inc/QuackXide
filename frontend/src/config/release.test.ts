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
});
