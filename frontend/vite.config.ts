/// <reference types="vitest/config" />
import tailwindcss from "@tailwindcss/vite";
import { playwright } from "@vitest/browser-playwright";
import react from "@vitejs/plugin-react";
import { defineConfig, loadEnv } from "vite";

import { releaseEnvProblems } from "./src/config/release";

// Browsers for the `browser` test project: a comma list in BROWSERS
// (chromium, firefox, webkit), Chromium when unset.
const BROWSERS = ["chromium", "firefox", "webkit"] as const;
type Browser = (typeof BROWSERS)[number];

function browserInstances(list: string | undefined): { browser: Browser }[] {
  return (list?.trim() || "chromium")
    .split(",")
    .map((name) => name.trim())
    .filter((name) => name.length > 0)
    .map((name) => {
      const browser = BROWSERS.find((known) => known === name);
      if (!browser) throw new Error(`BROWSERS: unknown browser "${name}" (use ${BROWSERS.join(", ")})`);
      return { browser };
    });
}

// Branding and endpoints come from VITE_* env vars (see .env.example).
export default defineConfig(({ mode }) => {
  // Dev server only: API_PROXY_TARGET has no VITE_ prefix, so it never
  // reaches the bundle. The browser calls the dev server's own origin and
  // the proxy forwards, so no CORS preflight crosses origins.
  const env = loadEnv(mode, ".", "");
  const target = env.API_PROXY_TARGET?.trim() || "http://127.0.0.1:8080";
  const browsers = browserInstances(env.BROWSERS);
  // Release builds (`npm run build:release`, release.yml) refuse
  // development paths (ADR 0009).
  if (mode === "release") {
    const problems = releaseEnvProblems(loadEnv(mode, ".", "VITE_"));
    if (problems.length > 0) {
      throw new Error(`release build refused:\n- ${problems.join("\n- ")}`);
    }
  }
  const proxy = Object.fromEntries(
    ["/api", "/admin", "/healthz"].map((prefix) => [prefix, { target, changeOrigin: true }]),
  );

  return {
    plugins: [react(), tailwindcss()],
    // Tests ignore .env files so local tokens and branding cannot change results.
    envDir: mode === "test" ? false : undefined,
    server: {
      port: 5173,
      proxy,
    },
    test: {
      projects: [
        {
          extends: true,
          test: {
            name: "node",
            environment: "node",
            include: ["src/**/*.test.ts"],
            exclude: ["src/**/*.browser.test.ts"],
          },
        },
        {
          extends: true,
          test: {
            name: "dom",
            environment: "jsdom",
            include: ["src/**/*.test.tsx"],
            setupFiles: ["src/test/setup.ts"],
          },
        },
        {
          // Real browsers (Playwright): the crypto worker, Web Crypto and
          // IndexedDB. Run with `npm run test:browser`, not `npm test`.
          extends: true,
          test: {
            name: "browser",
            // Timings run only on request (`npm run bench:browser`).
            include: [
              "src/**/*.browser.test.ts",
              ...(env.TIMINGS === "1" ? ["src/**/*.browser.timing.ts"] : []),
            ],
            browser: {
              enabled: true,
              provider: playwright(),
              headless: true,
              instances: browsers,
              // Failure screenshots and traces land in .vitest/ (CI keeps them).
              trace: { mode: "retain-on-failure", tracesDir: ".vitest/traces" },
            },
          },
        },
      ],
    },
  };
});