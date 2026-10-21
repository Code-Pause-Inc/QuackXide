/// <reference types="vitest/config" />
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig, loadEnv } from "vite";

// Branding and endpoints come from VITE_* env vars (see .env.example).
export default defineConfig(({ mode }) => {
  // Dev server only: API_PROXY_TARGET has no VITE_ prefix, so it never
  // reaches the bundle. The browser calls the dev server's own origin and
  // the proxy forwards, so no CORS preflight crosses origins.
  const env = loadEnv(mode, ".", "");
  const target = env.API_PROXY_TARGET?.trim() || "http://127.0.0.1:8080";
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
          test: { name: "node", environment: "node", include: ["src/**/*.test.ts"] },
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
      ],
    },
  };
});