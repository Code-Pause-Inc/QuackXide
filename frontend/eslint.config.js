// ESLint flat config: typescript-eslint and the React hooks rules.
// `npm run lint` runs it with zero warnings allowed (scripts/check.sh).
import js from "@eslint/js";
import { defineConfig } from "eslint/config";
import reactHooks from "eslint-plugin-react-hooks";
import globals from "globals";
import tseslint from "typescript-eslint";

export default defineConfig(
  { ignores: ["dist", "coverage", "src/lib/crypto/wasm"] },
  {
    files: ["**/*.{ts,tsx}"],
    extends: [
      js.configs.recommended,
      tseslint.configs.recommended,
      reactHooks.configs.flat.recommended,
    ],
    languageOptions: { globals: globals.browser },
  },
  {
    // The wasm envelope module runs only in the crypto worker, behind
    // envelope.ts; nothing else may load its glue. Tests of the crypto core
    // load the module inline, since Node cannot fetch it by URL.
    files: ["src/**/*.{ts,tsx}"],
    ignores: ["src/lib/crypto/envelope.ts", "src/lib/crypto/*.test.ts"],
    rules: {
      "no-restricted-imports": [
        "error",
        { patterns: [{ group: ["**/crypto/wasm/*", "./wasm/*"], message: "Use lib/crypto/envelope.ts." }] },
      ],
    },
  },
  {
    files: ["vite.config.ts", "eslint.config.js"],
    languageOptions: { globals: globals.node },
  },
);
