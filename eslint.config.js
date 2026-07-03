import js from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
  // Don't lint build output or dependencies.
  { ignores: ["dist/", "node_modules/"] },

  js.configs.recommended,
  ...tseslint.configs.recommended,

  // Allow underscore-prefixed identifiers as intentional throwaways.
  {
    rules: {
      "@typescript-eslint/no-unused-vars": [
        "error",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_", caughtErrors: "none" },
      ],
    },
  },

  // Source TypeScript: browser + extension globals.
  {
    files: ["popup/**/*.ts", "settings/**/*.ts", "scripts/**/*.ts"],
    languageOptions: {
      globals: {
        chrome: "readonly",
        document: "readonly",
        window: "readonly",
        crypto: "readonly",
        fetch: "readonly",
        TextEncoder: "readonly",
        URL: "readonly",
        console: "readonly",
      },
    },
  },

  // Node build/config scripts.
  {
    files: ["build.mjs", "eslint.config.js", "assets/**/*.mjs"],
    languageOptions: {
      globals: { process: "readonly", console: "readonly" },
    },
  },
);
