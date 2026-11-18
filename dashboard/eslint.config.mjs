// ESLint flat config: Next.js core web vitals and TypeScript rules (`npm run lint`).
import { defineConfig, globalIgnores } from "eslint/config";
import nextVitals from "eslint-config-next/core-web-vitals";
import nextTs from "eslint-config-next/typescript";

export default defineConfig([
  ...nextVitals,
  ...nextTs,
  {
    rules: {
      // Pages load data through useAsync (src/hooks/useAsync.ts), which sets state only when a
      // request settles. Setting state synchronously in an effect would cascade renders.
      "react-hooks/set-state-in-effect": "error",
    },
  },
  globalIgnores([".next/**", "out/**", "build/**", "next-env.d.ts"]),
]);
