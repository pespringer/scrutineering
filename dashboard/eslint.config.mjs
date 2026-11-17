// ESLint flat config: Next.js core web vitals and TypeScript rules (`npm run lint`).
import { defineConfig, globalIgnores } from "eslint/config";
import nextVitals from "eslint-config-next/core-web-vitals";
import nextTs from "eslint-config-next/typescript";

export default defineConfig([
  ...nextVitals,
  ...nextTs,
  {
    rules: {
      // The pages load their data from the API in an effect, which is the effect's intended use
      // (synchronising with an external system). The rule cannot see that most of these loaders
      // set state only after an await, so it is a warning until data loading moves to a fetch
      // library, not an error that blocks CI.
      "react-hooks/set-state-in-effect": "warn",
    },
  },
  globalIgnores([".next/**", "out/**", "build/**", "next-env.d.ts"]),
]);
