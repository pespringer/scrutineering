import test from "node:test";
import { execFileSync } from "node:child_process";

test("README documentation links resolve", () => {
  execFileSync("node", ["scripts/validate-doc-links.mjs"], { stdio: "pipe" });
});
