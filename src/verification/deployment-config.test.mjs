import test from "node:test";
import { execFileSync } from "node:child_process";

test("deployment configuration validator passes checked-in manifests", () => {
  execFileSync("node", ["scripts/validate-deployment-config.mjs"], { stdio: "pipe" });
});
