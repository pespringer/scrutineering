import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

const root = process.cwd();
const dashboard = join(root, "dashboard");
const packagePath = join(dashboard, "package.json");

if (!existsSync(packagePath)) throw new Error("dashboard/package.json is required");
if (existsSync(join(root, "web"))) throw new Error("legacy web frontend must not be restored");

const pkg = JSON.parse(readFileSync(packagePath, "utf8"));
for (const script of ["dev", "build", "start"]) {
  if (typeof pkg.scripts?.[script] !== "string") throw new Error(`dashboard package is missing ${script} script`);
}
if (!existsSync(join(dashboard, "package-lock.json"))) throw new Error("dashboard/package-lock.json is required");
console.log("PASS dashboard frontend configuration");
