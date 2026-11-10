import fs from "node:fs";
import path from "node:path";

const staticDir = path.resolve(process.cwd(), ".next", "static");
const requiredUtilities = [".text-3xl", ".rounded-3xl", ".p-6", ".text-white", ".font-semibold", ".lg\\:grid-cols-6"];

function cssFiles(directory) {
  if (!fs.existsSync(directory)) return [];
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const target = path.join(directory, entry.name);
    return entry.isDirectory() ? cssFiles(target) : target.endsWith(".css") ? [target] : [];
  });
}

const css = cssFiles(staticDir).map((file) => fs.readFileSync(file, "utf8")).join("\n");
if (!css) throw new Error("dashboard CSS bundle was not generated; run npm run build first");
const missing = requiredUtilities.filter((utility) => !css.includes(utility));
if (missing.length) throw new Error(`dashboard CSS bundle is missing utilities: ${missing.join(", ")}`);
console.log(`PASS dashboard CSS utility bundle (${requiredUtilities.length} required utilities)`);
