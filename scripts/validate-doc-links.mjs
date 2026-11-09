import fs from "node:fs";
import path from "node:path";

const readme = fs.readFileSync("README.md", "utf8");
const links = [...readme.matchAll(/\]\((docs\/[^)]+)\)/g)].map((match) => match[1]);
for (const link of links) {
  if (!fs.existsSync(path.resolve(link))) throw new Error(`missing documentation target: ${link}`);
  console.log(`PASS ${link}`);
}
