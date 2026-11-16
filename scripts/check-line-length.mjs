#!/usr/bin/env node
// Fail on any line over 120 characters in the dashboard and repository scripts.
// Prettier wraps code at 120 but cannot split strings, so long class names and
// messages need this separate check (Python is covered by Ruff's E501).
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

const LIMIT = 120;
const roots = ["dashboard/src", "scripts"];
const extensions = /\.(ts|tsx|mjs|js|css)$/;
const failures = [];

function walk(dir) {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) {
      if (name !== "node_modules" && name !== ".next") walk(path);
    } else if (extensions.test(name)) {
      readFileSync(path, "utf8")
        .split("\n")
        .forEach((line, index) => {
          if (line.length > LIMIT)
            failures.push(`${path}:${index + 1}: ${line.length} > ${LIMIT}`);
        });
    }
  }
}

roots.forEach(walk);
if (failures.length) {
  console.error(failures.join("\n"));
  console.error(`\n${failures.length} line(s) over ${LIMIT} characters.`);
  process.exit(1);
}
console.log(`PASS line length (<= ${LIMIT}) in ${roots.join(", ")}`);
