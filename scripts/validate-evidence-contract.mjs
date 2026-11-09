import fs from "node:fs";
import path from "node:path";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

const schemaPath = path.resolve("schemas/evidence/v1.schema.json");
const examplesDir = path.resolve("schemas/evidence/examples");
const schema = JSON.parse(fs.readFileSync(schemaPath, "utf8"));
const ajv = new Ajv2020({ allErrors: true, strict: false });
addFormats(ajv);
const validate = ajv.compile(schema);

let failures = 0;
for (const file of fs.readdirSync(examplesDir).filter((name) => name.endsWith(".json")).sort()) {
  const payload = JSON.parse(fs.readFileSync(path.join(examplesDir, file), "utf8"));
  const valid = validate(payload);
  const expected = file.startsWith("valid-");

  if (valid !== expected) {
    failures += 1;
    console.error(`FAIL ${file}: expected ${expected ? "valid" : "invalid"}`);
    if (!valid) console.error(validate.errors);
  } else {
    console.log(`PASS ${file}`);
  }
}

if (failures) {
  console.error(`Evidence contract validation failed with ${failures} error(s).`);
  process.exit(1);
}

console.log("All evidence contract example checks passed.");
