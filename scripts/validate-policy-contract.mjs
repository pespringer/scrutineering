import fs from "node:fs";
import path from "node:path";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

const schemaPath = path.resolve("schemas/policy-contract/v1.schema.json");
const examplesDir = path.resolve("schemas/policy-contract/examples");

const schema = JSON.parse(fs.readFileSync(schemaPath, "utf8"));
const ajv = new Ajv2020({ allErrors: true, strict: false });
addFormats(ajv);
const validate = ajv.compile(schema);

const files = fs
  .readdirSync(examplesDir)
  .filter((name) => name.endsWith(".json"))
  .sort();

let failures = 0;
for (const file of files) {
  const payload = JSON.parse(
    fs.readFileSync(path.join(examplesDir, file), "utf8"),
  );
  const isValid = validate(payload);
  const expectsValid = file.startsWith("valid-");

  if (expectsValid && !isValid) {
    failures += 1;
    console.error(`FAIL ${file} expected valid, got invalid`);
    console.error(validate.errors);
    continue;
  }

  if (!expectsValid && isValid) {
    failures += 1;
    console.error(`FAIL ${file} expected invalid, got valid`);
    continue;
  }

  console.log(`PASS ${file}`);
}

if (failures > 0) {
  console.error(`Validation failed with ${failures} error(s).`);
  process.exit(1);
}

console.log("All policy contract example checks passed.");
