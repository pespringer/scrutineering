import { execFileSync } from "node:child_process";

const commands = [
  ["npm", ["test"]],
  ["npm", ["run", "validate:policy-contract"]],
  ["npm", ["run", "validate:evidence-contract"]],
  ["npm", ["run", "drill:staging-rollback"]],
  ["npm", ["run", "validate:deployment"]],
  ["npm", ["run", "validate:docs"]],
  ["npm", ["run", "validate:frontend"]],
  ["uv", ["run", "--with-requirements", "requirements.txt", "--with", "pytest", "pytest", "tests/", "-q"]],
];

for (const [command, args] of commands) {
  console.log(`\n$ ${command} ${args.join(" ")}`);
  execFileSync(command, args, { stdio: "inherit", env: { ...process.env, PYTHONPATH: "." } });
}

console.log("\nLocal CI verification passed.");
