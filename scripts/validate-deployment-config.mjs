import fs from "node:fs";

const required = ["k8s/resource-quota.yaml", "k8s/pod-disruption-budgets.yaml", "docker-compose.yml"];
for (const file of required) {
  if (!fs.existsSync(file)) throw new Error(`missing deployment file: ${file}`);
  const content = fs.readFileSync(file, "utf8");
  if (!content.trim()) throw new Error(`empty deployment file: ${file}`);
  console.log(`PASS ${file}`);
}
