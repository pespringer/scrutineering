import fs from "node:fs";

const required = ["k8s/resource-quota.yaml", "k8s/pod-disruption-budgets.yaml", "k8s/infrastructure.yaml", "k8s/planner-deployment.yaml", "k8s/worker-deployment.yaml", "docker-compose.yml", "Dockerfile", "Dockerfile.api", "Dockerfile.worker", "Dockerfile.dashboard", ".dockerignore"];
for (const file of required) {
  if (!fs.existsSync(file)) throw new Error(`missing deployment file: ${file}`);
  const content = fs.readFileSync(file, "utf8");
  if (!content.trim()) throw new Error(`empty deployment file: ${file}`);
  if (file === "Dockerfile.worker" && !content.includes("HEALTHCHECK")) throw new Error("worker image health check is required");
  if (file === "k8s/resource-quota.yaml" && !content.includes("limits.memory")) throw new Error("resource quota memory limit is required");
  if (file === "k8s/pod-disruption-budgets.yaml" && !content.includes("minAvailable")) throw new Error("pod disruption budgets must define availability");
  console.log(`PASS ${file}`);
}
