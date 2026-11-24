import fs from "node:fs";

const required = [
  "k8s/resource-quota.yaml",
  "k8s/pod-disruption-budgets.yaml",
  "k8s/network-policies.yaml",
  "k8s/pod-security.yaml",
  "k8s/infrastructure.yaml",
  "k8s/api-deployment.yaml",
  "k8s/dashboard-deployment.yaml",
  "k8s/worker-deployment.yaml",
  "k8s/worker-service-account.yaml",
  "k8s/services.yaml",
  "k8s/registry.yaml",
  "k8s/buildkit/buildkit.yaml",
  "docker-compose.yml",
  "Dockerfile.api",
  "Dockerfile.worker",
  "Dockerfile.dashboard",
  ".dockerignore",
];
for (const file of required) {
  if (!fs.existsSync(file)) throw new Error(`missing deployment file: ${file}`);
  const content = fs.readFileSync(file, "utf8");
  if (!content.trim()) throw new Error(`empty deployment file: ${file}`);
  if (file === "Dockerfile.worker" && !content.includes("HEALTHCHECK"))
    throw new Error("worker image health check is required");
  if (file === "k8s/resource-quota.yaml" && !content.includes("limits.memory"))
    throw new Error("resource quota memory limit is required");
  if (
    file === "k8s/pod-disruption-budgets.yaml" &&
    !content.includes("minAvailable")
  )
    throw new Error("pod disruption budgets must define availability");
  console.log(`PASS ${file}`);
}

// Every port a Compose file publishes names a host address, so nothing listens on every
// interface by default (docs/design/security-hardening.md).
const composeFiles = [
  ...fs
    .readdirSync(".")
    .filter((name) => /^docker-compose.*\.ya?ml$/.test(name)),
  ...fs
    .readdirSync("examples")
    .flatMap((dir) =>
      fs.existsSync(`examples/${dir}/docker-compose.yml`)
        ? [`examples/${dir}/docker-compose.yml`]
        : [],
    ),
];
function unboundPorts(content) {
  const unbound = [];
  let inPorts = false;
  for (const line of content.split("\n")) {
    if (/^\s*ports:\s*$/.test(line)) {
      inPorts = true;
      continue;
    }
    const entry = line.match(/^\s*-\s*["']?([^"'\s]+)["']?\s*$/);
    if (inPorts && entry) {
      // Collapse ${VAR:-default} so its own colon doesn't count as a separator.
      const parts = entry[1].replace(/\$\{[^}]*\}/g, "X").split(":");
      const address = entry[1].startsWith("${") ? null : parts[0];
      if (parts.length < 3 || address === "0.0.0.0") unbound.push(entry[1]);
      continue;
    }
    inPorts = false;
  }
  return unbound;
}
for (const file of composeFiles) {
  const unbound = unboundPorts(fs.readFileSync(file, "utf8"));
  if (unbound.length)
    throw new Error(
      `${file} publishes ports without a host address: ${unbound.join(", ")}`,
    );
  console.log(`PASS ${file} binds every published port to an address`);
}
