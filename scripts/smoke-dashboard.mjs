const base = (process.env.DASHBOARD_SMOKE_URL || "http://localhost:3001").replace(/\/$/, "");

async function check(path, expectedStatus = 200) {
  const response = await fetch(`${base}${path}`);
  if (response.status !== expectedStatus) throw new Error(`${path} returned ${response.status}, expected ${expectedStatus}`);
  return response.text();
}

const html = await check("/dashboard");
if (!html.includes("/_next/static/") || !html.includes("__next_f.push")) {
  throw new Error("dashboard HTML did not contain the Next.js browser shell");
}
for (const path of ["/api/posture/summary", "/api/posture/trend", "/api/scans", "/api/images"]) {
  const body = await check(path);
  if (body.includes("DASHBOARD_API_KEY") || body.includes("PYTHON_API_KEY")) {
    throw new Error(`${path} leaked a server-only API credential`);
  }
}
console.log(`PASS dashboard smoke checks at ${base}`);
