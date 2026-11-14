const base = (process.env.DASHBOARD_SMOKE_URL || "http://localhost:3001").replace(/\/$/, "");
const pages = ["/dashboard", "/operations", "/setup"];

for (const page of pages) {
  let response;
  for (let attempt = 0; attempt < 10; attempt += 1) {
    try {
      response = await fetch(`${base}${page}`);
      if (response.ok) break;
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  if (!response) throw new Error(`${page} could not reach the dashboard`);
  if (!response.ok) throw new Error(`${page} returned ${response.status}`);
  const html = await response.text();
  if (!/<html[^>]+lang=["']en["']/.test(html)) throw new Error(`${page} is missing an English document language`);
  if (!/<meta[^>]+name=["']viewport["']/.test(html)) throw new Error(`${page} is missing a responsive viewport declaration`);
  if (!/<main[\s>]/.test(html)) throw new Error(`${page} is missing the main landmark`);
  for (const image of html.matchAll(/<img\b[^>]*>/gi)) {
    if (!/\balt=["'][^"']*["']/.test(image[0])) throw new Error(`${page} contains an image without alt text`);
  }
}

console.log(`PASS accessibility shell checks for ${pages.length} dashboard pages at ${base}`);
