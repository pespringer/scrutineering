import fs from "node:fs/promises";

export function createFileIdempotencyStore(path) {
  async function read() { try { return JSON.parse(await fs.readFile(path, "utf8")); } catch { return {}; } }
  return {
    async get(key) { return (await read())[key] || null; },
    async set(key, value) { const entries = await read(); entries[key] = value; await fs.writeFile(path, JSON.stringify(entries, null, 2) + "\n", { mode: 0o600 }); },
  };
}
