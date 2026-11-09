export function createRedisClient({ connect, disconnect = async () => {}, ping = async () => "PONG" } = {}) {
  if (typeof connect !== "function") throw new TypeError("connect is required");
  let client = null;
  let starting = null;
  return {
    async start() { if (client) return client; if (!starting) starting = (async () => { const candidate = await connect(); await ping(candidate); client = candidate; return client; })().finally(() => { starting = null; }); return starting; },
    async stop() { if (client) { await disconnect(client); client = null; } },
    get connected() { return client !== null; },
  };
}
