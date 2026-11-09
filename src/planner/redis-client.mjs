export function createRedisClient({ connect, disconnect = async () => {}, ping = async () => "PONG" } = {}) {
  if (typeof connect !== "function") throw new TypeError("connect is required");
  let client = null;
  return {
    async start() { if (!client) client = await connect(); await ping(client); return client; },
    async stop() { if (client) { await disconnect(client); client = null; } },
    get connected() { return client !== null; },
  };
}
