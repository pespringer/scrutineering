export function loadRedisConfig(env = process.env) {
  const raw = String(env.REDIS_URL || "").trim();
  if (!raw) throw new Error("REDIS_URL is required for distributed limits");
  let url;
  try { url = new URL(raw); } catch { throw new Error("REDIS_URL must be a valid URL"); }
  if (!["redis:", "rediss:"].includes(url.protocol)) throw new Error("REDIS_URL must use redis or rediss");
  if (url.hostname === "localhost" && env.NODE_ENV === "production") throw new Error("production Redis must not use localhost");
  return { url: url.toString(), tls: url.protocol === "rediss:" };
}
