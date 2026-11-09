/** Adapt a node-redis compatible client to the distributed limiter contract. */
export function createRedisIncrement(redisClient) {
  if (!redisClient || typeof redisClient.incr !== "function" || typeof redisClient.expire !== "function") {
    throw new TypeError("redisClient must provide incr and expire");
  }
  return async (key, windowMs) => {
    const count = await redisClient.incr(key);
    if (count === 1) await redisClient.expire(key, Math.ceil(windowMs / 1000));
    return count;
  };
}
