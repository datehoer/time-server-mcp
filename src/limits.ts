import { randomUUID } from "node:crypto";

export type RedisClientLike = {
  eval: (script: string, options: { keys: string[]; arguments: string[] }) => Promise<unknown>;
  multi: () => any;
  zRem: (key: string, member: string) => Promise<unknown>;
};

export type CounterStore = {
  incrWithExpire(key: string, ttlSeconds: number): Promise<number>;
};

export function createInMemoryCounterStore(): CounterStore {
  const map = new Map<string, { value: number; expiresAt: number }>();

  function cleanup(now: number) {
    for (const [k, v] of map) {
      if (v.expiresAt <= now) map.delete(k);
    }
  }

  return {
    async incrWithExpire(key: string, ttlSeconds: number) {
      const now = Date.now();
      cleanup(now);
      const existing = map.get(key);
      if (!existing || existing.expiresAt <= now) {
        map.set(key, { value: 1, expiresAt: now + ttlSeconds * 1000 });
        return 1;
      }
      existing.value += 1;
      return existing.value;
    },
  };
}

export function createRedisCounterStore(redis: RedisClientLike): CounterStore {
  const script = `
local v = redis.call('INCR', KEYS[1])
if v == 1 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return v
`;
  return {
    async incrWithExpire(key: string, ttlSeconds: number) {
      const v = await redis.eval(script, { keys: [key], arguments: [String(ttlSeconds)] });
      return Number(v);
    },
  };
}

export type RateLimitResult = { allowed: true } | { allowed: false; retryAfterSeconds: number };

export function createFixedWindowPerMinuteLimiter(opts: {
  store: CounterStore;
  keyPrefix: string;
  limitPerMinute: number;
}) {
  const { store, keyPrefix, limitPerMinute } = opts;
  return {
    async check(keyParts: string[]): Promise<RateLimitResult> {
      const now = Date.now();
      const window = Math.floor(now / 60_000);
      const key = `${keyPrefix}:${keyParts.join(":")}:${window}`;
      const ttlSeconds = 120;
      const n = await store.incrWithExpire(key, ttlSeconds);
      if (n <= limitPerMinute) return { allowed: true };
      const nextWindowMs = (window + 1) * 60_000;
      const retryAfterSeconds = Math.max(1, Math.ceil((nextWindowMs - now) / 1000));
      return { allowed: false, retryAfterSeconds };
    },
  };
}

export type SseAcquireResult =
  | { allowed: true; connId: string }
  | { allowed: false; retryAfterSeconds: number; active: number };

export type SseLimiter = {
  tryAcquire(ip: string): Promise<SseAcquireResult>;
  refresh(ip: string, connId: string): Promise<void>;
  release(ip: string, connId: string): Promise<void>;
};

export function createInMemorySseLimiter(opts: { maxConnsPerIp: number; maxAgeMs: number }): SseLimiter {
  const { maxConnsPerIp, maxAgeMs } = opts;
  const map = new Map<string, Map<string, number>>();

  function cleanup(ip: string, now: number) {
    const conns = map.get(ip);
    if (!conns) return;
    for (const [id, ts] of conns) {
      if (now - ts > maxAgeMs) conns.delete(id);
    }
    if (conns.size === 0) map.delete(ip);
  }

  return {
    async tryAcquire(ip: string) {
      const now = Date.now();
      cleanup(ip, now);
      const conns = map.get(ip) ?? new Map<string, number>();
      if (conns.size >= maxConnsPerIp) return { allowed: false, retryAfterSeconds: 60, active: conns.size };
      const connId = randomUUID();
      conns.set(connId, now);
      map.set(ip, conns);
      return { allowed: true, connId };
    },
    async refresh(ip: string, connId: string) {
      const now = Date.now();
      cleanup(ip, now);
      const conns = map.get(ip);
      if (!conns) return;
      if (conns.has(connId)) conns.set(connId, now);
    },
    async release(ip: string, connId: string) {
      const conns = map.get(ip);
      if (!conns) return;
      conns.delete(connId);
      if (conns.size === 0) map.delete(ip);
    },
  };
}

export function createRedisSseLimiter(opts: {
  redis: RedisClientLike;
  keyPrefix: string;
  maxConnsPerIp: number;
  maxAgeMs: number;
  ttlSeconds: number;
}): SseLimiter {
  const { redis, keyPrefix, maxConnsPerIp, maxAgeMs, ttlSeconds } = opts;
  const acquireScript = `
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', ARGV[1] - ARGV[2])
local count = redis.call('ZCARD', KEYS[1])
if count >= tonumber(ARGV[3]) then
  return {0, count}
end
redis.call('ZADD', KEYS[1], ARGV[1], ARGV[4])
redis.call('EXPIRE', KEYS[1], ARGV[5])
return {1, count + 1}
`;

  return {
    async tryAcquire(ip: string) {
      const connId = randomUUID();
      const now = Date.now();
      const key = `${keyPrefix}:${ip}`;
      const res = (await redis.eval(acquireScript, {
        keys: [key],
        arguments: [String(now), String(maxAgeMs), String(maxConnsPerIp), connId, String(ttlSeconds)],
      })) as unknown;

      const [ok, active] = Array.isArray(res) ? res : [0, 0];
      const allowed = Number(ok) === 1;
      if (!allowed) return { allowed: false, retryAfterSeconds: 60, active: Number(active) || 0 };
      return { allowed: true, connId };
    },
    async refresh(ip: string, connId: string) {
      const key = `${keyPrefix}:${ip}`;
      const now = Date.now();
      await redis.multi().zAdd(key, [{ score: now, value: connId }]).expire(key, ttlSeconds).exec();
    },
    async release(ip: string, connId: string) {
      const key = `${keyPrefix}:${ip}`;
      await redis.zRem(key, connId);
    },
  };
}
