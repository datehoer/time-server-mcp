import type { RedisClientLike } from "./redisLike.js";

// Lua：若已达上限则拒绝；否则 INCR 并设置 TTL（首次写入时）
const LUA_INCR_IF_BELOW = `
local current = redis.call('GET', KEYS[1])
if current and tonumber(current) >= tonumber(ARGV[1]) then
  return {0, tonumber(current)}
end
local v = redis.call('INCR', KEYS[1])
if v == 1 then
  redis.call('EXPIRE', KEYS[1], tonumber(ARGV[2]))
end
if v > tonumber(ARGV[1]) then
  return {0, v}
end
return {1, v}
`;

// Lua：双 key 原子扣减（用于“全局额度 + 工具级额度”并存时）
const LUA_INCR_2_IF_BELOW = `
local c1 = redis.call('GET', KEYS[1])
local c2 = redis.call('GET', KEYS[2])
if c1 and tonumber(c1) >= tonumber(ARGV[1]) then
  return {0, tonumber(c1), c2 and tonumber(c2) or 0}
end
if c2 and tonumber(c2) >= tonumber(ARGV[2]) then
  return {0, c1 and tonumber(c1) or 0, tonumber(c2)}
end
local v1 = redis.call('INCR', KEYS[1])
local v2 = redis.call('INCR', KEYS[2])
if v1 == 1 then redis.call('EXPIRE', KEYS[1], tonumber(ARGV[3])) end
if v2 == 1 then redis.call('EXPIRE', KEYS[2], tonumber(ARGV[3])) end
return {1, v1, v2}
`;

export async function incrDailyIfBelow(opts: {
  redis: RedisClientLike;
  key: string;
  limit: number;
  ttlSeconds: number;
}): Promise<{ allowed: boolean; used: number }> {
  const res = (await opts.redis.eval(LUA_INCR_IF_BELOW, {
    keys: [opts.key],
    arguments: [String(opts.limit), String(opts.ttlSeconds)],
  })) as unknown;
  const [ok, used] = Array.isArray(res) ? res : [0, 0];
  return { allowed: Number(ok) === 1, used: Number(used) || 0 };
}

export async function incrDailyPairIfBelow(opts: {
  redis: RedisClientLike;
  key1: string;
  limit1: number;
  key2: string;
  limit2: number;
  ttlSeconds: number;
}): Promise<{ allowed: boolean; used1: number; used2: number }> {
  const res = (await opts.redis.eval(LUA_INCR_2_IF_BELOW, {
    keys: [opts.key1, opts.key2],
    arguments: [String(opts.limit1), String(opts.limit2), String(opts.ttlSeconds)],
  })) as unknown;
  const [ok, used1, used2] = Array.isArray(res) ? res : [0, 0, 0];
  return { allowed: Number(ok) === 1, used1: Number(used1) || 0, used2: Number(used2) || 0 };
}

export function utcDayKey(d = new Date()): string {
  const y = d.getUTCFullYear();
  const m = String(d.getUTCMonth() + 1).padStart(2, "0");
  const dd = String(d.getUTCDate()).padStart(2, "0");
  return `${y}${m}${dd}`;
}

export function secondsUntilNextUtcDay(d = new Date()): number {
  const next = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate() + 1, 0, 0, 0));
  // +60s 缓冲，避免边界抖动导致 TTL 过短
  return Math.max(60, Math.ceil((next.getTime() - d.getTime()) / 1000) + 60);
}
