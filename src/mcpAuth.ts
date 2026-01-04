import type { Request, Response } from "express";
import type { Db } from "./db.js";
import type { RedisClientLike } from "./redisLike.js";
import { sha256Hex } from "./security.js";

export type ApiKeyAuth = { accountId: string; apiKeyId: string };

function parseBearer(req: Request): string | null {
  const auth = req.header("authorization") ?? "";
  const prefix = "Bearer ";
  if (!auth.startsWith(prefix)) return null;
  const token = auth.slice(prefix.length).trim();
  return token.length ? token : null;
}

export async function requireApiKey(req: Request, res: Response, deps: { db: Db; redis: RedisClientLike }) {
  const token = parseBearer(req);
  if (!token) {
    res.status(401).send("Unauthorized");
    return null;
  }
  const keyHash = sha256Hex(token);

  // Redis 缓存：避免每次都打 Postgres
  const cacheKey = `ak:${keyHash}`;
  const cached = await deps.redis.get(cacheKey);
  if (cached) {
    const [accountId, apiKeyId] = cached.split(":");
    if (accountId && apiKeyId) {
      const revoked = await deps.redis.get(`akrev:${apiKeyId}`);
      if (revoked) {
        res.status(401).send("Unauthorized");
        return null;
      }
      return { accountId, apiKeyId } as ApiKeyAuth;
    }
  }

  const r = await deps.db.query<{ id: string; account_id: string; revoked_at: string | null }>(
    "SELECT id, account_id, revoked_at FROM api_keys WHERE key_hash=$1 LIMIT 1",
    [keyHash],
  );
  const row = r.rows[0];
  if (!row || row.revoked_at) {
    if (row?.id) await deps.redis.set(`akrev:${row.id}`, "1", { EX: 600 });
    res.status(401).send("Unauthorized");
    return null;
  }
  await deps.redis.set(cacheKey, `${row.account_id}:${row.id}`, { EX: 300 });
  return { accountId: row.account_id, apiKeyId: row.id } as ApiKeyAuth;
}
