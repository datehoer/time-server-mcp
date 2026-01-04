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
      // 账号禁用：用于 Admin 侧“立即生效”，避免缓存窗口
      const acctDisabled = await deps.redis.get(`acctdis:${accountId}`);
      if (acctDisabled) {
        res.status(401).send("Unauthorized");
        return null;
      }
      const revoked = await deps.redis.get(`akrev:${apiKeyId}`);
      if (revoked) {
        res.status(401).send("Unauthorized");
        return null;
      }
      return { accountId, apiKeyId } as ApiKeyAuth;
    }
  }

  const r = await deps.db.query<{ id: string; account_id: string; revoked_at: string | null; disabled_at: string | null }>(
    `
SELECT k.id, k.account_id, k.revoked_at, a.disabled_at
FROM api_keys k
JOIN accounts a ON a.id = k.account_id
WHERE k.key_hash=$1
LIMIT 1
`,
    [keyHash],
  );
  const row = r.rows[0];
  if (!row || row.revoked_at || row.disabled_at) {
    if (row?.id) await deps.redis.set(`akrev:${row.id}`, "1", { EX: 600 });
    if (row?.account_id && row.disabled_at) await deps.redis.set(`acctdis:${row.account_id}`, "1");
    res.status(401).send("Unauthorized");
    return null;
  }
  await deps.redis.set(cacheKey, `${row.account_id}:${row.id}`, { EX: 300 });
  return { accountId: row.account_id, apiKeyId: row.id } as ApiKeyAuth;
}
