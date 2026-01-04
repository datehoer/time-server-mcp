import type { Express, Request, Response } from "express";
import { randomUUID } from "node:crypto";
import { z } from "zod";
import type { Db } from "./db.js";
import type { RedisClientLike } from "./redisLike.js";
import { requireSession } from "./auth.js";
import { newApiKeySecret, sha256Hex } from "./security.js";
import { decryptApiKeySecret, encryptApiKeySecret } from "./cryptoBox.js";

export function registerMeRoutes(
  app: Express,
  deps: { db: Db; redis: RedisClientLike; cookieName: string; maxKeysPerAccount: number; encryptionSecret: string },
) {
  const { db, redis, cookieName, maxKeysPerAccount, encryptionSecret } = deps;

  const CreateKeySchema = z.object({ name: z.string().max(100).optional() });

  app.get("/me", async (req: Request, res: Response) => {
    const s = await requireSession(req, res, { redis, cookieName });
    if (!s) return;
    const r = await db.query<{ email: string }>("SELECT email FROM accounts WHERE id=$1 LIMIT 1", [s.accountId]);
    return res.status(200).json({ ok: true, account: { id: s.accountId, email: r.rows[0]?.email ?? "" } });
  });

  app.get("/me/api-keys", async (req: Request, res: Response) => {
    const s = await requireSession(req, res, { redis, cookieName });
    if (!s) return;
    const r = await db.query<{
      id: string;
      name: string;
      prefix: string;
      created_at: string;
      last_used_at: string | null;
      revoked_at: string | null;
    }>(
      "SELECT id, name, prefix, created_at, last_used_at, revoked_at FROM api_keys WHERE account_id=$1 ORDER BY created_at DESC",
      [s.accountId],
    );
    return res.status(200).json({ ok: true, keys: r.rows });
  });

  app.post("/me/api-keys", async (req: Request, res: Response) => {
    const s = await requireSession(req, res, { redis, cookieName });
    if (!s) return;
    const input = CreateKeySchema.safeParse(req.body ?? {});
    if (!input.success) return res.status(400).json({ ok: false, error: "Invalid input" });

    const secret = newApiKeySecret();
    const keyHash = sha256Hex(secret);
    const prefix = secret.slice(0, 10);
    const secretEnc = encryptApiKeySecret(secret, encryptionSecret);
    const id = randomUUID();
    const name = input.data.name ?? "";

    try {
      await db.withTx(async (tx) => {
        // 为了避免并发超发，锁住账号行
        await tx.query("SELECT 1 FROM accounts WHERE id=$1 FOR UPDATE", [s.accountId]);
        const c = await tx.query<{ n: string }>(
          "SELECT COUNT(*)::text AS n FROM api_keys WHERE account_id=$1 AND revoked_at IS NULL",
          [s.accountId],
        );
        const n = Number(c.rows[0]?.n ?? "0");
        if (n >= maxKeysPerAccount) throw new Error("MAX_KEYS");

        await tx.query("INSERT INTO api_keys (id, account_id, name, prefix, key_hash, secret_enc) VALUES ($1,$2,$3,$4,$5,$6)", [
          id,
          s.accountId,
          name,
          prefix,
          keyHash,
          secretEnc,
        ]);
      });
    } catch (err: any) {
      if (String(err?.message ?? "") === "MAX_KEYS") {
        return res.status(409).json({ ok: false, error: `Too many active keys (max=${maxKeysPerAccount})` });
      }
      return res.status(500).json({ ok: false, error: "Failed to create key" });
    }

    // 只在创建时返回一次明文 secret
    return res.status(201).json({ ok: true, key: { id, name, prefix }, secret });
  });

  // 方案B：临时解密取回明文（用于 Dashboard 点击复制）
  app.post("/me/api-keys/:id/reveal", async (req: Request, res: Response) => {
    const s = await requireSession(req, res, { redis, cookieName });
    if (!s) return;
    const id = String(req.params.id ?? "");
    if (!id) return res.status(400).json({ ok: false, error: "Invalid id" });

    const r = await db.query<{ secret_enc: string | null; revoked_at: string | null }>(
      "SELECT secret_enc, revoked_at FROM api_keys WHERE id=$1 AND account_id=$2 LIMIT 1",
      [id, s.accountId],
    );
    const row = r.rows[0];
    if (!row) return res.status(404).json({ ok: false, error: "Not found" });
    if (row.revoked_at) return res.status(409).json({ ok: false, error: "Key revoked" });
    if (!row.secret_enc) return res.status(409).json({ ok: false, error: "Key secret unavailable; please rotate" });

    try {
      const secret = decryptApiKeySecret(row.secret_enc, encryptionSecret);
      return res.status(200).json({ ok: true, secret });
    } catch {
      return res.status(500).json({ ok: false, error: "Failed to decrypt key" });
    }
  });

  app.delete("/me/api-keys/:id", async (req: Request, res: Response) => {
    const s = await requireSession(req, res, { redis, cookieName });
    if (!s) return;
    const id = String(req.params.id ?? "");
    if (!id) return res.status(400).json({ ok: false, error: "Invalid id" });
    const u = await db.query<{ key_hash: string }>(
      "UPDATE api_keys SET revoked_at=now() WHERE id=$1 AND account_id=$2 AND revoked_at IS NULL RETURNING key_hash",
      [id, s.accountId],
    );
    if (u.rows.length === 0) return res.status(404).json({ ok: false, error: "Not found" });

    // 立即失效：清除 keyHash 缓存 + 写入撤销标记（覆盖 requireApiKey 的 5 分钟缓存）
    await redis.del(`ak:${u.rows[0]!.key_hash}`);
    await redis.set(`akrev:${id}`, "1", { EX: 600 });
    return res.status(200).json({ ok: true });
  });
}
