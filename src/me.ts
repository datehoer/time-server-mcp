import { Controller, Delete, Get, Param, Post, Req, Res } from "@nestjs/common";
import type { FastifyReply, FastifyRequest } from "fastify";
import { randomUUID } from "node:crypto";
import { z } from "zod";
import { AppContextService } from "./appContext.service.js";
import { requireSession } from "./auth.js";
import { newApiKeySecret, sha256Hex } from "./security.js";
import { decryptApiKeySecret, encryptApiKeySecret } from "./cryptoBox.js";
import { sendApiError } from "./apiError.js";

@Controller("me")
export class MeController {
  constructor(private readonly ctx: AppContextService) {}

  private ensureEnabled(req: FastifyRequest, reply: FastifyReply) {
    if (!this.ctx.dbAuthEnabled || !this.ctx.db || !this.ctx.redis) {
      sendApiError(req, reply, {
        format: "json",
        httpStatus: 404,
        code: "ACCOUNT_SYSTEM_DISABLED",
        i18n: { zh: "账号系统未启用。", en: "Account/API key management disabled." },
      });
      return false;
    }
    return true;
  }

  @Get()
  async me(@Req() req: FastifyRequest, @Res() reply: FastifyReply) {
    if (!this.ensureEnabled(req, reply)) return;

    const s = await requireSession(req, reply, { redis: this.ctx.redis as any, cookieName: this.ctx.cfg.AUTH_SESSION_COOKIE_NAME });
    if (!s) return;
    const r = await this.ctx.db!.query<{ email: string }>("SELECT email FROM accounts WHERE id=$1 LIMIT 1", [s.accountId]);
    reply.code(200).send({ ok: true, account: { id: s.accountId, email: r.rows[0]?.email ?? "" } });
  }

  @Get("api-keys")
  async listKeys(@Req() req: FastifyRequest, @Res() reply: FastifyReply) {
    if (!this.ensureEnabled(req, reply)) return;

    const s = await requireSession(req, reply, { redis: this.ctx.redis as any, cookieName: this.ctx.cfg.AUTH_SESSION_COOKIE_NAME });
    if (!s) return;
    const r = await this.ctx.db!.query<{
      id: string;
      name: string;
      prefix: string;
      created_at: string;
      last_used_at: string | null;
      revoked_at: string | null;
    }>("SELECT id, name, prefix, created_at, last_used_at, revoked_at FROM api_keys WHERE account_id=$1 ORDER BY created_at DESC", [
      s.accountId,
    ]);
    reply.code(200).send({ ok: true, keys: r.rows });
  }

  @Post("api-keys")
  async createKey(@Req() req: FastifyRequest, @Res() reply: FastifyReply) {
    if (!this.ensureEnabled(req, reply)) return;

    const s = await requireSession(req, reply, { redis: this.ctx.redis as any, cookieName: this.ctx.cfg.AUTH_SESSION_COOKIE_NAME });
    if (!s) return;

    const CreateKeySchema = z.object({ name: z.string().max(100).optional() });
    const input = CreateKeySchema.safeParse((req as any).body ?? {});
    if (!input.success) {
      sendApiError(req, reply, { format: "json", httpStatus: 400, code: "INVALID_INPUT", i18n: { zh: "输入不合法。", en: "Invalid input." } });
      return;
    }

    const secret = newApiKeySecret();
    const keyHash = sha256Hex(secret);
    const prefix = secret.slice(0, 10);
    const secretEnc = encryptApiKeySecret(secret, this.ctx.cfg.API_KEY_ENCRYPTION_SECRET!);
    const id = randomUUID();
    const name = input.data.name ?? "";

    try {
      await this.ctx.db!.withTx(async (tx) => {
        // 为了避免并发超发，锁住账号行
        await tx.query("SELECT 1 FROM accounts WHERE id=$1 FOR UPDATE", [s.accountId]);
        const c = await tx.query<{ n: string }>("SELECT COUNT(*)::text AS n FROM api_keys WHERE account_id=$1 AND revoked_at IS NULL", [s.accountId]);
        const n = Number(c.rows[0]?.n ?? "0");
        if (n >= 10) throw new Error("MAX_KEYS");

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
        sendApiError(req, reply, {
          format: "json",
          httpStatus: 409,
          code: "API_KEY_LIMIT_EXCEEDED",
          i18n: { zh: "可用 Key 数量已达上限（最多 10 个）。", en: "Too many active keys (max=10)." },
        });
        return;
      }
      sendApiError(req, reply, {
        format: "json",
        httpStatus: 500,
        code: "API_KEY_CREATE_FAILED",
        i18n: { zh: "创建 Key 失败，请稍后重试。", en: "Failed to create key." },
      });
      return;
    }

    // 只在创建时返回一次明文 secret
    reply.code(201).send({ ok: true, key: { id, name, prefix }, secret });
  }

  // 方案B：临时解密取回明文（用于 Dashboard 点击复制）
  @Post("api-keys/:id/reveal")
  async reveal(@Req() req: FastifyRequest, @Res() reply: FastifyReply, @Param("id") idParam: string) {
    if (!this.ensureEnabled(req, reply)) return;

    const s = await requireSession(req, reply, { redis: this.ctx.redis as any, cookieName: this.ctx.cfg.AUTH_SESSION_COOKIE_NAME });
    if (!s) return;
    const id = String(idParam ?? "");
    if (!id) {
      sendApiError(req, reply, { format: "json", httpStatus: 400, code: "INVALID_ID", i18n: { zh: "参数不合法。", en: "Invalid id." } });
      return;
    }

    const r = await this.ctx.db!.query<{ secret_enc: string | null; revoked_at: string | null }>(
      "SELECT secret_enc, revoked_at FROM api_keys WHERE id=$1 AND account_id=$2 LIMIT 1",
      [id, s.accountId],
    );
    const row = r.rows[0];
    if (!row) {
      sendApiError(req, reply, { format: "json", httpStatus: 404, code: "NOT_FOUND", i18n: { zh: "资源不存在。", en: "Not found." } });
      return;
    }
    if (row.revoked_at) {
      sendApiError(req, reply, { format: "json", httpStatus: 409, code: "API_KEY_REVOKED", i18n: { zh: "Key 已被吊销。", en: "Key revoked." } });
      return;
    }
    if (!row.secret_enc) {
      sendApiError(req, reply, {
        format: "json",
        httpStatus: 409,
        code: "API_KEY_SECRET_UNAVAILABLE",
        i18n: { zh: "Key 明文不可用，请重新生成。", en: "Key secret unavailable; please rotate." },
      });
      return;
    }

    try {
      const secret = decryptApiKeySecret(row.secret_enc, this.ctx.cfg.API_KEY_ENCRYPTION_SECRET!);
      return reply.code(200).send({ ok: true, secret });
    } catch {
      sendApiError(req, reply, {
        format: "json",
        httpStatus: 500,
        code: "API_KEY_DECRYPT_FAILED",
        i18n: { zh: "解密 Key 失败，请稍后重试。", en: "Failed to decrypt key." },
      });
      return;
    }
  }

  @Delete("api-keys/:id")
  async revoke(@Req() req: FastifyRequest, @Res() reply: FastifyReply, @Param("id") idParam: string) {
    if (!this.ensureEnabled(req, reply)) return;

    const s = await requireSession(req, reply, { redis: this.ctx.redis as any, cookieName: this.ctx.cfg.AUTH_SESSION_COOKIE_NAME });
    if (!s) return;
    const id = String(idParam ?? "");
    if (!id) {
      sendApiError(req, reply, { format: "json", httpStatus: 400, code: "INVALID_ID", i18n: { zh: "参数不合法。", en: "Invalid id." } });
      return;
    }
    const u = await this.ctx.db!.query<{ key_hash: string }>(
      "UPDATE api_keys SET revoked_at=now() WHERE id=$1 AND account_id=$2 AND revoked_at IS NULL RETURNING key_hash",
      [id, s.accountId],
    );
    if (u.rows.length === 0) {
      sendApiError(req, reply, { format: "json", httpStatus: 404, code: "NOT_FOUND", i18n: { zh: "资源不存在。", en: "Not found." } });
      return;
    }

    // 立即失效：清除 keyHash 缓存 + 写入撤销标记（覆盖 requireApiKey 的 5 分钟缓存）
    await (this.ctx.redis as any).del(`ak:${u.rows[0]!.key_hash}`);
    await (this.ctx.redis as any).set(`akrev:${id}`, "1", { EX: 600 });
    return reply.code(200).send({ ok: true });
  }
}
