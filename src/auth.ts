import { Controller, Post, Req, Res } from "@nestjs/common";
import type { FastifyReply, FastifyRequest } from "fastify";
import { randomUUID } from "node:crypto";
import { z } from "zod";
import type { Db } from "./db.js";
import type { RedisClientLike } from "./redisLike.js";
import { hashPassword, verifyPassword } from "./security.js";
import { requireCaptcha } from "./captcha.js";
import { AppContextService } from "./appContext.service.js";
import { sendApiError } from "./apiError.js";

const RegisterSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8).max(200),
  captcha: z.string().min(1).max(64),
});
const LoginSchema = RegisterSchema;

function setSessionCookie(reply: FastifyReply, cookieName: string, sid: string, opts: { ttlSeconds: number; cookieSecure: boolean }) {
  reply.setCookie(cookieName, sid, {
    httpOnly: true,
    sameSite: "lax",
    secure: opts.cookieSecure,
    maxAge: opts.ttlSeconds,
    path: "/",
  });
}

export async function requireSession(
  req: FastifyRequest,
  reply: FastifyReply,
  deps: { redis: RedisClientLike; cookieName: string },
) {
  const cookies = (req as any).cookies as Record<string, string> | undefined;
  const sid = cookies?.[deps.cookieName] ?? "";
  if (!sid) {
    sendApiError(req, reply, {
      format: "json",
      httpStatus: 401,
      code: "UNAUTHORIZED",
      i18n: { zh: "未登录或登录已过期。", en: "Unauthorized." },
    });
    return null;
  }
  const accountId = await deps.redis.get(`sess:${sid}`);
  if (!accountId) {
    sendApiError(req, reply, {
      format: "json",
      httpStatus: 401,
      code: "UNAUTHORIZED",
      i18n: { zh: "未登录或登录已过期。", en: "Unauthorized." },
    });
    return null;
  }
  return { accountId };
}

@Controller("auth")
export class AuthController {
  constructor(private readonly ctx: AppContextService) {}

  private ensureEnabled(req: FastifyRequest, reply: FastifyReply) {
    if (!this.ctx.dbAuthEnabled || !this.ctx.db || !this.ctx.redis) {
      sendApiError(req, reply, {
        format: "json",
        httpStatus: 404,
        code: "ACCOUNT_SYSTEM_DISABLED",
        i18n: { zh: "账号系统未启用。", en: "Account system disabled." },
      });
      return false;
    }
    return true;
  }

  @Post("register")
  async register(@Req() req: FastifyRequest, @Res() reply: FastifyReply) {
    if (!this.ensureEnabled(req, reply)) return;

    const input = RegisterSchema.safeParse((req as any).body);
    if (!input.success) {
      sendApiError(req, reply, { format: "json", httpStatus: 400, code: "INVALID_INPUT", i18n: { zh: "输入不合法。", en: "Invalid input." } });
      return;
    }

    // 注册必须验证码：场景与入口绑定；一次性校验通过即删除。
    if (
      !(await requireCaptcha(req, reply, {
        redis: this.ctx.redis as any,
        scene: "auth_register",
        value: input.data.captcha,
        ignoreCase: this.ctx.cfg.CAPTCHA_IGNORE_CASE,
        format: "json",
        cookieSecure: this.ctx.cfg.AUTH_COOKIE_SECURE,
      }))
    )
      return;

    const db: Db = this.ctx.db!;
    const redis: RedisClientLike = this.ctx.redis as any;

    const email = input.data.email.toLowerCase();
    const passwordHash = await hashPassword(input.data.password);
    const id = randomUUID();

    try {
      await db.query("INSERT INTO accounts (id, email, password_hash) VALUES ($1,$2,$3)", [id, email, passwordHash]);
      return reply.code(201).send({ ok: true });
    } catch {
      sendApiError(req, reply, { format: "json", httpStatus: 409, code: "EMAIL_EXISTS", i18n: { zh: "Email 已存在。", en: "Email already exists." } });
      return;
    }
  }

  @Post("login")
  async login(@Req() req: FastifyRequest, @Res() reply: FastifyReply) {
    if (!this.ensureEnabled(req, reply)) return;

    const input = LoginSchema.safeParse((req as any).body);
    if (!input.success) {
      sendApiError(req, reply, { format: "json", httpStatus: 400, code: "INVALID_INPUT", i18n: { zh: "输入不合法。", en: "Invalid input." } });
      return;
    }

    // 登录必须验证码：场景与入口绑定；一次性校验通过即删除。
    if (
      !(await requireCaptcha(req, reply, {
        redis: this.ctx.redis as any,
        scene: "auth_login",
        value: input.data.captcha,
        ignoreCase: this.ctx.cfg.CAPTCHA_IGNORE_CASE,
        format: "json",
        cookieSecure: this.ctx.cfg.AUTH_COOKIE_SECURE,
      }))
    )
      return;

    const db: Db = this.ctx.db!;
    const redis: RedisClientLike = this.ctx.redis as any;

    const email = input.data.email.toLowerCase();
    const r = await db.query<{ id: string; password_hash: string; disabled_at: string | null }>(
      "SELECT id, password_hash, disabled_at FROM accounts WHERE email=$1 LIMIT 1",
      [email],
    );
    const row = r.rows[0];
    if (!row || row.disabled_at) {
      sendApiError(req, reply, {
        format: "json",
        httpStatus: 401,
        code: "INVALID_CREDENTIALS",
        i18n: { zh: "账号或密码错误。", en: "Invalid credentials." },
      });
      return;
    }

    const ok = await verifyPassword(input.data.password, row.password_hash);
    if (!ok) {
      sendApiError(req, reply, {
        format: "json",
        httpStatus: 401,
        code: "INVALID_CREDENTIALS",
        i18n: { zh: "账号或密码错误。", en: "Invalid credentials." },
      });
      return;
    }

    const sid = randomUUID();
    await redis.set(`sess:${sid}`, row.id, { EX: this.ctx.cfg.AUTH_SESSION_TTL_SECONDS });
    setSessionCookie(reply, this.ctx.cfg.AUTH_SESSION_COOKIE_NAME, sid, {
      ttlSeconds: this.ctx.cfg.AUTH_SESSION_TTL_SECONDS,
      cookieSecure: this.ctx.cfg.AUTH_COOKIE_SECURE,
    });
    return reply.code(200).send({ ok: true });
  }

  @Post("logout")
  async logout(@Req() req: FastifyRequest, @Res() reply: FastifyReply) {
    if (!this.ensureEnabled(req, reply)) return;
    const cookies = (req as any).cookies as Record<string, string> | undefined;
    const sid = cookies?.[this.ctx.cfg.AUTH_SESSION_COOKIE_NAME] ?? "";
    if (sid) await (this.ctx.redis as any).del(`sess:${sid}`);
    reply.clearCookie(this.ctx.cfg.AUTH_SESSION_COOKIE_NAME, { path: "/" });
    return reply.code(200).send({ ok: true });
  }
}
