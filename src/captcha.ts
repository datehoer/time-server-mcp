import { Controller, Get, Req, Res } from "@nestjs/common";
import type { FastifyReply, FastifyRequest } from "fastify";
import { randomUUID } from "node:crypto";
import svgCaptcha from "svg-captcha";
import type { RedisClientLike } from "./redisLike.js";
import { AppContextService } from "./appContext.service.js";
import { sendApiError } from "./apiError.js";

// 统一的验证码场景：避免不同入口复用同一验证码，降低被滥用的风险。
export type CaptchaScene = "admin_login" | "dashboard_login" | "dashboard_register" | "auth_login" | "auth_register";

const AllowedScenes = new Set<CaptchaScene>(["admin_login", "dashboard_login", "dashboard_register", "auth_login", "auth_register"]);
const CAPTCHA_COOKIE_NAME = "captcha_sid";

function normalize(input: string, ignoreCase: boolean) {
  const s = input.trim();
  return ignoreCase ? s.toLowerCase() : s;
}

function captchaKey(scene: CaptchaScene, sessionId: string) {
  return `cap:${scene}:${sessionId}`;
}

function badRequest(
  req: FastifyRequest,
  reply: FastifyReply,
  format: "json" | "text",
  code: string,
  i18n: { zh: string; en: string },
  httpStatus = 400,
) {
  sendApiError(req, reply, { format, httpStatus, code, i18n });
}

function getCaptchaSessionId(req: FastifyRequest) {
  const cookies = (req as any).cookies as Record<string, string> | undefined;
  const sid = cookies?.[CAPTCHA_COOKIE_NAME];
  return typeof sid === "string" && sid.trim() ? sid : null;
}

function ensureCaptchaSessionId(req: FastifyRequest, reply: FastifyReply, cookieSecure: boolean) {
  const existing = getCaptchaSessionId(req);
  if (existing) return existing;
  const sid = randomUUID();
  reply.setCookie(CAPTCHA_COOKIE_NAME, sid, {
    httpOnly: true,
    sameSite: "lax",
    secure: cookieSecure,
    path: "/",
    // 7 天：足够覆盖多数“重复尝试”，且不会太长
    maxAge: 7 * 24 * 3600,
  });
  return sid;
}

@Controller("captcha")
export class CaptchaController {
  constructor(private readonly ctx: AppContextService) {}

  @Get("svg")
  async svg(@Req() req: FastifyRequest, @Res() reply: FastifyReply) {
    const sceneRaw = String((req.query as any)?.scene ?? "");
    if (!AllowedScenes.has(sceneRaw as CaptchaScene)) {
      badRequest(req, reply, "text", "CAPTCHA_SCENE_INVALID", { zh: "验证码场景无效。", en: "Invalid captcha scene." }, 400);
      return;
    }
    const scene = sceneRaw as CaptchaScene;

    if (!this.ctx.redis) {
      badRequest(req, reply, "text", "REDIS_REQUIRED", { zh: "验证码功能需要启用 Redis（REDIS_URL）。", en: "Captcha requires REDIS_URL." }, 500);
      return;
    }

    const sid = ensureCaptchaSessionId(req, reply, this.ctx.cfg.AUTH_COOKIE_SECURE);
    if (!sid) {
      badRequest(
        req,
        reply,
        "text",
        "CAPTCHA_SESSION_NOT_INITIALIZED",
        { zh: "验证码会话未初始化，请刷新页面重试。", en: "Captcha session not initialized." },
        500,
      );
      return;
    }

    const cap = svgCaptcha.create({
      size: this.ctx.cfg.CAPTCHA_LENGTH,
      noise: 2,
      color: true,
      background: "#f6f6f6",
      // 尽量避开易混淆字符
      ignoreChars: "0oO1iIlL",
    });

    const expected = normalize(cap.text ?? "", this.ctx.cfg.CAPTCHA_IGNORE_CASE);
    await this.ctx.redis.set(captchaKey(scene, sid), expected, { EX: this.ctx.cfg.CAPTCHA_TTL_SECONDS });

    // 强制不缓存：避免浏览器缓存旧验证码导致用户误判。
    reply.header("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
    reply.header("Pragma", "no-cache");
    reply.header("Expires", "0");
    reply.code(200).type("image/svg+xml").send(cap.data);
  }
}

export async function requireCaptcha(
  req: FastifyRequest,
  reply: FastifyReply,
  deps: { redis: RedisClientLike; scene: CaptchaScene; value: unknown; ignoreCase: boolean; format: "json" | "text"; cookieSecure: boolean },
) {
  // cookie 会话：验证码的“绑定因子”。没有 cookie，等价于未初始化。
  const sid = getCaptchaSessionId(req) ?? ensureCaptchaSessionId(req, reply, deps.cookieSecure);
  if (!sid) {
    badRequest(
      req,
      reply,
      deps.format,
      "CAPTCHA_SESSION_NOT_INITIALIZED",
      { zh: "验证码会话未初始化，请刷新页面重试。", en: "Captcha session not initialized." },
      500,
    );
    return false;
  }

  const input = normalize(String(deps.value ?? ""), deps.ignoreCase);
  if (!input) {
    badRequest(req, reply, deps.format, "CAPTCHA_REQUIRED", { zh: "请输入验证码。", en: "Captcha required." }, 400);
    return false;
  }

  const key = captchaKey(deps.scene, sid);
  const expected = await deps.redis.get(key);
  if (!expected) {
    badRequest(req, reply, deps.format, "CAPTCHA_EXPIRED", { zh: "验证码已过期，请刷新后重试。", en: "Captcha expired." }, 400);
    return false;
  }

  if (expected !== input) {
    // 安全策略：输错也删除，强制刷新验证码（避免同一验证码被反复尝试）。
    await deps.redis.del(key);
    badRequest(req, reply, deps.format, "CAPTCHA_INCORRECT", { zh: "验证码错误，请重试。", en: "Captcha incorrect." }, 400);
    return false;
  }

  // 一次性验证码：校验成功立即删除
  await deps.redis.del(key);
  return true;
}
