import type { Express, Request, Response } from "express";
import svgCaptcha from "svg-captcha";
import type { RedisClientLike } from "./redisLike.js";

// 统一的验证码场景：避免不同入口复用同一验证码，降低被滥用的风险。
export type CaptchaScene = "admin_login" | "dashboard_login" | "dashboard_register" | "auth_login" | "auth_register";

const AllowedScenes = new Set<CaptchaScene>(["admin_login", "dashboard_login", "dashboard_register", "auth_login", "auth_register"]);

function normalize(input: string, ignoreCase: boolean) {
  const s = input.trim();
  return ignoreCase ? s.toLowerCase() : s;
}

function captchaKey(scene: CaptchaScene, sessionId: string) {
  return `cap:${scene}:${sessionId}`;
}

function badRequest(req: Request, res: Response, format: "json" | "text", error: string, httpStatus = 400) {
  if (format === "json") res.status(httpStatus).json({ ok: false, error });
  else res.status(httpStatus).send(error);
}

export function registerCaptchaRoutes(
  app: Express,
  deps: { redis: RedisClientLike; ttlSeconds: number; length: number; ignoreCase: boolean },
) {
  // 生成 SVG 验证码：依赖 express-session 的 sessionID，验证码文本写入 Redis（带 TTL）。
  app.get("/captcha/svg", async (req: Request, res: Response) => {
    const sceneRaw = String(req.query?.scene ?? "");
    if (!AllowedScenes.has(sceneRaw as CaptchaScene)) return res.status(400).send("Invalid captcha scene.");
    const scene = sceneRaw as CaptchaScene;

    const sid = req.sessionID;
    if (!sid) return res.status(500).send("Captcha session not initialized.");

    const cap = svgCaptcha.create({
      size: deps.length,
      noise: 2,
      color: true,
      background: "#f6f6f6",
      // 尽量避开易混淆字符
      ignoreChars: "0oO1iIlL",
    });

    const expected = normalize(cap.text ?? "", deps.ignoreCase);
    await deps.redis.set(captchaKey(scene, sid), expected, { EX: deps.ttlSeconds });

    // 强制不缓存：避免浏览器缓存旧验证码导致用户误判。
    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");
    res.status(200).type("image/svg+xml").send(cap.data);
  });
}

export async function requireCaptcha(
  req: Request,
  res: Response,
  deps: { redis: RedisClientLike; scene: CaptchaScene; value: unknown; ignoreCase: boolean; format: "json" | "text" },
) {
  // `req.sessionID` 由 express-session 提供（只读）。
  const sid = req.sessionID;
  if (!sid) {
    badRequest(req, res, deps.format, "Captcha session not initialized", 500);
    return false;
  }

  const input = normalize(String(deps.value ?? ""), deps.ignoreCase);
  if (!input) {
    badRequest(req, res, deps.format, "Captcha required", 400);
    return false;
  }

  const key = captchaKey(deps.scene, sid);
  const expected = await deps.redis.get(key);
  if (!expected) {
    badRequest(req, res, deps.format, "Captcha expired", 400);
    return false;
  }

  if (expected !== input) {
    // 安全策略：输错也删除，强制刷新验证码（避免同一验证码被反复尝试）。
    await deps.redis.del(key);
    badRequest(req, res, deps.format, "Captcha incorrect", 400);
    return false;
  }

  // 一次性验证码：校验成功立即删除
  await deps.redis.del(key);
  return true;
}

