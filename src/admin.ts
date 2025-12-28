import type { Request, Response } from "express";
import { randomInt } from "node:crypto";
import { parseCookies, signCookie, verifySignedCookie } from "./httpUtil.js";

export type AdminConfig = {
  username: string;
  password: string;
  cookieSecret: string;
  cookieSecure: boolean;
  sessionTtlSeconds: number;
};

type SessionPayload = { u: string; exp: number };
type CaptchaPayload = { a: number; b: number; exp: number };

function setCookie(res: Response, name: string, value: string, opts: { maxAgeSeconds?: number; httpOnly?: boolean; secure?: boolean; sameSite?: "Lax" | "Strict"; path?: string } = {}) {
  const parts = [`${name}=${encodeURIComponent(value)}`];
  parts.push(`Path=${opts.path ?? "/"}`);
  if (opts.httpOnly ?? true) parts.push("HttpOnly");
  if (opts.secure) parts.push("Secure");
  parts.push(`SameSite=${opts.sameSite ?? "Lax"}`);
  if (typeof opts.maxAgeSeconds === "number") parts.push(`Max-Age=${Math.floor(opts.maxAgeSeconds)}`);
  res.append("Set-Cookie", parts.join("; "));
}

function clearCookie(res: Response, name: string) {
  res.append("Set-Cookie", `${name}=; Path=/; Max-Age=0`);
}

function getSession(req: Request, cfg: AdminConfig): SessionPayload | null {
  const cookies = parseCookies(req.headers.cookie);
  const payload = verifySignedCookie<SessionPayload>(cfg.cookieSecret, cookies["admin_session"]);
  if (!payload) return null;
  if (payload.exp <= Date.now()) return null;
  if (payload.u !== cfg.username) return null;
  return payload;
}

function requireSession(req: Request, res: Response, cfg: AdminConfig) {
  const s = getSession(req, cfg);
  if (!s) {
    res.redirect(302, "/admin/login");
    return null;
  }
  return s;
}

export function registerAdminRoutes(app: any, cfg: AdminConfig, getStats: () => Record<string, unknown>) {
  app.get("/admin/login", (req: Request, res: Response) => {
    const a = randomInt(1, 10);
    const b = randomInt(1, 10);
    const exp = Date.now() + 5 * 60_000;
    const captcha = signCookie(cfg.cookieSecret, { a, b, exp } satisfies CaptchaPayload);
    setCookie(res, "admin_captcha", captcha, { maxAgeSeconds: 5 * 60, httpOnly: true, secure: cfg.cookieSecure, sameSite: "Lax", path: "/admin" });

    res.status(200).type("html").send(`<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Admin Login</title>
  <style>
    body{font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto;max-width:480px;margin:40px auto;padding:0 16px;line-height:1.5}
    .card{border:1px solid #e5e7eb;border-radius:12px;padding:16px}
    label{display:block;margin:10px 0 4px}
    input{width:100%;padding:10px;border:1px solid #d1d5db;border-radius:10px}
    button{margin-top:14px;width:100%;padding:10px;border-radius:10px;border:0;background:#111827;color:#fff;font-weight:600}
    small{color:#6b7280}
  </style>
</head>
<body>
  <h1>Dashboard 登录</h1>
  <div class="card">
    <form method="post" action="/admin/login">
      <label>用户名</label>
      <input name="username" autocomplete="username" required />
      <label>密码</label>
      <input type="password" name="password" autocomplete="current-password" required />
      <label>验证码：${a} + ${b} = ?</label>
      <input name="captcha" inputmode="numeric" required />
      <button type="submit">登录</button>
      <p><small>无注册入口，仅允许配置账号登录。</small></p>
    </form>
  </div>
</body>
</html>`);
  });

  app.post("/admin/login", (req: Request, res: Response) => {
    const cookies = parseCookies(req.headers.cookie);
    const captcha = verifySignedCookie<CaptchaPayload>(cfg.cookieSecret, cookies["admin_captcha"]);
    if (!captcha || captcha.exp <= Date.now()) {
      res.status(400).send("Captcha expired. Please retry.");
      return;
    }

    const username = String(req.body?.username ?? "");
    const password = String(req.body?.password ?? "");
    const answer = Number.parseInt(String(req.body?.captcha ?? ""), 10);
    if (!Number.isFinite(answer) || answer !== captcha.a + captcha.b) {
      res.status(400).send("Captcha incorrect.");
      return;
    }

    if (username !== cfg.username || password !== cfg.password) {
      res.status(401).send("Invalid credentials.");
      return;
    }

    clearCookie(res, "admin_captcha");
    const exp = Date.now() + cfg.sessionTtlSeconds * 1000;
    const session = signCookie(cfg.cookieSecret, { u: cfg.username, exp } satisfies SessionPayload);
    setCookie(res, "admin_session", session, {
      maxAgeSeconds: cfg.sessionTtlSeconds,
      httpOnly: true,
      secure: cfg.cookieSecure,
      sameSite: "Lax",
      path: "/admin",
    });
    res.redirect(302, "/admin");
  });

  app.post("/admin/logout", (req: Request, res: Response) => {
    clearCookie(res, "admin_session");
    res.redirect(302, "/admin/login");
  });

  app.get("/admin", (req: Request, res: Response) => {
    const s = requireSession(req, res, cfg);
    if (!s) return;
    const stats = getStats();
    res.status(200).type("html").send(`<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Admin Dashboard</title>
  <style>
    body{font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto;max-width:860px;margin:40px auto;padding:0 16px;line-height:1.5}
    .row{display:flex;gap:16px;flex-wrap:wrap}
    .card{flex:1 1 260px;border:1px solid #e5e7eb;border-radius:12px;padding:16px}
    pre{background:#0b1020;color:#e5e7eb;padding:12px;border-radius:12px;overflow:auto}
    button{padding:8px 12px;border-radius:10px;border:1px solid #d1d5db;background:#fff}
  </style>
</head>
<body>
  <h1>Admin Dashboard</h1>
  <div class="row">
    <div class="card">
      <div>登录用户：<b>${s.u}</b></div>
      <form method="post" action="/admin/logout" style="margin-top:10px">
        <button type="submit">退出登录</button>
      </form>
    </div>
    <div class="card">
      <div>服务状态</div>
      <pre>${escapeHtml(JSON.stringify(stats, null, 2))}</pre>
    </div>
  </div>
</body>
</html>`);
  });

  app.get("/admin/api/stats", (req: Request, res: Response) => {
    const s = requireSession(req, res, cfg);
    if (!s) return;
    res.status(200).json(getStats());
  });
}

function escapeHtml(s: string) {
  return s
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}
