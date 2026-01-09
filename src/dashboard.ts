import { Controller, Get, Post, Req, Res } from "@nestjs/common";
import type { FastifyReply, FastifyRequest } from "fastify";
import { randomUUID } from "node:crypto";
import type { RedisClientLike } from "./redisLike.js";
import { getGlobalDailyLimitCached } from "./quota.js";
import { hashPassword, verifyPassword } from "./security.js";
import { iconCopySvg, layoutHtml, modalInlineScripts } from "./ui.js";
import { requireCaptcha } from "./captcha.js";
import { getOrigin } from "./origin.js";
import { AppContextService } from "./appContext.service.js";
import { sendApiError } from "./apiError.js";

function isAjax(req: FastifyRequest) {
  const xrw = String(req.headers["x-requested-with"] ?? "").toLowerCase();
  const accept = String(req.headers["accept"] ?? "").toLowerCase();
  return xrw === "fetch" || accept.includes("application/json");
}

function authPageScripts(opts: { redirectTo: string }) {
  // 纯原生 JS：拦截表单提交，用 fetch 提交，失败时 toast 提示并刷新验证码图。
  return `
(function(){
  var form = document.querySelector('form.form');
  if(!form) return;

  var wrap = document.createElement('div');
  wrap.className = 'toast-wrap';
  wrap.innerHTML = '<div class="toast" id="toast"><div class="toast-title">操作失败</div><div class="toast-msg" id="toast-msg"></div><div class="toast-actions"><button class="btn btn-primary" type="button" id="toast-ok">知道了</button></div></div>';
  document.body.appendChild(wrap);
  var toast = document.getElementById('toast');
  var toastMsg = document.getElementById('toast-msg');
  var toastOk = document.getElementById('toast-ok');

  function showToast(msg){
    if(toastMsg) toastMsg.textContent = msg || '请求失败';
    if(toast) toast.setAttribute('data-show','true');
  }
  function hideToast(){
    if(toast) toast.setAttribute('data-show','false');
  }
  if(toastOk) toastOk.addEventListener('click', hideToast);

  function refreshCaptcha(){
    var img = document.querySelector('img[alt="captcha"]');
    if(!img) return;
    try{
      var u = new URL(img.getAttribute('src') || '', location.href);
      u.searchParams.set('t', String(Date.now()));
      img.setAttribute('src', u.toString());
    }catch(e){}
  }

  form.addEventListener('submit', function(e){
    e.preventDefault();
    var submitBtn = form.querySelector('button[type="submit"]');
    if(submitBtn) submitBtn.disabled = true;

    (async function(){
      try{
        var fd = new FormData(form);
        var body = new URLSearchParams();
        fd.forEach(function(v,k){ body.set(k, String(v)); });

        var r = await fetch(form.getAttribute('action') || location.pathname, {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json', 'X-Requested-With': 'fetch' },
          body: body.toString()
        });

        var data = null;
        try{ data = await r.json(); }catch(_e){ data = null; }
        if(r.ok && data && data.ok){
          location.href = data.redirect || ${JSON.stringify(opts.redirectTo)};
          return;
        }

        // UI 默认中文；同时保留服务端返回的双语结果（error_i18n）
        var msg =
          (data && data.error_i18n && data.error_i18n.zh) ? data.error_i18n.zh
          : ((data && data.error) ? data.error : ('请求失败（' + r.status + '）'));
        showToast(msg);
        refreshCaptcha();
        var cap = form.querySelector('input[name="captcha"]');
        if(cap) cap.value = '';
      }catch(err){
        showToast('网络错误，请重试');
        refreshCaptcha();
      }finally{
        if(submitBtn) submitBtn.disabled = false;
      }
    })();
  });
})();`;
}

async function requireDashboardSession(
  req: FastifyRequest,
  reply: FastifyReply,
  deps: { redis: RedisClientLike; cookieName: string },
) {
  const cookies = (req as any).cookies as Record<string, string> | undefined;
  const sid = cookies?.[deps.cookieName] ?? "";
  if (!sid) {
    reply.redirect("/dashboard/login", 302);
    return null;
  }
  const accountId = await deps.redis.get(`sess:${sid}`);
  if (!accountId) {
    reply.redirect("/dashboard/login", 302);
    return null;
  }
  return { accountId, sid };
}

function utcDayRange(d = new Date()) {
  const dayStart = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate(), 0, 0, 0));
  const dayEnd = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate() + 1, 0, 0, 0));
  const utcDay = `${dayStart.getUTCFullYear()}-${String(dayStart.getUTCMonth() + 1).padStart(2, "0")}-${String(dayStart.getUTCDate()).padStart(2, "0")}`;
  return { dayStartIso: dayStart.toISOString(), dayEndIso: dayEnd.toISOString(), utcDay };
}

function utcYmdKey(d: Date) {
  return `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, "0")}-${String(d.getUTCDate()).padStart(2, "0")}`;
}

type DashboardDeps = {
  db: NonNullable<AppContextService["db"]>;
  redis: RedisClientLike;
  cookieName: string;
  ttlSeconds: number;
  cookieSecure: boolean;
  captchaIgnoreCase: boolean;
  defaultFreeDailyRequestLimit: number;
  policyCacheSeconds: number;
};

@Controller("dashboard")
export class DashboardController {
  constructor(private readonly ctx: AppContextService) {}

  private deps(reply: FastifyReply): DashboardDeps | null {
    if (!this.ctx.dashboardEnabled || !this.ctx.db || !this.ctx.redis) {
      reply.code(404).type("text/plain").send("Dashboard disabled");
      return null;
    }
    return {
      db: this.ctx.db,
      redis: this.ctx.redis as any,
      cookieName: this.ctx.cfg.AUTH_SESSION_COOKIE_NAME,
      ttlSeconds: this.ctx.cfg.AUTH_SESSION_TTL_SECONDS,
      cookieSecure: this.ctx.cfg.AUTH_COOKIE_SECURE,
      captchaIgnoreCase: this.ctx.cfg.CAPTCHA_IGNORE_CASE,
      defaultFreeDailyRequestLimit: this.ctx.cfg.DEFAULT_FREE_DAILY_REQUEST_LIMIT,
      policyCacheSeconds: this.ctx.cfg.POLICY_CACHE_SECONDS,
    };
  }

  private setSession(reply: FastifyReply, deps: DashboardDeps, sid: string) {
    reply.setCookie(deps.cookieName, sid, {
      httpOnly: true,
      sameSite: "lax",
      secure: deps.cookieSecure,
      maxAge: deps.ttlSeconds,
      path: "/",
    });
  }

  @Get("login")
  async loginPage(@Res() reply: FastifyReply) {
    const deps = this.deps(reply);
    if (!deps) return;
    reply.code(200).type("text/html").send(
      layoutHtml({
        title: "Dashboard Login",
        scripts: authPageScripts({ redirectTo: "/dashboard" }),
        body: `
<div class="shell">
  <div class="auth">
    <div class="brand" style="justify-content:center;margin-bottom:14px">
      <div class="logo"><img class="logo-img" src="/assets/logo.png" alt="MCP" width="28" height="28" /></div>
      <div>
        <div class="brand-title">Time Server</div>
        <div class="muted" style="font-size:12px">Dashboard</div>
      </div>
    </div>

    <h1>登录</h1>

    <div class="card card-pad" style="box-shadow:var(--shadow)">
      <form class="form" method="post" action="/dashboard/login">
        <div>
          <label>Email</label>
          <input class="input" name="email" autocomplete="email" required />
        </div>
        <div>
          <label>Password</label>
          <input class="input" type="password" name="password" autocomplete="current-password" required />
        </div>
        <div>
          <label>验证码（点击图片刷新）</label>
          <div style="display:flex;gap:10px;align-items:center">
            <input class="input" name="captcha" autocomplete="off" required />
            <img
              src="/captcha/svg?scene=dashboard_login"
              alt="captcha"
              style="height:40px;cursor:pointer;border-radius:12px;border:1px solid hsl(var(--input));background:hsl(var(--popover))"
              onclick="this.src='/captcha/svg?scene=dashboard_login&t='+Date.now()"
            />
          </div>
        </div>
        <button class="btn btn-primary" type="submit" style="height:40px;border-radius:12px">登录</button>
        <div class="muted" style="font-size:12px">没有账号？<a href="/dashboard/register">去注册</a></div>
      </form>
    </div>
  </div>
</div>
        `,
      }),
    );
  }

  @Get("register")
  async registerPage(@Res() reply: FastifyReply) {
    const deps = this.deps(reply);
    if (!deps) return;
    reply.code(200).type("text/html").send(
      layoutHtml({
        title: "Dashboard Register",
        scripts: authPageScripts({ redirectTo: "/dashboard" }),
        body: `
<div class="shell">
  <div class="auth">
    <div class="brand" style="justify-content:center;margin-bottom:14px">
      <div class="logo"><img class="logo-img" src="/assets/logo.png" alt="MCP" width="28" height="28" /></div>
      <div>
        <div class="brand-title">Time Server</div>
        <div class="muted" style="font-size:12px">Dashboard</div>
      </div>
    </div>

    <h1>注册</h1>

    <div class="card card-pad" style="box-shadow:var(--shadow)">
      <form class="form" method="post" action="/dashboard/register">
        <div>
          <label>Email</label>
          <input class="input" name="email" autocomplete="email" required />
        </div>
        <div>
          <label>Password（>=8）</label>
          <input class="input" type="password" name="password" autocomplete="new-password" required />
        </div>
        <div>
          <label>验证码（点击图片刷新）</label>
          <div style="display:flex;gap:10px;align-items:center">
            <input class="input" name="captcha" autocomplete="off" required />
            <img
              src="/captcha/svg?scene=dashboard_register"
              alt="captcha"
              style="height:40px;cursor:pointer;border-radius:12px;border:1px solid hsl(var(--input));background:hsl(var(--popover))"
              onclick="this.src='/captcha/svg?scene=dashboard_register&t='+Date.now()"
            />
          </div>
        </div>
        <button class="btn btn-primary" type="submit" style="height:40px;border-radius:12px">注册并登录</button>
        <div class="muted" style="font-size:12px">已有账号？<a href="/dashboard/login">去登录</a></div>
      </form>
    </div>
  </div>
</div>
        `,
      }),
    );
  }

  @Post("register")
  async register(@Req() req: FastifyRequest, @Res() reply: FastifyReply) {
    const deps = this.deps(reply);
    if (!deps) return;
    const { db, redis, ttlSeconds, captchaIgnoreCase, cookieSecure } = deps;
    const ajax = isAjax(req);

    // 注册必须验证码：一次性校验通过即删除。
    if (
      !(await requireCaptcha(req, reply, {
        redis,
        scene: "dashboard_register",
        value: (req as any).body?.captcha,
        ignoreCase: captchaIgnoreCase,
        format: ajax ? "json" : "text",
        cookieSecure,
      }))
    )
      return;

    const email = String((req as any).body?.email ?? "").toLowerCase();
    const password = String((req as any).body?.password ?? "");
    if (!email.includes("@") || password.length < 8) {
      const format = ajax ? "json" : "text";
      sendApiError(req, reply, { format, httpStatus: 400, code: "INVALID_INPUT", i18n: { zh: "输入不合法。", en: "Invalid input." } });
      return;
    }

    const id = randomUUID();
    const passwordHash = await hashPassword(password);
    try {
      await db.query("INSERT INTO accounts (id, email, password_hash) VALUES ($1,$2,$3)", [id, email, passwordHash]);
    } catch {
      if (ajax) {
        sendApiError(req, reply, { format: "json", httpStatus: 409, code: "EMAIL_EXISTS", i18n: { zh: "Email 已存在。", en: "Email already exists." } });
        return;
      }
      return reply
        .code(409)
        .type("text/html")
        .send(
          layoutHtml({
            title: "Register failed",
            body: `<div class="shell"><div class="container" style="padding:28px 16px"><div class="card card-pad">Email 已存在。<a href="/dashboard/login">去登录</a></div></div></div>`,
          }),
        );
    }

    const sid = randomUUID();
    await redis.set(`sess:${sid}`, id, { EX: ttlSeconds });
    this.setSession(reply, deps, sid);
    if (ajax) return reply.code(200).send({ ok: true, redirect: "/dashboard" });
    reply.redirect("/dashboard", 302);
  }

  @Post("login")
  async login(@Req() req: FastifyRequest, @Res() reply: FastifyReply) {
    const deps = this.deps(reply);
    if (!deps) return;
    const { db, redis, ttlSeconds, captchaIgnoreCase, cookieSecure } = deps;
    const ajax = isAjax(req);

    // 登录必须验证码：一次性校验通过即删除。
    if (
      !(await requireCaptcha(req, reply, {
        redis,
        scene: "dashboard_login",
        value: (req as any).body?.captcha,
        ignoreCase: captchaIgnoreCase,
        format: ajax ? "json" : "text",
        cookieSecure,
      }))
    )
      return;

    const email = String((req as any).body?.email ?? "").toLowerCase();
    const password = String((req as any).body?.password ?? "");
    const r = await db.query<{ id: string; password_hash: string; disabled_at: string | null }>(
      "SELECT id, password_hash, disabled_at FROM accounts WHERE email=$1 LIMIT 1",
      [email],
    );
    const row = r.rows[0];
    if (!row || row.disabled_at) {
      const format = ajax ? "json" : "text";
      sendApiError(req, reply, {
        format,
        httpStatus: 401,
        code: "INVALID_CREDENTIALS",
        i18n: { zh: "账号或密码错误。", en: "Invalid credentials." },
      });
      return;
    }
    const ok = await verifyPassword(password, row.password_hash);
    if (!ok) {
      const format = ajax ? "json" : "text";
      sendApiError(req, reply, {
        format,
        httpStatus: 401,
        code: "INVALID_CREDENTIALS",
        i18n: { zh: "账号或密码错误。", en: "Invalid credentials." },
      });
      return;
    }

    const sid = randomUUID();
    await redis.set(`sess:${sid}`, row.id, { EX: ttlSeconds });
    this.setSession(reply, deps, sid);
    if (ajax) return reply.code(200).send({ ok: true, redirect: "/dashboard" });
    reply.redirect("/dashboard", 302);
  }

  @Post("logout")
  async logout(@Req() req: FastifyRequest, @Res() reply: FastifyReply) {
    const deps = this.deps(reply);
    if (!deps) return;
    const cookies = (req as any).cookies as Record<string, string> | undefined;
    const sid = cookies?.[deps.cookieName] ?? "";
    if (sid) await deps.redis.del(`sess:${sid}`);
    reply.clearCookie(deps.cookieName, { path: "/" });
    reply.redirect("/dashboard/login", 302);
  }

  // Dashboard：按当前登录账号汇总的状态/配额/Usage（迁移自 /admin，但不暴露其他账号数据）
  @Get("api/stats")
  async apiStats(@Req() req: FastifyRequest, @Res() reply: FastifyReply) {
    const deps = this.deps(reply);
    if (!deps) return;
    const { db, redis, cookieName } = deps;
    const s = await requireDashboardSession(req, reply, { redis, cookieName });
    if (!s) return;

    const me = await db.query<{ email: string; disabled_at: string | null }>("SELECT email, disabled_at FROM accounts WHERE id=$1 LIMIT 1", [
      s.accountId,
    ]);
    const meRow = me.rows[0];
    if (!meRow || meRow.disabled_at) {
      sendApiError(req, reply, { format: "json", httpStatus: 401, code: "ACCOUNT_DISABLED", i18n: { zh: "账号已被禁用。", en: "Account disabled." } });
      return;
    }

    const { dayStartIso, dayEndIso, utcDay } = utcDayRange(new Date());
    const dayStart = new Date(dayStartIso);
    const last7Start = new Date(dayStart);
    last7Start.setUTCDate(last7Start.getUTCDate() - 6);

    const totals = await db.query<{ allowed: string | null; denied: string | null }>(
      `
SELECT
  SUM(CASE WHEN allowed THEN 1 ELSE 0 END)::text AS allowed,
  SUM(CASE WHEN NOT allowed THEN 1 ELSE 0 END)::text AS denied
FROM request_logs
WHERE account_id=$1 AND ts >= $2 AND ts < $3
`,
      [s.accountId, dayStartIso, dayEndIso],
    );

    // 折线图：按 UTC 的“小时/日”聚合，并在服务端补齐缺口（前端直接渲染）。
    const hourlyTotals = await db.query<{ hour_utc: number | string; allowed: string | null; denied: string | null }>(
      `
SELECT
  EXTRACT(HOUR FROM ts AT TIME ZONE 'UTC')::int AS hour_utc,
  SUM(CASE WHEN allowed THEN 1 ELSE 0 END)::text AS allowed,
  SUM(CASE WHEN NOT allowed THEN 1 ELSE 0 END)::text AS denied
FROM request_logs
WHERE account_id=$1 AND ts >= $2 AND ts < $3
GROUP BY 1
ORDER BY 1
`,
      [s.accountId, dayStartIso, dayEndIso],
    );
    const hourBuckets = new Map<number, { allowed: number; denied: number }>();
    for (const r of hourlyTotals.rows) {
      const hour = Number(r.hour_utc);
      if (!Number.isFinite(hour) || hour < 0 || hour > 23) continue;
      hourBuckets.set(hour, { allowed: Number(r.allowed ?? "0"), denied: Number(r.denied ?? "0") });
    }
    const hourlyLabels = Array.from({ length: 24 }, (_, h) => `${String(h).padStart(2, "0")}:00`);
    const hourlyAllowed = hourlyLabels.map((_, h) => hourBuckets.get(h)?.allowed ?? 0);
    const hourlyDenied = hourlyLabels.map((_, h) => hourBuckets.get(h)?.denied ?? 0);

    const dailyTotalsLast7 = await db.query<{ day_utc: string; allowed: string | null; denied: string | null }>(
      `
SELECT
  ((ts AT TIME ZONE 'UTC')::date)::text AS day_utc,
  SUM(CASE WHEN allowed THEN 1 ELSE 0 END)::text AS allowed,
  SUM(CASE WHEN NOT allowed THEN 1 ELSE 0 END)::text AS denied
FROM request_logs
WHERE account_id=$1 AND ts >= $2 AND ts < $3
GROUP BY 1
ORDER BY 1
`,
      [s.accountId, last7Start.toISOString(), dayEndIso],
    );
    const dayBuckets = new Map<string, { allowed: number; denied: number }>();
    for (const r of dailyTotalsLast7.rows) {
      const key = String(r.day_utc ?? "");
      if (!key) continue;
      dayBuckets.set(key, { allowed: Number(r.allowed ?? "0"), denied: Number(r.denied ?? "0") });
    }
    const dailyLabels = Array.from({ length: 7 }, (_, i) => {
      const d = new Date(last7Start);
      d.setUTCDate(d.getUTCDate() + i);
      return utcYmdKey(d);
    });
    const dailyAllowed = dailyLabels.map((k) => dayBuckets.get(k)?.allowed ?? 0);
    const dailyDenied = dailyLabels.map((k) => dayBuckets.get(k)?.denied ?? 0);

    const byKey = await db.query<{ api_key_id: string; allowed: string; denied: string }>(
      `
SELECT
  api_key_id,
  SUM(CASE WHEN allowed THEN 1 ELSE 0 END)::text AS allowed,
  SUM(CASE WHEN NOT allowed THEN 1 ELSE 0 END)::text AS denied
FROM request_logs
WHERE account_id=$1 AND ts >= $2 AND ts < $3 AND api_key_id IS NOT NULL
GROUP BY api_key_id
ORDER BY (SUM(CASE WHEN allowed THEN 1 ELSE 0 END)) DESC
LIMIT 20
`,
      [s.accountId, dayStartIso, dayEndIso],
    );

    const meta =
      byKey.rows.length > 0
        ? await db.query<{ id: string; prefix: string; name: string; last_used_at: string | null }>(
            `SELECT id, prefix, name, last_used_at FROM api_keys WHERE account_id=$1 AND id = ANY($2::uuid[])`,
            [s.accountId, byKey.rows.map((r) => r.api_key_id)],
          )
        : { rows: [] as any[] };
    const metaById = new Map(meta.rows.map((r) => [r.id, r]));

    const dailyLimit = await getGlobalDailyLimitCached({
      redis,
      db,
      accountId: s.accountId,
      metric: "requests",
      defaultFree: deps.defaultFreeDailyRequestLimit,
      cacheSeconds: deps.policyCacheSeconds,
    });

    const allowedToday = Number(totals.rows[0]?.allowed ?? "0");
    const deniedToday = Number(totals.rows[0]?.denied ?? "0");

    const origin = getOrigin(req);
    const mcpUrl = `${origin}/mcp`;
    const healthUrl = `${origin}/health`;

    return reply.code(200).send({
      ok: true,
      utc_day: utcDay,
      account: { id: s.accountId, email: meRow.email ?? "" },
      overview: {
        uptime_s: Math.floor(process.uptime()),
        transports: Object.keys(this.ctx.transports).length,
        redis: Boolean(this.ctx.redis),
        db: Boolean(this.ctx.db),
        auth_mode: this.ctx.authMode,
        limits: { rate_limit_per_ip_per_minute: this.ctx.rateLimitPerMinute, sse_max_conns_per_ip: this.ctx.sseMaxConnsPerIp },
      },
      quota: { timezone: "UTC", counts: "tools/call", daily_limit: dailyLimit, used_today: allowedToday + deniedToday },
      usage: {
        allowed: allowedToday,
        denied: deniedToday,
        by_key: byKey.rows.map((r) => {
          const m = metaById.get(r.api_key_id);
          return {
            api_key_id: r.api_key_id,
            prefix: m?.prefix ?? "",
            name: m?.name ?? "",
            last_used_at: m?.last_used_at ?? null,
            allowed: Number(r.allowed ?? "0"),
            denied: Number(r.denied ?? "0"),
          };
        }),
      },
      charts: {
        hourly_today: { labels: hourlyLabels, allowed: hourlyAllowed, denied: hourlyDenied },
        daily_last_7d: { labels: dailyLabels, allowed: dailyAllowed, denied: dailyDenied },
      },
      connect: {
        mcp_url: mcpUrl,
        health_url: healthUrl,
        auth_header_hint: "Authorization: Bearer <YOUR_API_KEY>",
      },
    });
  }

  @Get()
  async dashboard(@Req() req: FastifyRequest, @Res() reply: FastifyReply) {
    const deps = this.deps(reply);
    if (!deps) return;
    const { redis, cookieName } = deps;
    const s = await requireDashboardSession(req, reply, { redis, cookieName });
    if (!s) return;
    reply.code(200).type("text/html").send(
      layoutHtml({
        title: "Dashboard",
        body: `
<div class="shell">
  <header class="topbar">
    <div class="container">
      <div class="topbar-inner">
        <div class="brand">
          <div class="logo"><img class="logo-img" src="/assets/logo.png" alt="MCP" width="28" height="28" /></div>
          <div class="brand-title">Time Server</div>
          <div class="workspace" title="Workspace">
            <span>Personal</span>
            <span aria-hidden="true">▾</span>
          </div>
        </div>

        <nav class="nav" aria-label="Primary">
          <a href="#" data-tab-group="main" data-tab="overview" data-active="true">Overview</a>
          <a href="#" data-tab-group="main" data-tab="usage">Usage</a>
          <a href="#" data-tab-group="main" data-tab="apikeys">API Keys</a>
          <a href="#" data-tab-group="main" data-tab="connect">Connect</a>
          <a href="#" data-tab-group="main" data-tab="api">API</a>
          <a href="#" data-tab-group="main" data-tab="limits">Limits</a>
        </nav>

        <div class="actions">
          <form method="post" action="/dashboard/logout" style="margin:0">
            <button class="btn" type="submit">Logout</button>
          </form>
        </div>
      </div>
    </div>
  </header>

  <main>
    <div class="container">
      <div class="stack">
        <div class="tabs" aria-label="Tabs">
          <button class="tab" data-tab-group="main" data-tab="overview" data-active="true" type="button">Overview</button>
          <button class="tab" data-tab-group="main" data-tab="usage" type="button">Usage</button>
          <button class="tab" data-tab-group="main" data-tab="apikeys" type="button">API Keys</button>
          <button class="tab" data-tab-group="main" data-tab="connect" type="button">Connect</button>
          <button class="tab" data-tab-group="main" data-tab="api" type="button">API</button>
          <button class="tab" data-tab-group="main" data-tab="limits" type="button">Limits</button>
        </div>

        <section data-tab-panel-group="main" data-tab-panel="overview" style="display:block">
          <div id="overviewCards" class="grid grid-4">
            <article class="card card-pad"><div class="kicker">Uptime</div><div class="value">—</div><div class="sub">Server running</div></article>
          </div>
          <div class="card" style="margin-top:18px">
            <div class="card-pad">
              <div class="section-head">
                <div>
                  <h2 class="section-title">Overview</h2>
                  <div class="section-desc">Usage/Quota 均按当前登录账号统计。</div>
                </div>
                <span class="badge badge-ok">Signed In</span>
              </div>
	              <div style="display:grid;gap:12px;margin-top:14px">
	                <div class="field">
	                  <div class="kicker" style="width:74px;flex:0 0 auto">Account</div>
	                  <input id="acct" readonly value="loading…" class="mono" />
	                </div>
	                <div class="field" id="quotaField">
	                  <div class="kicker" style="width:74px;flex:0 0 auto">Quota</div>
	                  <div style="display:flex;align-items:center;gap:12px;flex:1;min-width:0">
	                    <div id="quotaChart" aria-hidden="true" style="width:56px;height:56px;flex:0 0 auto"></div>
	                    <div style="min-width:0">
	                      <div class="mono" id="quotaMain" style="line-height:1.2">loading…</div>
	                      <div class="muted" id="quotaSub" style="font-size:12px;line-height:1.2">—</div>
	                    </div>
	                  </div>
	                </div>
	                <div class="muted" id="status" style="font-size:12px"></div>
	              </div>
            </div>
          </div>

          <div class="card" style="margin-top:18px">
            <div class="card-pad">
              <div class="section-head">
                <div>
                  <h2 class="section-title">Trends (UTC)</h2>
                  <div class="section-desc">近 7 天 <span class="mono">tools/call</span> 趋势（allowed/denied）。</div>
                </div>
              </div>
            </div>
            <div class="card-pad" style="padding-top:0">
              <div class="chart" id="chartDaily7d"></div>
            </div>
          </div>
        </section>

        <section data-tab-panel-group="main" data-tab-panel="usage" style="display:none">
          <div class="card">
            <div class="card-pad">
              <div class="section-head">
                <div>
                  <h2 class="section-title">Usage (UTC today)</h2>
                  <div class="section-desc">仅统计 <span class="mono">tools/call</span>，按当前账号汇总。</div>
                </div>
                <span class="badge" id="usageBadge">loading…</span>
              </div>
            </div>
            <div class="card-pad" style="padding-top:0">
              <div class="chart" id="chartHourlyToday"></div>
            </div>
            <table class="table" aria-label="Usage by key">
              <thead>
                <tr>
                  <th>#</th>
                  <th>Key Prefix</th>
                  <th>Name</th>
                  <th>Allowed</th>
                  <th>Denied</th>
                  <th>Last Used</th>
                </tr>
              </thead>
              <tbody id="usageRows"><tr><td colspan="6" class="muted">loading…</td></tr></tbody>
            </table>
          </div>
        </section>

        <section data-tab-panel-group="main" data-tab-panel="apikeys" style="display:none">
          <div class="card">
            <div class="card-pad">
              <div class="section-head">
                <div>
                  <h2 class="section-title">API Keys</h2>
                  <div class="section-desc">默认仅显示掩码；点击复制将临时解密并写入剪贴板。</div>
                </div>
                <button class="btn btn-primary" type="button" id="btnCreate">Create API Key</button>
              </div>
            </div>

            <table class="table" aria-label="API keys table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Key</th>
                  <th>Created</th>
                  <th>Last Used</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody id="rows"><tr><td colspan="5" class="muted">loading…</td></tr></tbody>
            </table>
          </div>
        </section>

        <section data-tab-panel-group="main" data-tab-panel="connect" style="display:none">
          <div class="card">
            <div class="card-pad">
              <div class="section-head">
                <div>
                  <h2 class="section-title">Connect</h2>
                  <div class="section-desc">复制地址或选择客户端模板快速接入。</div>
                </div>
                <span class="badge badge-ok">Auth: API Key</span>
              </div>

              <div style="display:grid;gap:12px;margin-top:14px">
                <div class="field">
                  <div class="kicker" style="width:74px;flex:0 0 auto">MCP URL</div>
                  <input readonly id="mcpUrl" value="loading…" class="mono" />
                  <button class="icon-btn" type="button" data-copy-text-el="mcpUrl" title="Copy">${iconCopySvg()}</button>
                </div>
                <div class="field">
                  <div class="kicker" style="width:74px;flex:0 0 auto">API URL</div>
                  <input readonly id="healthUrl" value="loading…" class="mono" />
                  <button class="icon-btn" type="button" data-copy-text-el="healthUrl" title="Copy">${iconCopySvg()}</button>
                </div>
              </div>

              <div class="tabs" style="margin-top:16px">
                <button class="tab" data-tab-group="connectTpl" data-tab="cursor" data-active="true" type="button">Cursor</button>
                <button class="tab" data-tab-group="connectTpl" data-tab="vscode" type="button">VS Code</button>
                <button class="tab" data-tab-group="connectTpl" data-tab="generic" type="button">Generic</button>
              </div>
            </div>

            <div class="card-pad" style="padding-top:0">
              <div data-tab-panel-group="connectTpl" data-tab-panel="cursor" style="display:block">
                <pre class="mono" id="tplCursor">loading…</pre>
              </div>
              <div data-tab-panel-group="connectTpl" data-tab-panel="vscode" style="display:none">
                <pre class="mono" id="tplVsCode">loading…</pre>
              </div>
              <div data-tab-panel-group="connectTpl" data-tab-panel="generic" style="display:none">
                <pre class="mono" id="tplGeneric">loading…</pre>
              </div>
            </div>
          </div>
        </section>

        <section data-tab-panel-group="main" data-tab-panel="api" style="display:none">
          <div class="card">
            <div class="card-pad">
              <div class="section-head">
                <div>
                  <h2 class="section-title">API</h2>
                  <div class="section-desc">用 curl 验证服务可用性与工具调用（示例）。</div>
                </div>
              </div>
            </div>

            <div class="card-pad api-grid" style="padding-top:0">
              <div>
                <div class="kicker" style="margin:6px 0 8px">Health</div>
                <pre class="mono" id="curlHealth">loading…</pre>
              </div>
              <div>
                <div class="kicker" style="margin:6px 0 8px">Initialize (creates a session)</div>
                <pre class="mono" id="curlInit">loading…</pre>
              </div>
              <div>
                <div class="kicker" style="margin:6px 0 8px">Call tool: time_now</div>
                <pre class="mono" id="curlTool">loading…</pre>
              </div>
            </div>
          </div>
        </section>

        <section data-tab-panel-group="main" data-tab-panel="limits" style="display:none">
          <div class="card">
            <div class="card-pad">
              <div class="section-head">
                <div>
                  <h2 class="section-title">Limits</h2>
                  <div class="section-desc">运行时限流与 SSE 并发上限。</div>
                </div>
                <span class="badge" id="limitsBadge">loading…</span>
              </div>
            </div>
            <table class="table" aria-label="Limits table">
              <thead>
                <tr>
                  <th>Limiter</th>
                  <th>Value</th>
                  <th>Description</th>
                </tr>
              </thead>
              <tbody id="limitsRows"><tr><td colspan="3" class="muted">loading…</td></tr></tbody>
            </table>
          </div>
        </section>
      </div>
    </div>
  </main>
  <script src="/assets/echarts.min.js"></script>
</div>
        `,
        scripts: `
          (function(){
            const statusEl = document.getElementById('status');
            function flash(msg){
              if(!statusEl) return;
              statusEl.textContent = msg || '';
              if(!msg) return;
              setTimeout(() => { if(statusEl.textContent === msg) statusEl.textContent = ''; }, 2000);
            }
${modalInlineScripts()}
            function fmtDuration(sec){
              sec = Math.max(0, Math.floor(Number(sec)||0));
              const days = Math.floor(sec / 86400);
              const hours = Math.floor((sec % 86400) / 3600);
              const minutes = Math.floor((sec % 3600) / 60);
              if(days>0) return days+'d '+hours+'h';
              if(hours>0) return hours+'h '+minutes+'m';
              return minutes+'m';
            }
            function fmtIso(s){ if(!s) return 'Never'; return s.length>=19 ? s.slice(0,19).replace('T',' ') : s; }
            function esc(s){ return String(s||'').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;'); }
            function pickErr(j, fallback){
              try{
                if(j && j.error_i18n && j.error_i18n.zh) return String(j.error_i18n.zh);
                if(j && j.error) return String(j.error);
              }catch(_e){}
              return fallback || '操作失败';
            }
            const copyIcon = ${JSON.stringify(iconCopySvg())};

            // 折线图：ECharts（无 bundler，直接从 /assets/echarts.min.js 取）
            const chartInstances = Object.create(null);
            function cssHslVar(name, fallback){
              try{
                const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
                return v ? ('hsl(' + v + ')') : fallback;
              }catch(_){ return fallback; }
            }
            function renderLineChart(elId, title, labels, allowed, denied){
              if(!window.echarts) return;
              const el = document.getElementById(elId);
              if(!el) return;
              const chart = chartInstances[elId] || (chartInstances[elId] = window.echarts.init(el));
              const colorOk = cssHslVar('--primary', 'hsl(142 71% 30%)');
              const colorBad = 'hsl(0 72% 35%)';
              chart.setOption({
                animation: false,
                title: { text: title || '', left: 0, top: 0, textStyle: { fontSize: 12, fontWeight: 650 } },
                tooltip: { trigger: 'axis' },
                legend: { top: 26, right: 0, data: ['allowed', 'denied'], itemGap: 14, selectedMode: false },
                grid: { left: 44, right: 16, top: 64, bottom: 40, containLabel: true },
                xAxis: { type: 'category', data: labels || [], axisLabel: { hideOverlap: true, margin: 12 } },
                yAxis: { type: 'value', axisLabel: { margin: 12 } },
                color: [colorOk, colorBad],
                series: [
                  {
                    name: 'allowed',
                    type: 'line',
                    data: allowed || [],
                    smooth: true,
                    showSymbol: false,
                    lineStyle: { width: 2 },
                    emphasis: { disabled: true },
                    select: { disabled: true },
                  },
                  {
                    name: 'denied',
                    type: 'line',
                    data: denied || [],
                    smooth: true,
                    showSymbol: false,
                    lineStyle: { width: 2 },
                    emphasis: { disabled: true },
                    select: { disabled: true },
                  },
                ],
              }, { notMerge: true });
            }

            // Quota 圆环图：used vs remaining（超额时整圈标红，并在文本提示超额）
            function renderQuotaDonut(elId, used, limit){
              if(!window.echarts) return;
              const el = document.getElementById(elId);
              if(!el) return;
              const chart = chartInstances[elId] || (chartInstances[elId] = window.echarts.init(el));
              const u = Math.max(0, Number(used)||0);
              const l = Math.max(0, Number(limit)||0);
              const over = (l > 0) && (u > l);
              const pct = (l > 0) ? Math.round((u / l) * 100) : 0;
              const colorOk = cssHslVar('--primary', 'hsl(142 71% 30%)');
              const colorBad = 'hsl(0 72% 35%)';
              const colorRest = cssHslVar('--muted', 'hsl(210 40% 96%)');
              const usedColor = over ? colorBad : colorOk;
              const label = (l > 0) ? (String(pct) + '%') : '—';
              chart.setOption({
                animation: false,
                tooltip: { show: false },
                series: [{
                  type: 'pie',
                  radius: ['70%','95%'],
                  center: ['50%','50%'],
                  silent: true,
                  labelLine: { show: false },
                  label: { show: true, position: 'center', formatter: label, fontSize: 12, fontWeight: 750, color: usedColor },
                  data: (l > 0)
                    ? [{ value: Math.min(u, l), name: 'used' }, { value: Math.max(l - u, 0), name: 'remaining' }]
                    : [{ value: u || 1, name: 'used' }],
                  color: [usedColor, colorRest],
                }],
              }, { notMerge: true });
            }
            function resizeCharts(){
              Object.keys(chartInstances).forEach((k) => { try{ chartInstances[k].resize(); }catch(_){} });
            }

            function setTab(group, id){
              var buttons = document.querySelectorAll('[data-tab-group="'+group+'"][data-tab]');
              buttons.forEach(function(b){ b.dataset.active = (b.dataset.tab === id) ? "true" : "false"; });
              var panels = document.querySelectorAll('[data-tab-panel-group="'+group+'"][data-tab-panel]');
              panels.forEach(function(p){ p.style.display = (p.dataset.tabPanel === id) ? "block" : "none"; });
              setTimeout(resizeCharts, 0);
            }

            document.addEventListener('click', function(e){
              var el = e.target;
              while(el && el !== document.body){
                if(el.matches && el.matches('[data-tab-group][data-tab]')){
                  e.preventDefault();
                  setTab(el.dataset.tabGroup, el.dataset.tab);
                  return;
                }
                if(el.matches && el.matches('[data-copy-text-el]')){
                  e.preventDefault();
                  var id = el.getAttribute('data-copy-text-el');
                  var node = id ? document.getElementById(id) : null;
                  if(!node) return;
                  navigator.clipboard.writeText(node.value || node.textContent || '');
                  flash('已复制到剪贴板');
                  return;
                }
                el = el.parentElement;
              }
            });

            function renderConnectTemplates(mcpUrl){
              const cursor = {
                mcpServers: {
                  "time-server": {
                    url: mcpUrl,
                    headers: { Authorization: "Bearer YOUR_API_KEY" }
                  }
                }
              };
              const vscode = {
                mcp: {
                  servers: {
                    "time-server": {
                      url: mcpUrl,
                      headers: { Authorization: "Bearer YOUR_API_KEY" }
                    }
                  }
                }
              };
              const generic = {
                mcp_url: mcpUrl,
                auth: { type: "bearer", header: "Authorization: Bearer YOUR_API_KEY" }
              };
              const el1 = document.getElementById('tplCursor');
              const el2 = document.getElementById('tplVsCode');
              const el3 = document.getElementById('tplGeneric');
              if(el1) el1.textContent = JSON.stringify(cursor, null, 2);
              if(el2) el2.textContent = JSON.stringify(vscode, null, 2);
              if(el3) el3.textContent = JSON.stringify(generic, null, 2);
            }

            function renderApiSamples(mcpUrl, healthUrl){
              const elHealth = document.getElementById('curlHealth');
              const elInit = document.getElementById('curlInit');
              const elTool = document.getElementById('curlTool');
              const cont = ' \\\\';
              function bashSingleQuote(s){
                // Bash 单引号安全包裹：遇到 ' 用 '"'"' 打断再拼接
                return "'" + String(s).replaceAll("'", "'\\"'\\"'") + "'";
              }
              if(elHealth) elHealth.textContent = 'curl -sS -H "Authorization: Bearer YOUR_API_KEY" "' + healthUrl + '"';
              if(elInit){
                const initBody = JSON.stringify({jsonrpc:"2.0",id:1,method:"initialize",params:{protocolVersion:"2024-11-05",capabilities:{},clientInfo:{name:"curl",version:"1.0.0"}}}, null, 2);
                elInit.textContent = [
                  'curl -sS -X POST "' + mcpUrl + '"' + cont,
                  '  -H "Content-Type: application/json"' + cont,
                  '  -H "Authorization: Bearer YOUR_API_KEY"' + cont,
                  '  -d ' + bashSingleQuote(initBody),
                ].join('\\n');
              }
              if(elTool){
                const toolBody = JSON.stringify({jsonrpc:"2.0",id:2,method:"tools/call",params:{name:"time_now",arguments:{timezone:"Asia/Shanghai"}}}, null, 2);
                elTool.textContent = [
                  'curl -sS -X POST "' + mcpUrl + '"' + cont,
                  '  -H "Content-Type: application/json"' + cont,
                  '  -H "mcp-session-id: <SESSION_ID>"' + cont,
                  '  -H "Authorization: Bearer YOUR_API_KEY"' + cont,
                  '  -d ' + bashSingleQuote(toolBody),
                ].join('\\n');
              }
            }

            async function loadStats(){
              const r = await fetch('/dashboard/api/stats', {credentials:'same-origin'});
              if(r.status===401){ location.href='/dashboard/login'; return null; }
              const j = await r.json().catch(()=>null);
              if(!j || !j.ok){ flash((j && j.error) || '加载失败'); return null; }

              const acctEl = document.getElementById('acct');
              if(acctEl) acctEl.value = (j.account && (j.account.email || j.account.id)) || '';
              const quotaMainEl = document.getElementById('quotaMain');
              const quotaSubEl = document.getElementById('quotaSub');
              if(j.quota){
                const used = Number(j.quota.used_today||0);
                const limit = Number(j.quota.daily_limit||0);
                const pct = (limit>0) ? Math.round((used/limit)*100) : 0;
                const remaining = Math.max(limit - used, 0);
                const over = Math.max(used - limit, 0);
                if(quotaMainEl) quotaMainEl.textContent = '已用 ' + String(used) + '/' + String(limit) + '（' + String(pct) + '%）';
                if(quotaSubEl) quotaSubEl.textContent = 'UTC · tools/call · ' + (over>0 ? ('超额 ' + String(over)) : ('剩余 ' + String(remaining)));
                renderQuotaDonut('quotaChart', used, limit);
              }

              const o = j.overview || {};
              const cards = document.getElementById('overviewCards');
              if(cards){
                cards.innerHTML = ''
                  + '<article class="card card-pad"><div class="kicker">Uptime</div><div class="value">'+ esc(fmtDuration(o.uptime_s)) +'</div><div class="sub">Server running</div></article>'
                  + '<article class="card card-pad"><div class="kicker">Sessions</div><div class="value">'+ esc(String(o.transports||0)) +'</div><div class="sub">Active MCP transports</div></article>'
                  + '<article class="card card-pad"><div class="kicker">Redis</div><div class="value">'+ (o.redis ? 'On' : 'Off') +'</div><div class="sub">'+ (o.redis ? 'Shared counters enabled' : 'In-memory fallback') +'</div></article>'
                  + '<article class="card card-pad"><div class="kicker">Rate Limit</div><div class="value">'+ esc(String((o.limits && o.limits.rate_limit_per_ip_per_minute) || 0)) +'/min</div><div class="sub">Per IP on /mcp</div></article>';
              }

              const usageBadge = document.getElementById('usageBadge');
              if(usageBadge) usageBadge.textContent = (j.utc_day || 'UTC') + ' · allowed ' + String(j.usage ? j.usage.allowed : 0) + ' · denied ' + String(j.usage ? j.usage.denied : 0);
              const usageRows = document.getElementById('usageRows');
              if(usageRows){
                const rows = (j.usage && j.usage.by_key) ? j.usage.by_key : [];
                if(!rows || rows.length===0){
                  usageRows.innerHTML = '<tr><td colspan="6" class="muted">No tool calls today (UTC).</td></tr>';
                }else{
                  usageRows.innerHTML = rows.map((k, i) => {
                    return '<tr>'
                      + '<td>'+(i+1)+'</td>'
                      + '<td class="mono">'+ esc(k.prefix || '') +'</td>'
                      + '<td>'+ esc(k.name || '') +'</td>'
                      + '<td>'+ Number(k.allowed||0) +'</td>'
                      + '<td>'+ Number(k.denied||0) +'</td>'
                      + '<td class="mono">'+ esc(fmtIso(k.last_used_at)) +'</td>'
                    + '</tr>';
                  }).join('');
                }
              }

              if(!window.echarts){
                flash('ECharts 未加载（检查 /assets/echarts.min.js）');
              }else{
                const c = j.charts || {};
                if(c.daily_last_7d) renderLineChart('chartDaily7d', '近 7 天（UTC）', c.daily_last_7d.labels, c.daily_last_7d.allowed, c.daily_last_7d.denied);
                if(c.hourly_today) renderLineChart('chartHourlyToday', '今日 24 小时（UTC）', c.hourly_today.labels, c.hourly_today.allowed, c.hourly_today.denied);
                setTimeout(resizeCharts, 0);
              }

              const mcpUrl = j.connect && j.connect.mcp_url ? String(j.connect.mcp_url) : '';
              const healthUrl = j.connect && j.connect.health_url ? String(j.connect.health_url) : '';
              const mcpUrlEl = document.getElementById('mcpUrl');
              const healthUrlEl = document.getElementById('healthUrl');
              if(mcpUrlEl) mcpUrlEl.value = mcpUrl;
              if(healthUrlEl) healthUrlEl.value = healthUrl;
              renderConnectTemplates(mcpUrl);
              renderApiSamples(mcpUrl, healthUrl);

              const limitsBadge = document.getElementById('limitsBadge');
              if(limitsBadge) limitsBadge.textContent = o.redis ? 'Redis-backed' : 'In-memory';
              const limitsRows = document.getElementById('limitsRows');
              if(limitsRows){
                const lim = o.limits || {};
                limitsRows.innerHTML = ''
                  + '<tr><td>Requests / IP</td><td class="mono">'+ esc(String(lim.rate_limit_per_ip_per_minute||0)) +' per minute</td><td class="muted">Applies to GET/POST/DELETE /mcp</td></tr>'
                  + '<tr><td>SSE Conns / IP</td><td class="mono">'+ esc(String(lim.sse_max_conns_per_ip||0)) +' active</td><td class="muted">Max concurrent GET /mcp streams</td></tr>';
              }

              return j;
            }

            async function loadKeys(){
              const r = await fetch('/me/api-keys', {credentials:'same-origin'});
              if(r.status===401){ location.href='/dashboard/login'; return; }
              const j = await r.json();
              const rows = document.getElementById('rows');
              if(!rows) return;
              if(!j.keys || j.keys.length===0){ rows.innerHTML = '<tr><td colspan=\"5\" class=\"muted\">No keys yet.</td></tr>'; return; }
              rows.innerHTML = j.keys.map(k => {
                const masked = (k.prefix || 'mcp_') + '…';
                const disabled = k.revoked_at ? 'disabled' : '';
                const revoked = k.revoked_at ? '<span class=\"badge\">revoked</span>' : '<button class=\"btn btn-danger\" type=\"button\" data-revoke=\"'+ esc(k.id) +'\">Revoke</button>';
                return '<tr>'
                  + '<td>' + esc(k.name) + '</td>'
                  + '<td class=\"mono\">' + esc(masked) + '</td>'
                  + '<td class=\"mono\">' + esc(fmtIso(k.created_at)) + '</td>'
                  + '<td class=\"mono\">' + esc(fmtIso(k.last_used_at)) + '</td>'
                  + '<td style=\"display:flex;align-items:center;gap:10px\">'
                    + '<button class=\"icon-btn\" type=\"button\" data-copy=\"'+ esc(k.id) +'\" '+disabled+' title=\"Copy\">' + copyIcon + '</button>'
                    + revoked
                  + '</td>'
                + '</tr>';
              }).join('');
            }

            document.addEventListener('click', async (e) => {
              const t = e.target && e.target.closest ? e.target.closest('button') : null;
              if(!t) return;
              const idCopy = t.getAttribute('data-copy');
              const idRev = t.getAttribute('data-revoke');
              if(idCopy){
                const r = await fetch('/me/api-keys/' + encodeURIComponent(idCopy) + '/reveal', {method:'POST', credentials:'same-origin'});
                const j = await r.json().catch(()=>({ok:false}));
                if(!j.ok){ flash(pickErr(j, '复制失败')); return; }
                await navigator.clipboard.writeText(j.secret);
                t.dataset.copied = 'true';
                setTimeout(() => { try{ delete t.dataset.copied; }catch(_){} }, 900);
                flash('已复制到剪贴板');
                return;
              }
              if(idRev){
                const tr = t.closest('tr');
                const name = tr && tr.children && tr.children[0] ? tr.children[0].textContent : '';
                const prefix = tr && tr.children && tr.children[1] ? tr.children[1].textContent : '';
                const detail = []
                  .concat(name ? ['名称：' + name] : [])
                  .concat(prefix ? ['前缀：' + prefix] : [])
                  .join('\\n');
                const ok = await confirmModal({
                  title: '吊销 API Key',
                  message: '吊销后将立即失效，且不可恢复。',
                  detail: detail,
                  okText: '确认吊销',
                  cancelText: '取消',
                  danger: true,
                });
                if(!ok) return;
                const r = await fetch('/me/api-keys/' + encodeURIComponent(idRev), {method:'DELETE', credentials:'same-origin'});
                const j = await r.json().catch(()=>({ok:false}));
                if(!j.ok){ flash(pickErr(j, '吊销失败')); return; }
                flash('已吊销');
                await loadKeys();
              }
            });

            const btnCreate = document.getElementById('btnCreate');
            if(btnCreate){
              btnCreate.addEventListener('click', async () => {
                const name = await promptModal({
                  title: '创建 API Key',
                  message: '可选：填写名称，便于日后识别。',
                  placeholder: '例如：本地开发 / CI / iPhone',
                  defaultValue: '',
                  okText: '创建并复制',
                  cancelText: '取消',
                });
                if(name === null) return;
                const r = await fetch('/me/api-keys', {
                  method:'POST',
                  credentials:'same-origin',
                  headers:{'Content-Type':'application/json'},
                  body: JSON.stringify({ name: String(name || '').trim() })
                });
                const j = await r.json().catch(()=>({ok:false}));
                if(!j.ok){ flash(pickErr(j, '创建失败')); return; }
                await navigator.clipboard.writeText(j.secret);
                flash('Key 已创建并已复制（仅创建时返回一次）');
                await loadKeys();
              });
            }

            (async function(){
              await loadStats();
              await loadKeys();
            })().catch(()=>flash('加载失败'));

            // 窗口缩放时，确保折线图自适应（避免隐藏 tab 重新显示后尺寸为 0）
            let resizeTimer = null;
            window.addEventListener('resize', () => {
              if(resizeTimer) clearTimeout(resizeTimer);
              resizeTimer = setTimeout(resizeCharts, 120);
            });
          })();
        `,
      }),
    );
  }
}
