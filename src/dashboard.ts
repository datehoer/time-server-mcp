import type { Express, Request, Response } from "express";
import { randomUUID } from "node:crypto";
import type { Db } from "./db.js";
import type { RedisClientLike } from "./redisLike.js";
import { getGlobalDailyLimitCached } from "./quota.js";
import { hashPassword, verifyPassword } from "./security.js";
import { iconCopySvg, layoutHtml } from "./ui.js";

async function requireDashboardSession(req: Request, res: Response, deps: { redis: RedisClientLike; cookieName: string }) {
  const sid = (req.cookies?.[deps.cookieName] as string | undefined) ?? "";
  if (!sid) {
    res.redirect(302, "/dashboard/login");
    return null;
  }
  const accountId = await deps.redis.get(`sess:${sid}`);
  if (!accountId) {
    res.redirect(302, "/dashboard/login");
    return null;
  }
  return { accountId, sid };
}

function getOrigin(req: Request) {
  const proto = (req.headers["x-forwarded-proto"] as string | undefined)?.split(",")[0]?.trim() || req.protocol || "http";
  const host = (req.headers["x-forwarded-host"] as string | undefined)?.split(",")[0]?.trim() || req.get("host") || "127.0.0.1";
  return `${proto}://${host}`;
}

function utcDayRange(d = new Date()) {
  const dayStart = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate(), 0, 0, 0));
  const dayEnd = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate() + 1, 0, 0, 0));
  const utcDay = `${dayStart.getUTCFullYear()}-${String(dayStart.getUTCMonth() + 1).padStart(2, "0")}-${String(dayStart.getUTCDate()).padStart(2, "0")}`;
  return { dayStartIso: dayStart.toISOString(), dayEndIso: dayEnd.toISOString(), utcDay };
}

export function registerDashboardRoutes(
  app: Express,
  deps: {
    db: Db;
    redis: RedisClientLike;
    cookieName: string;
    ttlSeconds: number;
    cookieSecure: boolean;
    defaultFreeDailyRequestLimit: number;
    policyCacheSeconds: number;
    getServerStats: () => {
      uptime_s: number;
      transports: number;
      redis: boolean;
      db: boolean;
      auth_mode: string;
      limits: { rate_limit_per_ip_per_minute: number; sse_max_conns_per_ip: number };
    };
  },
) {
  const { db, redis, cookieName, ttlSeconds, cookieSecure } = deps;
  // Dashboard 页面复用 Admin 的 UI 基础样式与布局（见 src/ui.ts）。

  function setSession(res: Response, sid: string) {
    res.cookie(cookieName, sid, {
      httpOnly: true,
      sameSite: "lax",
      secure: cookieSecure,
      maxAge: ttlSeconds * 1000,
      path: "/",
    });
  }

  app.get("/dashboard/login", (_req, res) => {
    res.status(200).type("html").send(
      layoutHtml({
        title: "Dashboard Login",
        body: `
<div class="shell">
  <div class="auth">
    <div class="brand" style="justify-content:center;margin-bottom:14px">
      <div class="logo">MCP</div>
      <div>
        <div class="brand-title">Time Server</div>
        <div class="muted" style="font-size:12px">Dashboard</div>
      </div>
    </div>

    <h1>登录</h1>
    <p class="hint">用户后台：管理 API Keys 与配额。</p>

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
        <button class="btn btn-primary" type="submit" style="height:40px;border-radius:12px">登录</button>
        <div class="muted" style="font-size:12px">没有账号？<a href="/dashboard/register">去注册</a></div>
      </form>
    </div>
  </div>
</div>
        `,
      }),
    );
  });

  app.get("/dashboard/register", (_req, res) => {
    res.status(200).type("html").send(
      layoutHtml({
        title: "Dashboard Register",
        body: `
<div class="shell">
  <div class="auth">
    <div class="brand" style="justify-content:center;margin-bottom:14px">
      <div class="logo">MCP</div>
      <div>
        <div class="brand-title">Time Server</div>
        <div class="muted" style="font-size:12px">Dashboard</div>
      </div>
    </div>

    <h1>注册</h1>
    <p class="hint">注册账号后可自助创建 API Key。</p>

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
        <button class="btn btn-primary" type="submit" style="height:40px;border-radius:12px">注册并登录</button>
        <div class="muted" style="font-size:12px">已有账号？<a href="/dashboard/login">去登录</a></div>
      </form>
    </div>
  </div>
</div>
        `,
      }),
    );
  });

  app.post("/dashboard/register", async (req: Request, res: Response) => {
    const email = String(req.body?.email ?? "").toLowerCase();
    const password = String(req.body?.password ?? "");
    if (!email.includes("@") || password.length < 8) return res.status(400).send("Invalid input.");

    const id = randomUUID();
    const passwordHash = await hashPassword(password);
    try {
      await db.query("INSERT INTO accounts (id, email, password_hash) VALUES ($1,$2,$3)", [id, email, passwordHash]);
    } catch {
      return res
        .status(409)
        .type("html")
        .send(
          layoutHtml({
            title: "Register failed",
            body: `<div class="shell"><div class="container" style="padding:28px 16px"><div class="card card-pad">Email 已存在。<a href="/dashboard/login">去登录</a></div></div></div>`,
          }),
        );
    }

    const sid = randomUUID();
    await redis.set(`sess:${sid}`, id, { EX: ttlSeconds });
    setSession(res, sid);
    res.redirect(302, "/dashboard");
  });

  app.post("/dashboard/login", async (req: Request, res: Response) => {
    const email = String(req.body?.email ?? "").toLowerCase();
    const password = String(req.body?.password ?? "");
    const r = await db.query<{ id: string; password_hash: string; disabled_at: string | null }>(
      "SELECT id, password_hash, disabled_at FROM accounts WHERE email=$1 LIMIT 1",
      [email],
    );
    const row = r.rows[0];
    if (!row || row.disabled_at) return res.status(401).send("Invalid credentials.");
    const ok = await verifyPassword(password, row.password_hash);
    if (!ok) return res.status(401).send("Invalid credentials.");

    const sid = randomUUID();
    await redis.set(`sess:${sid}`, row.id, { EX: ttlSeconds });
    setSession(res, sid);
    res.redirect(302, "/dashboard");
  });

  app.post("/dashboard/logout", async (req: Request, res: Response) => {
    const sid = (req.cookies?.[cookieName] as string | undefined) ?? "";
    if (sid) await redis.del(`sess:${sid}`);
    res.clearCookie(cookieName, { path: "/" });
    res.redirect(302, "/dashboard/login");
  });

  // Dashboard：按当前登录账号汇总的状态/配额/Usage（迁移自 /admin，但不暴露其他账号数据）
  app.get("/dashboard/api/stats", async (req: Request, res: Response) => {
    const s = await requireDashboardSession(req, res, { redis, cookieName });
    if (!s) return;

    const me = await db.query<{ email: string; disabled_at: string | null }>("SELECT email, disabled_at FROM accounts WHERE id=$1 LIMIT 1", [
      s.accountId,
    ]);
    const meRow = me.rows[0];
    if (!meRow || meRow.disabled_at) return res.status(401).json({ ok: false, error: "Account disabled" });

    const { dayStartIso, dayEndIso, utcDay } = utcDayRange(new Date());

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

    return res.status(200).json({
      ok: true,
      utc_day: utcDay,
      account: { id: s.accountId, email: meRow.email ?? "" },
      overview: deps.getServerStats(),
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
      connect: {
        mcp_url: mcpUrl,
        health_url: healthUrl,
        auth_header_hint: "Authorization: Bearer <YOUR_API_KEY>",
      },
    });
  });

  app.get("/dashboard", async (req: Request, res: Response) => {
    const s = await requireDashboardSession(req, res, { redis, cookieName });
    if (!s) return;
    res.status(200).type("html").send(
      layoutHtml({
        title: "Dashboard",
        body: `
<div class="shell">
  <header class="topbar">
    <div class="container">
      <div class="topbar-inner">
        <div class="brand">
          <div class="logo">MCP</div>
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
                <div class="field">
                  <div class="kicker" style="width:74px;flex:0 0 auto">Quota</div>
                  <input id="quota" readonly value="loading…" class="mono" />
                </div>
                <div class="muted" id="status" style="font-size:12px"></div>
              </div>
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

            <div class="card-pad" style="padding-top:0;display:grid;gap:12px">
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
            const copyIcon = ${JSON.stringify(iconCopySvg())};

            function setTab(group, id){
              var buttons = document.querySelectorAll('[data-tab-group="'+group+'"][data-tab]');
              buttons.forEach(function(b){ b.dataset.active = (b.dataset.tab === id) ? "true" : "false"; });
              var panels = document.querySelectorAll('[data-tab-panel-group="'+group+'"][data-tab-panel]');
              panels.forEach(function(p){ p.style.display = (p.dataset.tabPanel === id) ? "block" : "none"; });
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
              if(elHealth) elHealth.textContent = 'curl -sS -H "Authorization: Bearer YOUR_API_KEY" "' + healthUrl + '"';
              if(elInit) elInit.textContent =
                'curl -sS -X POST "' + mcpUrl + '" \\\\\\n' +
                '  -H "Content-Type: application/json" \\\\\\n' +
                '  -H "Authorization: Bearer YOUR_API_KEY" \\\\\\n' +
                '  -d ' + JSON.stringify(JSON.stringify({jsonrpc:"2.0",id:1,method:"initialize",params:{protocolVersion:"2024-11-05",capabilities:{},clientInfo:{name:"curl",version:"1.0.0"}}}, null, 2));
              if(elTool) elTool.textContent =
                'curl -sS -X POST "' + mcpUrl + '" \\\\\\n' +
                '  -H "Content-Type: application/json" \\\\\\n' +
                '  -H "mcp-session-id: <SESSION_ID>" \\\\\\n' +
                '  -H "Authorization: Bearer YOUR_API_KEY" \\\\\\n' +
                '  -d ' + JSON.stringify(JSON.stringify({jsonrpc:"2.0",id:2,method:"tools/call",params:{name:"time_now",arguments:{timezone:"Asia/Shanghai"}}}, null, 2));
            }

            async function loadStats(){
              const r = await fetch('/dashboard/api/stats', {credentials:'same-origin'});
              if(r.status===401){ location.href='/dashboard/login'; return null; }
              const j = await r.json().catch(()=>null);
              if(!j || !j.ok){ flash((j && j.error) || '加载失败'); return null; }

              const acctEl = document.getElementById('acct');
              if(acctEl) acctEl.value = (j.account && (j.account.email || j.account.id)) || '';
              const quotaEl = document.getElementById('quota');
              if(quotaEl && j.quota) quotaEl.value = 'UTC · tools/call · ' + String(j.quota.used_today) + '/' + String(j.quota.daily_limit);

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
                if(!j.ok){ flash(j.error || '复制失败'); return; }
                await navigator.clipboard.writeText(j.secret);
                t.dataset.copied = 'true';
                setTimeout(() => { try{ delete t.dataset.copied; }catch(_){} }, 900);
                flash('已复制到剪贴板');
                return;
              }
              if(idRev){
                if(!confirm('确定吊销该 Key？吊销后将立即失效。')) return;
                const r = await fetch('/me/api-keys/' + encodeURIComponent(idRev), {method:'DELETE', credentials:'same-origin'});
                const j = await r.json().catch(()=>({ok:false}));
                if(!j.ok){ flash(j.error || '吊销失败'); return; }
                flash('已吊销');
                await loadKeys();
              }
            });

            const btnCreate = document.getElementById('btnCreate');
            if(btnCreate){
              btnCreate.addEventListener('click', async () => {
                const name = prompt('Key 名称（可选）','');
                const r = await fetch('/me/api-keys', {
                  method:'POST',
                  credentials:'same-origin',
                  headers:{'Content-Type':'application/json'},
                  body: JSON.stringify({ name: name || '' })
                });
                const j = await r.json().catch(()=>({ok:false}));
                if(!j.ok){ flash(j.error || '创建失败'); return; }
                await navigator.clipboard.writeText(j.secret);
                flash('Key 已创建并已复制（仅创建时返回一次）');
                await loadKeys();
              });
            }

            (async function(){
              await loadStats();
              await loadKeys();
            })().catch(()=>flash('加载失败'));
          })();
        `,
      }),
    );
  });
}
