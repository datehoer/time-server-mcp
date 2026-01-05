import type { Request, Response } from "express";
import type { Db } from "./db.js";
import type { RedisClientLike } from "./redisLike.js";
import { parseCookies, signCookie, verifySignedCookie } from "./httpUtil.js";
import { escapeHtml, layoutHtml } from "./ui.js";
import { requireCaptcha } from "./captcha.js";

export type AdminConfig = {
  username: string;
  password: string;
  cookieSecret: string;
  cookieSecure: boolean;
  sessionTtlSeconds: number;
  captchaIgnoreCase: boolean;
};

export type AdminDeps = {
  db: Db | null;
  redis: RedisClientLike | null;
  getStats: () => Record<string, unknown>;
};

type SessionPayload = { u: string; exp: number };

function isAjax(req: Request) {
  const xrw = (req.get("x-requested-with") ?? "").toLowerCase();
  const accept = (req.get("accept") ?? "").toLowerCase();
  return xrw === "fetch" || accept.includes("application/json");
}

function adminLoginScripts() {
  // 纯原生 JS：拦截表单提交，用 fetch 提交，失败时 toast 提示并刷新验证码图。
  return `
(function(){
  var form = document.querySelector('form.form');
  if(!form) return;

  var wrap = document.createElement('div');
  wrap.className = 'toast-wrap';
  wrap.innerHTML = '<div class="toast" id="toast"><div class="toast-title">登录失败</div><div class="toast-msg" id="toast-msg"></div><div class="toast-actions"><button class="btn btn-primary" type="button" id="toast-ok">知道了</button></div></div>';
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
          location.href = data.redirect || '/admin';
          return;
        }

        var msg = (data && data.error) ? data.error : ('请求失败（' + r.status + '）');
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

function setCookie(
  res: Response,
  name: string,
  value: string,
  opts: {
    maxAgeSeconds?: number;
    httpOnly?: boolean;
    secure?: boolean;
    sameSite?: "Lax" | "Strict";
    path?: string;
  } = {},
) {
  const parts = [`${name}=${encodeURIComponent(value)}`];
  parts.push(`Path=${opts.path ?? "/"}`);
  if (opts.httpOnly ?? true) parts.push("HttpOnly");
  if (opts.secure) parts.push("Secure");
  parts.push(`SameSite=${opts.sameSite ?? "Lax"}`);
  if (typeof opts.maxAgeSeconds === "number") parts.push(`Max-Age=${Math.floor(opts.maxAgeSeconds)}`);
  res.append("Set-Cookie", parts.join("; "));
}

function clearCookie(res: Response, name: string, path = "/") {
  res.append("Set-Cookie", `${name}=; Path=${path}; Max-Age=0`);
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

function fmtIso(s: unknown): string {
  if (s == null || s === "") return "Never";

  // DB/pg 可能返回 Date（例如 timestamptz），此处统一归一化为 ISO 文本，避免下游 split 崩溃。
  if (s instanceof Date) {
    const iso = s.toISOString(); // e.g. 2026-01-04T08:19:49.123Z
    return iso.slice(0, 19).replace("T", " ");
  }

  if (typeof s === "string") {
    return s.length >= 19 ? s.slice(0, 19).replace("T", " ") : s;
  }

  // 兜底：尽量转成字符串，保证 renderWhenUtc 可安全 split。
  return String(s);
}

// Admin：UTC 时间两行展示（保持与服务端统计/日志口径一致）
function renderWhenUtc(s: unknown) {
  const v = fmtIso(s);
  if (v === "Never") {
    return `<div class="when"><div class="when-primary muted">Never</div><div class="when-sub muted">—</div></div>`;
  }
  const parts = v.split(" ");
  const date = parts[0] ?? v;
  const time = parts[1] ?? "";
  return `<div class="when"><div class="when-primary mono">${escapeHtml(date)}</div><div class="when-sub mono">${escapeHtml(time)} UTC</div></div>`;
}

export function registerAdminRoutes(app: any, cfg: AdminConfig, deps: AdminDeps) {
  app.get("/admin/login", (_req: Request, res: Response) => {
    res
      .status(200)
      .type("html")
      .send(
        layoutHtml({
          title: "Admin Login",
          scripts: adminLoginScripts(),
          body: `
<div class="shell">
  <div class="auth">
    <div class="brand" style="justify-content:center;margin-bottom:14px">
      <div class="logo"><img class="logo-img" src="/assets/logo.png" alt="MCP" width="28" height="28" /></div>
      <div>
        <div class="brand-title">Time Server</div>
        <div class="muted" style="font-size:12px">Admin</div>
      </div>
    </div>

    <h1>登录</h1>

    <div class="card card-pad" style="box-shadow:var(--shadow)">
      <form class="form" method="post" action="/admin/login">
        <div>
          <label>用户名</label>
          <input class="input" name="username" autocomplete="username" required />
        </div>
        <div>
          <label>密码</label>
          <input class="input" type="password" name="password" autocomplete="current-password" required />
        </div>
        <div>
          <label>验证码（点击图片刷新）</label>
          <div style="display:flex;gap:10px;align-items:center">
            <input class="input" name="captcha" autocomplete="off" required />
            <img
              src="/captcha/svg?scene=admin_login"
              alt="captcha"
              style="height:40px;cursor:pointer;border-radius:12px;border:1px solid hsl(var(--input));background:hsl(var(--popover))"
              onclick="this.src='/captcha/svg?scene=admin_login&t='+Date.now()"
            />
          </div>
        </div>
        <button class="btn btn-primary" type="submit" style="height:40px;border-radius:12px">登录</button>
      </form>
    </div>
  </div>
</div>
          `,
        }),
      );
  });

  app.post("/admin/login", async (req: Request, res: Response) => {
    const ajax = isAjax(req);
    if (!deps.redis) {
      if (ajax) return res.status(500).json({ ok: false, error: "Redis disabled" });
      res.status(500).send("Redis disabled.");
      return;
    }

    // Admin 登录必须验证码：一次性校验通过即删除。
    if (
      !(await requireCaptcha(req, res, {
        redis: deps.redis,
        scene: "admin_login",
        value: req.body?.captcha,
        ignoreCase: cfg.captchaIgnoreCase,
        format: ajax ? "json" : "text",
      }))
    )
      return;

    const username = String(req.body?.username ?? "");
    const password = String(req.body?.password ?? "");

    if (username !== cfg.username || password !== cfg.password) {
      if (ajax) return res.status(401).json({ ok: false, error: "Invalid credentials" });
      res.status(401).send("Invalid credentials.");
      return;
    }

    const exp = Date.now() + cfg.sessionTtlSeconds * 1000;
    const session = signCookie(cfg.cookieSecret, { u: cfg.username, exp } satisfies SessionPayload);
    setCookie(res, "admin_session", session, {
      maxAgeSeconds: cfg.sessionTtlSeconds,
      httpOnly: true,
      secure: cfg.cookieSecure,
      sameSite: "Lax",
      path: "/admin",
    });
    if (ajax) return res.status(200).json({ ok: true, redirect: "/admin" });
    res.redirect(302, "/admin");
  });

  app.post("/admin/logout", (_req: Request, res: Response) => {
    // 修复：登录时 cookie Path=/admin，登出也必须按相同 path 清理；并兼容历史 path=/
    clearCookie(res, "admin_session", "/admin");
    clearCookie(res, "admin_session", "/");
    res.redirect(302, "/admin/login");
  });

  // 管理员：账号禁用（最小可用）。禁用后：无法登录 Dashboard，且 API Key 会被判定为 Unauthorized。
  app.post("/admin/accounts/:id/disable", async (req: Request, res: Response) => {
    const s = requireSession(req, res, cfg);
    if (!s) return;
    if (!deps.db) return res.status(500).send("DB disabled");
    const id = String(req.params.id ?? "");
    if (!id) return res.status(400).send("Invalid id");

    await deps.db.query("UPDATE accounts SET disabled_at=now() WHERE id=$1 AND disabled_at IS NULL", [id]);
    // 立即生效：设置 Redis 标记，避免 5 分钟的 API Key 缓存窗口。
    if (deps.redis) await deps.redis.set(`acctdis:${id}`, "1");
    res.redirect(302, "/admin");
  });

  // 管理员：账号启用（最小可用）
  app.post("/admin/accounts/:id/enable", async (req: Request, res: Response) => {
    const s = requireSession(req, res, cfg);
    if (!s) return;
    if (!deps.db) return res.status(500).send("DB disabled");
    const id = String(req.params.id ?? "");
    if (!id) return res.status(400).send("Invalid id");

    await deps.db.query("UPDATE accounts SET disabled_at=NULL WHERE id=$1", [id]);
    if (deps.redis) await deps.redis.del(`acctdis:${id}`);
    res.redirect(302, "/admin");
  });

  // 管理员：吊销 API Key（最小可用）
  app.post("/admin/api-keys/:id/revoke", async (req: Request, res: Response) => {
    const s = requireSession(req, res, cfg);
    if (!s) return;
    if (!deps.db) return res.status(500).send("DB disabled");
    const id = String(req.params.id ?? "");
    if (!id) return res.status(400).send("Invalid id");

    const u = await deps.db.query<{ key_hash: string }>(
      "UPDATE api_keys SET revoked_at=now() WHERE id=$1 AND revoked_at IS NULL RETURNING key_hash",
      [id],
    );
    if (u.rows.length === 0) return res.status(404).send("Not found");

    // 立即失效：清除 keyHash 缓存 + 写入撤销标记（覆盖 requireApiKey 的 5 分钟缓存）
    if (deps.redis) {
      await deps.redis.del(`ak:${u.rows[0]!.key_hash}`);
      await deps.redis.set(`akrev:${id}`, "1", { EX: 600 });
    }
    res.redirect(302, "/admin");
  });

  app.get("/admin", async (req: Request, res: Response) => {
    const s = requireSession(req, res, cfg);
    if (!s) return;

    const stats = deps.getStats();
    const uptimeSeconds = Number((stats as any)?.uptime_s ?? 0);
    const transportsCount = Number((stats as any)?.transports ?? 0);
    const redisEnabled = Boolean((stats as any)?.redis);
    const dbEnabled = Boolean((stats as any)?.db);
    const limits = (stats as any)?.limits as { rate_limit_per_ip_per_minute?: number; sse_max_conns_per_ip?: number } | undefined;
    const rateLimit = Number(limits?.rate_limit_per_ip_per_minute ?? 0);
    const sseMax = Number(limits?.sse_max_conns_per_ip ?? 0);

    const db = deps.db;

    // 账号/Key 列表（最小可用：只做展示与禁用/吊销）
    let accounts: Array<{ id: string; email: string; created_at: string | Date; disabled_at: string | null; active_keys: number }> = [];
    let keys: Array<{
      id: string;
      prefix: string;
      name: string;
      created_at: string | Date;
      last_used_at: string | Date | null;
      revoked_at: string | null;
      account_email: string;
      account_id: string;
    }> = [];

    if (db) {
      const a = await db.query<{ id: string; email: string; created_at: string | Date; disabled_at: string | null; active_keys: string }>(
        `
	SELECT
	  a.id,
	  a.email,
	  a.created_at,
  a.disabled_at,
  (SELECT COUNT(*)::text FROM api_keys k WHERE k.account_id=a.id AND k.revoked_at IS NULL) AS active_keys
FROM accounts a
ORDER BY a.created_at DESC
LIMIT 50
`,
      );
      accounts = a.rows.map((r) => ({ ...r, active_keys: Number(r.active_keys || "0") }));

      const k = await db.query<{
        id: string;
        prefix: string;
        name: string;
        created_at: string | Date;
        last_used_at: string | Date | null;
        revoked_at: string | null;
        account_email: string;
        account_id: string;
      }>(
        `
SELECT k.id, k.prefix, k.name, k.created_at, k.last_used_at, k.revoked_at, a.email AS account_email, a.id AS account_id
FROM api_keys k
JOIN accounts a ON a.id = k.account_id
ORDER BY k.created_at DESC
LIMIT 50
`,
      );
      keys = k.rows;
    }

    res.status(200).type("html").send(
      layoutHtml({
        title: "Admin",
        body: `
<div class="shell">
  <header class="topbar">
    <div class="container">
      <div class="topbar-inner">
        <div class="brand">
          <div class="logo"><img class="logo-img" src="/assets/logo.png" alt="MCP" width="28" height="28" /></div>
          <div class="brand-title">Time Server</div>
          <div class="workspace" title="Workspace">
            <span>Admin</span>
            <span aria-hidden="true">▾</span>
          </div>
        </div>

        <nav class="nav" aria-label="Primary">
          <a href="/admin" data-active="true">Admin</a>
        </nav>

        <div class="actions">
          <a class="link" href="/admin/api/stats">Stats</a>
          <form method="post" action="/admin/logout" style="margin:0">
            <button class="btn btn-primary" type="submit">Logout</button>
          </form>
        </div>
      </div>
    </div>
  </header>

  <main>
    <div class="container">
      <div class="stack">
        <div class="grid grid-4">
          <article class="card card-pad">
            <div class="kicker">Uptime</div>
            <div class="value">${escapeHtml(formatDuration(uptimeSeconds))}</div>
            <div class="sub">Server running</div>
          </article>
          <article class="card card-pad">
            <div class="kicker">Sessions</div>
            <div class="value">${Number.isFinite(transportsCount) ? transportsCount : 0}</div>
            <div class="sub">Active MCP transports</div>
          </article>
          <article class="card card-pad">
            <div class="kicker">Redis</div>
            <div class="value">${redisEnabled ? "On" : "Off"}</div>
            <div class="sub">${redisEnabled ? "Shared counters enabled" : "In-memory fallback"}</div>
          </article>
          <article class="card card-pad">
            <div class="kicker">Rate Limit</div>
            <div class="value">${rateLimit ? `${rateLimit}/min` : "—"}</div>
            <div class="sub">Per IP on /mcp</div>
          </article>
          <article class="card card-pad">
            <div class="kicker">Database</div>
            <div class="value">${dbEnabled ? "On" : "Off"}</div>
            <div class="sub">${dbEnabled ? "Account & Key mgmt enabled" : "DB auth disabled"}</div>
          </article>
          <article class="card card-pad">
            <div class="kicker">SSE Limit</div>
            <div class="value">${sseMax ? `${sseMax}` : "—"}</div>
            <div class="sub">Per IP</div>
          </article>
        </div>

        <div class="card">
          <div class="card-pad">
            <div class="section-head">
              <div>
                <h2 class="section-title">Usage Charts (UTC)</h2>
                <div class="section-desc">全局 <span class="mono">tools/call</span> 趋势（allowed/denied）。</div>
              </div>
              <span class="badge" id="chartsBadge">loading…</span>
            </div>
            <div class="muted" id="chartsStatus" style="font-size:12px;margin-top:8px"></div>
          </div>
          <div class="card-pad" style="padding-top:0">
            <div class="chart" id="adminChartHourly"></div>
            <div style="height:12px"></div>
            <div class="chart" id="adminChartDaily7d"></div>
          </div>
        </div>

        <div class="card">
          <div class="card-pad">
            <div class="section-head">
              <div>
                <h2 class="section-title">Accounts</h2>
                <div class="section-desc">最小可用：禁用/启用账号（禁用后无法登录与调用）。</div>
              </div>
              <span class="badge ${db ? "badge-ok" : ""}">${db ? "DB On" : "DB Off"}</span>
            </div>
          </div>
          <table class="table" aria-label="Accounts table">
            <thead>
              <tr>
                <th>Email</th>
                <th>Created</th>
                <th>Status</th>
                <th>Active Keys</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              ${
                db
                  ? accounts
                      .map((a) => {
                        const status = a.disabled_at
                          ? `<span class="badge badge-muted"><span class="dot dot-warn" aria-hidden="true"></span>disabled</span>`
                          : `<span class="badge badge-ok"><span class="dot dot-ok" aria-hidden="true"></span>active</span>`;
                        const action = a.disabled_at
                          ? `<form method="post" action="/admin/accounts/${escapeHtml(a.id)}/enable" style="margin:0"><button class="btn btn-sm" type="submit">Enable</button></form>`
                          : `<form method="post" action="/admin/accounts/${escapeHtml(a.id)}/disable" style="margin:0"><button class="btn btn-sm btn-danger" type="submit" onclick="return confirm('确定禁用该账号？')">Disable</button></form>`;
                        return `<tr>
                          <td class="mono">${escapeHtml(a.email)}</td>
                          <td>${renderWhenUtc(a.created_at)}</td>
                          <td>${status}</td>
                          <td class="mono">${a.active_keys}</td>
                          <td><div class="row-actions">${action}</div></td>
                        </tr>`;
                      })
                      .join("")
                  : `<tr><td colspan="5" class="muted">DB 未启用，无法管理账号。</td></tr>`
              }
            </tbody>
          </table>
        </div>

        <div class="card">
          <div class="card-pad">
            <div class="section-head">
              <div>
                <h2 class="section-title">API Keys</h2>
                <div class="section-desc">最小可用：吊销 Key（立即失效）。</div>
              </div>
            </div>
          </div>
          <table class="table" aria-label="Admin keys table">
            <thead>
              <tr>
                <th>Prefix</th>
                <th>Name</th>
                <th>Account</th>
                <th>Created</th>
                <th>Last Used</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              ${
                db
                  ? keys
                      .map((k) => {
                        const status = k.revoked_at
                          ? `<span class="badge badge-danger"><span class="dot dot-danger" aria-hidden="true"></span>revoked</span>`
                          : `<span class="badge badge-ok"><span class="dot dot-ok" aria-hidden="true"></span>active</span>`;
                        const action = k.revoked_at
                          ? ""
                          : `<form method="post" action="/admin/api-keys/${escapeHtml(k.id)}/revoke" style="margin:0"><button class="btn btn-sm btn-danger" type="submit" onclick="return confirm('确定吊销该 Key？吊销后将立即失效。')">Revoke</button></form>`;
                        return `<tr>
                          <td class="mono">${escapeHtml(k.prefix)}</td>
                          <td>${escapeHtml(k.name)}</td>
                          <td class="mono">${escapeHtml(k.account_email)}</td>
                          <td>${renderWhenUtc(k.created_at)}</td>
                          <td>${renderWhenUtc(k.last_used_at)}</td>
                          <td>${status}</td>
                          <td><div class="row-actions">${action}</div></td>
                        </tr>`;
                      })
                      .join("")
                  : `<tr><td colspan="7" class="muted">DB 未启用，无法管理 API Keys。</td></tr>`
              }
            </tbody>
          </table>
        </div>

        <div class="card">
          <div class="card-pad">
            <div class="section-head">
              <div>
                <h2 class="section-title">Debug</h2>
                <div class="section-desc">服务状态原始数据（只读）。</div>
              </div>
            </div>
            <pre class="mono" style="margin:0">${escapeHtml(JSON.stringify(stats, null, 2))}</pre>
          </div>
        </div>
      </div>
    </div>
  </main>
  <script src="/assets/echarts.min.js"></script>
</div>
        `,
        scripts: `
          (function(){
            const badge = document.getElementById('chartsBadge');
            const status = document.getElementById('chartsStatus');
            function setStatus(msg){
              if(status) status.textContent = msg || '';
            }
            function cssHslVar(name, fallback){
              try{
                const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
                return v ? ('hsl(' + v + ')') : fallback;
              }catch(_){ return fallback; }
            }
            function renderLine(elId, title, labels, allowed, denied){
              if(!window.echarts) return;
              const el = document.getElementById(elId);
              if(!el) return;
              const chart = window.echarts.init(el);
              const colorOk = cssHslVar('--primary', 'hsl(142 71% 30%)');
              const colorBad = 'hsl(0 72% 35%)';
              chart.setOption({
                animation:false,
                title:{ text:title||'', left:0, top:0, textStyle:{ fontSize:12, fontWeight:650 } },
                tooltip:{ trigger:'axis' },
                legend:{ top:26, right:0, data:['allowed','denied'], itemGap:14, selectedMode:false },
                grid:{ left:44, right:16, top:64, bottom:40, containLabel:true },
                xAxis:{ type:'category', data: labels || [], axisLabel:{ hideOverlap:true, margin:12 } },
                yAxis:{ type:'value', axisLabel:{ margin:12 } },
                color:[colorOk, colorBad],
                series:[
                  {
                    name:'allowed',
                    type:'line',
                    data: allowed || [],
                    smooth:true,
                    showSymbol:false,
                    lineStyle:{ width:2 },
                    emphasis:{ disabled:true },
                    select:{ disabled:true },
                  },
                  {
                    name:'denied',
                    type:'line',
                    data: denied || [],
                    smooth:true,
                    showSymbol:false,
                    lineStyle:{ width:2 },
                    emphasis:{ disabled:true },
                    select:{ disabled:true },
                  },
                ],
              }, { notMerge:true });
              return chart;
            }

            if(!window.echarts){
              if(badge) badge.textContent = 'ECharts missing';
              setStatus('ECharts 未加载（检查 /assets/echarts.min.js）');
              return;
            }

            let charts = [];
            function resizeAll(){
              charts.forEach((c)=>{ try{ c.resize(); }catch(_){} });
            }
            let resizeTimer = null;
            window.addEventListener('resize', () => {
              if(resizeTimer) clearTimeout(resizeTimer);
              resizeTimer = setTimeout(resizeAll, 120);
            });

            (async function(){
              const r = await fetch('/admin/api/stats', { credentials:'same-origin' });
              if(r.status===401){ location.href='/admin/login'; return; }
              const j = await r.json().catch(()=>null);
              const dbs = j && j.db_stats ? j.db_stats : null;
              if(!dbs){
                if(badge) badge.textContent = 'DB Off';
                setStatus('DB 未启用或统计快照不可用，无法生成折线图。');
                return;
              }
              if(badge) badge.textContent = (dbs.utc_day || 'UTC') + ' · global';
              setStatus('');

              const h = dbs.tool_calls_hourly_today;
              const d = dbs.tool_calls_daily_last_7d;
              if(h) charts.push(renderLine('adminChartHourly', '今日 24 小时（UTC）', h.labels, h.allowed, h.denied));
              if(d) charts.push(renderLine('adminChartDaily7d', '近 7 天（UTC）', d.labels, d.allowed, d.denied));
              charts = charts.filter(Boolean);
              setTimeout(resizeAll, 0);
            })().catch(()=>setStatus('加载折线图失败'));
          })();
        `,
      }),
    );
  });

  app.get("/admin/api/stats", (req: Request, res: Response) => {
    const s = requireSession(req, res, cfg);
    if (!s) return;
    res.status(200).json(deps.getStats());
  });
}

function formatDuration(uptimeSeconds: number) {
  const sec = Math.max(0, Math.floor(Number(uptimeSeconds) || 0));
  const days = Math.floor(sec / 86400);
  const hours = Math.floor((sec % 86400) / 3600);
  const minutes = Math.floor((sec % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  return `${minutes}m`;
}
