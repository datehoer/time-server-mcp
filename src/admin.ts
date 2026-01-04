import type { Request, Response } from "express";
import { createHash, randomInt } from "node:crypto";
import { parseCookies, signCookie, verifySignedCookie } from "./httpUtil.js";
import { escapeAttr, escapeHtml, iconCopySvg, layoutHtml } from "./ui.js";

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

function getOrigin(req: Request) {
  const proto = (req.headers["x-forwarded-proto"] as string | undefined)?.split(",")[0]?.trim() || req.protocol || "http";
  const host = (req.headers["x-forwarded-host"] as string | undefined)?.split(",")[0]?.trim() || req.get("host") || "127.0.0.1";
  return `${proto}://${host}`;
}

function tokenId(token: string) {
  return createHash("sha256").update(token).digest("hex").slice(0, 12);
}

function maskToken(token: string) {
  const t = String(token || "");
  if (t.length <= 8) return "••••••••";
  return `${t.slice(0, 4)}…${t.slice(-4)}`;
}

function formatIsoDay(iso: unknown) {
  const s = typeof iso === "string" ? iso : "";
  if (!s) return "Never";
  return s.length >= 10 ? s.slice(0, 10) : s;
}

export function registerAdminRoutes(app: any, cfg: AdminConfig, getStats: () => Record<string, unknown>) {
  app.get("/admin/login", (req: Request, res: Response) => {
    const a = randomInt(1, 10);
    const b = randomInt(1, 10);
    const exp = Date.now() + 5 * 60_000;
    const captcha = signCookie(cfg.cookieSecret, { a, b, exp } satisfies CaptchaPayload);
    setCookie(res, "admin_captcha", captcha, { maxAgeSeconds: 5 * 60, httpOnly: true, secure: cfg.cookieSecure, sameSite: "Lax", path: "/admin" });

    res
      .status(200)
      .type("html")
      .send(
        layoutHtml({
          title: "Admin Login",
          body: `
<div class="shell">
  <div class="auth">
    <div class="brand" style="justify-content:center;margin-bottom:14px">
      <div class="logo">MCP</div>
      <div>
        <div class="brand-title">Time Server</div>
        <div class="muted" style="font-size:12px">Admin Dashboard</div>
      </div>
    </div>

    <h1>登录</h1>
    <p class="hint">用于查看服务状态、连接信息与速率限制配置。</p>

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
          <label>验证码：${a} + ${b} = ?</label>
          <input class="input" name="captcha" inputmode="numeric" required />
        </div>
        <button class="btn btn-primary" type="submit" style="height:40px;border-radius:12px">登录</button>
        <div class="muted" style="font-size:12px">无注册入口，仅允许配置账号登录。</div>
      </form>
    </div>
  </div>
</div>
          `,
        }),
      );
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

    clearCookie(res, "admin_captcha", "/admin");
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
    // 修复：登录时 cookie Path=/admin，登出也必须按相同 path 清理；并兼容历史 path=/
    clearCookie(res, "admin_session", "/admin");
    clearCookie(res, "admin_session", "/");
    res.redirect(302, "/admin/login");
  });

  app.get("/admin", (req: Request, res: Response) => {
    const s = requireSession(req, res, cfg);
    if (!s) return;
    const stats = getStats();

    const origin = getOrigin(req);
    const mcpUrl = `${origin}/mcp`;
    const healthUrl = `${origin}/health`;

    const uptimeSeconds = Number((stats as any)?.uptime_s ?? 0);
    const transportsCount = Number((stats as any)?.transports ?? 0);
    const redisEnabled = Boolean((stats as any)?.redis);
    const dbEnabled = Boolean((stats as any)?.db);
    const quota = (stats as any)?.quota as { timezone?: string; counts?: string; default_free_daily_request_limit?: number } | undefined;
    const dbStats = (stats as any)?.db_stats as
      | {
          utc_day?: string;
          accounts?: number;
          active_api_keys?: number;
          tool_calls_today?: { allowed?: number; denied?: number };
          top_api_keys_today?: Array<{
            api_key_id?: string;
            prefix?: string;
            name?: string;
            account_id?: string;
            last_used_at?: string | null;
            allowed?: number;
            denied?: number;
          }>;
        }
      | undefined;
    const limits = (stats as any)?.limits as { rate_limit_per_ip_per_minute?: number; sse_max_conns_per_ip?: number } | undefined;
    const rateLimit = Number(limits?.rate_limit_per_ip_per_minute ?? 0);
    const sseMax = Number(limits?.sse_max_conns_per_ip ?? 0);

    const freeDailyLimit = Number(quota?.default_free_daily_request_limit ?? 0);
    const todayAllowed = Number(dbStats?.tool_calls_today?.allowed ?? 0);
    const todayDenied = Number(dbStats?.tool_calls_today?.denied ?? 0);
    const utcDay = String(dbStats?.utc_day ?? "");
    const accountsCount = Number(dbStats?.accounts ?? 0);
    const activeKeysCount = Number(dbStats?.active_api_keys ?? 0);

    const topKeys = (dbStats?.top_api_keys_today ?? []).slice(0, 10);
    const topKeysRows =
      topKeys.length > 0
        ? topKeys
            .map((k, i) => {
              return `
                <tr>
                  <td>${i + 1}</td>
                  <td class="mono">${escapeHtml(k.prefix ?? "")}</td>
                  <td>${escapeHtml(k.name ?? "")}</td>
                  <td class="mono">${escapeHtml(String(k.account_id ?? "").slice(0, 12))}</td>
                  <td>${Number(k.allowed ?? 0)}</td>
                  <td>${Number(k.denied ?? 0)}</td>
                </tr>
              `;
            })
            .join("")
        : `<tr><td colspan="6" class="muted">No tool calls logged today (UTC).</td></tr>`;

    const bearerTokenSource = process.env.MCP_BEARER_TOKENS ?? process.env.MCP_BEARER_TOKEN ?? "";
    const configuredTokens = bearerTokenSource
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    const authMode = String(((stats as any)?.auth as any)?.mode ?? "env");
    const authEnabled = authMode === "db" || authMode === "both" || configuredTokens.length > 0;

    const bearerUsage =
      ((((stats as any)?.auth as any)?.env_bearer_tokens as Array<{ id?: string; last_used_iso?: string }> | undefined) ?? []);
    const lastUsedIsoById = new Map<string, string>();
    for (const t of bearerUsage) {
      if (t?.id && typeof t.last_used_iso === "string") lastUsedIsoById.set(t.id, t.last_used_iso);
    }

    const apiKeysRows =
      authMode === "db" || authMode === "both"
        ? `
            <tr>
              <td colspan="4" class="muted">
                当前鉴权模式为 <span class="mono">${escapeHtml(authMode)}</span>：API Key 按账号管理，请通过 <span class="mono">/auth</span> 注册登录后在 <span class="mono">/me/api-keys</span> 创建/吊销（此处不展示明文密钥）。
              </td>
            </tr>
          `
        : configuredTokens.length > 0
          ? configuredTokens
              .map((t, i) => {
                const id = tokenId(t);
                const lastUsedIso = lastUsedIsoById.get(id) ?? "";
                return `
                  <tr>
                    <td>Token ${i + 1}</td>
                    <td class="mono">${escapeHtml(maskToken(t))}</td>
                    <td class="mono">—</td>
                    <td class="muted">${escapeHtml(formatIsoDay(lastUsedIso))}</td>
                  </tr>
                `;
              })
              .join("")
          : `
              <tr>
                <td colspan="4" class="muted">No API keys configured. Set <span class="mono">MCP_BEARER_TOKENS</span> to enable Env Bearer auth.</td>
              </tr>
            `;

    const overviewJson = JSON.stringify(
      {
        mcp_url: mcpUrl,
        health_url: healthUrl,
        auth: authEnabled ? { type: "bearer", header: "Authorization: Bearer YOUR_TOKEN" } : { type: "none" },
      },
      null,
      2,
    );

    const cursorConfig = JSON.stringify(
      {
        mcpServers: {
          "time-server": {
            url: mcpUrl,
            headers: authEnabled ? { Authorization: "Bearer YOUR_TOKEN" } : undefined,
          },
        },
      },
      null,
      2,
    );

    const vscodeConfig = JSON.stringify(
      {
        mcp: {
          servers: {
            "time-server": {
              url: mcpUrl,
              headers: authEnabled ? { Authorization: "Bearer YOUR_TOKEN" } : undefined,
            },
          },
        },
      },
      null,
      2,
    );

    const curlHealth = `curl -sS ${authEnabled ? `-H "Authorization: Bearer YOUR_TOKEN" ` : ""}"${healthUrl}"`;
    const curlInitialize = `curl -sS -X POST "${mcpUrl}" \\\n  -H "Content-Type: application/json" \\\n  ${
      authEnabled ? `-H "Authorization: Bearer YOUR_TOKEN" \\\n  ` : ""
    }-d '${JSON.stringify(
      {
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2024-11-05",
          capabilities: {},
          clientInfo: { name: "curl", version: "1.0.0" },
        },
      },
      null,
      2,
    )}'`;

    const curlTool = `curl -sS -X POST "${mcpUrl}" \\\n  -H "Content-Type: application/json" \\\n  -H "mcp-session-id: <SESSION_ID>" \\\n  ${
      authEnabled ? `-H "Authorization: Bearer YOUR_TOKEN" \\\n  ` : ""
    }-d '${JSON.stringify(
      {
        jsonrpc: "2.0",
        id: 2,
        method: "tools/call",
        params: { name: "time_now", arguments: { timezone: "Asia/Shanghai" } },
      },
      null,
      2,
    )}'`;

    const scripts = `
      (function(){
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
            if(el.matches && el.matches('[data-copy-el]')){
              e.preventDefault();
              var id = el.getAttribute('data-copy-el');
              var node = id ? document.getElementById(id) : null;
              var text = node ? (node.textContent || '') : '';
              if(navigator.clipboard && navigator.clipboard.writeText){
                navigator.clipboard.writeText(text).then(function(){});
              } else {
                var ta = document.createElement('textarea');
                ta.value = text; document.body.appendChild(ta); ta.select();
                try{ document.execCommand('copy'); }catch(_){}
                document.body.removeChild(ta);
              }
              el.dataset.copied = "true";
              setTimeout(function(){ delete el.dataset.copied; }, 900);
              return;
            }
            if(el.matches && el.matches('[data-copy]')){
              e.preventDefault();
              var text = el.getAttribute('data-copy') || '';
              if(navigator.clipboard && navigator.clipboard.writeText){
                navigator.clipboard.writeText(text).then(function(){});
              } else {
                var ta = document.createElement('textarea');
                ta.value = text; document.body.appendChild(ta); ta.select();
                try{ document.execCommand('copy'); }catch(_){}
                document.body.removeChild(ta);
              }
              el.dataset.copied = "true";
              setTimeout(function(){ delete el.dataset.copied; }, 900);
              return;
            }
            el = el.parentElement;
          }
        });
        setTab("main", "overview");
        setTab("connect", "cursor");
      })();
    `;

    res
      .status(200)
      .type("html")
      .send(
        layoutHtml({
          title: "Admin Dashboard",
          scripts,
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
          <a href="#" data-tab-group="main" data-tab="libraries">Libraries</a>
          <a href="#" aria-disabled="true" tabindex="-1">Members</a>
          <a href="#" aria-disabled="true" tabindex="-1">Rules</a>
        </nav>

        <div class="actions">
          <a class="link" href="/health">Health</a>
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
        <div class="tabs" aria-label="Tabs">
          <button class="tab" data-tab-group="main" data-tab="overview" data-active="true" type="button">Overview</button>
          <button class="tab" data-tab-group="main" data-tab="libraries" type="button">Libraries</button>
        </div>

        <section data-tab-panel-group="main" data-tab-panel="overview" style="display:block">
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
              <div class="sub">${dbEnabled ? `${accountsCount} accounts · ${activeKeysCount} active keys` : "DB auth disabled"}</div>
            </article>
            <article class="card card-pad">
              <div class="kicker">Quota (UTC)</div>
              <div class="value">${freeDailyLimit ? `${freeDailyLimit}/day` : "—"}</div>
              <div class="sub">${utcDay ? `${utcDay} · allowed ${todayAllowed} · denied ${todayDenied}` : "tools/call only"}</div>
            </article>
          </div>

          <div class="card" style="margin-top:18px">
            <div class="card-pad">
              <div class="section-head">
                <div>
                  <h2 class="section-title">Usage (UTC today)</h2>
                  <div class="section-desc">仅统计并记录 <span class="mono">tools/call</span>（按 UTC 自然日）。</div>
                </div>
                <span class="badge ${dbEnabled ? "badge-ok" : ""}">${dbEnabled ? "DB Logs On" : "DB Logs Off"}</span>
              </div>
            </div>
            <table class="table" aria-label="Top API keys today">
              <thead>
                <tr>
                  <th>#</th>
                  <th>Key Prefix</th>
                  <th>Name</th>
                  <th>Account</th>
                  <th>Allowed</th>
                  <th>Denied</th>
                </tr>
              </thead>
              <tbody>
                ${topKeysRows}
              </tbody>
            </table>
          </div>

          <div class="card" style="margin-top:18px">
            <div class="card-pad">
              <div class="section-head">
                <div>
                  <h2 class="section-title">API Keys</h2>
                  <div class="section-desc">用于访问 <span class="mono">/mcp</span> 的 Bearer Token（<span class="mono">AUTH_MODE=db</span> 时通过 <span class="mono">/me/api-keys</span> 创建）。</div>
                </div>
                <button class="btn btn-primary" type="button" disabled title="${escapeHtml(authMode === "db" || authMode === "both" ? "Use /me/api-keys to create per-account keys" : "Set MCP_BEARER_TOKENS to manage tokens")}">Create API Key</button>
              </div>
            </div>
            <table class="table" aria-label="API keys table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Key</th>
                  <th>Created</th>
                  <th>Last Used</th>
                </tr>
              </thead>
              <tbody>
                ${apiKeysRows}
              </tbody>
            </table>
          </div>

          <div class="card" style="margin-top:18px">
            <div class="card-pad">
              <div class="section-head">
                <div>
                  <h2 class="section-title">Connect</h2>
                  <div class="section-desc">复制地址或选择客户端模板快速接入。</div>
                </div>
                <span class="badge ${authEnabled ? "badge-ok" : ""}">${authEnabled ? `Auth: ${escapeHtml(authMode)}` : "Auth Disabled"}</span>
              </div>

              <div style="display:grid;gap:12px;margin-top:14px">
                <div class="field">
                  <div class="kicker" style="width:74px;flex:0 0 auto">MCP URL</div>
                  <input readonly value="${escapeHtml(mcpUrl)}" class="mono" />
                  <button class="icon-btn" type="button" data-copy="${escapeHtml(mcpUrl)}" title="Copy">${iconCopySvg()}</button>
                </div>
                <div class="field">
                  <div class="kicker" style="width:74px;flex:0 0 auto">API URL</div>
                  <input readonly value="${escapeHtml(healthUrl)}" class="mono" />
                  <button class="icon-btn" type="button" data-copy="${escapeHtml(healthUrl)}" title="Copy">${iconCopySvg()}</button>
                </div>
              </div>

              <div class="tabs" style="margin-top:16px">
                <button class="tab" data-tab-group="connect" data-tab="cursor" data-active="true" type="button">Cursor</button>
                <button class="tab" data-tab-group="connect" data-tab="vscode" type="button">VS Code</button>
                <button class="tab" data-tab-group="connect" data-tab="generic" type="button">Generic</button>
              </div>
            </div>

            <div class="card-pad" style="padding-top:0">
              <div data-tab-panel-group="connect" data-tab-panel="cursor" style="display:block">
                <pre class="mono">${escapeHtml(cursorConfig)}</pre>
              </div>
              <div data-tab-panel-group="connect" data-tab-panel="vscode" style="display:none">
                <pre class="mono">${escapeHtml(vscodeConfig)}</pre>
              </div>
              <div data-tab-panel-group="connect" data-tab-panel="generic" style="display:none">
                <pre class="mono">${escapeHtml(overviewJson)}</pre>
              </div>
            </div>
          </div>

          <div class="card" style="margin-top:18px">
            <div class="card-pad">
              <div class="section-head">
                <div>
                  <h2 class="section-title">API</h2>
                  <div class="section-desc">用 curl 验证服务可用性与工具调用（示例）。</div>
                </div>
                <button class="btn" type="button" data-copy="${escapeHtml(mcpUrl)}">Copy MCP URL</button>
              </div>
            </div>

            <div class="card-pad" style="padding-top:0;display:grid;gap:12px">
              <div>
                <div class="kicker" style="margin:6px 0 8px">Health</div>
                <pre class="mono">${escapeHtml(curlHealth)}</pre>
              </div>
              <div>
                <div class="kicker" style="margin:6px 0 8px">Initialize (creates a session)</div>
                <pre class="mono">${escapeHtml(curlInitialize)}</pre>
              </div>
              <div>
                <div class="kicker" style="margin:6px 0 8px">Call tool: time_now</div>
                <pre class="mono">${escapeHtml(curlTool)}</pre>
              </div>
            </div>
          </div>

          <div class="card" style="margin-top:18px">
            <div class="card-pad">
              <div class="section-head">
                <div>
                  <h2 class="section-title">Limits</h2>
                  <div class="section-desc">运行时限流与 SSE 并发上限。</div>
                </div>
                <span class="badge">${redisEnabled ? "Redis-backed" : "In-memory"}</span>
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
              <tbody>
                <tr>
                  <td>Requests / IP</td>
                  <td class="mono">${rateLimit ? `${rateLimit} per minute` : "—"}</td>
                  <td class="muted">Applies to GET/POST/DELETE /mcp</td>
                </tr>
                <tr>
                  <td>SSE Conns / IP</td>
                  <td class="mono">${sseMax ? `${sseMax} active` : "—"}</td>
                  <td class="muted">Max concurrent GET /mcp streams</td>
                </tr>
              </tbody>
            </table>
            <div class="card-pad">
              <div class="callout">
                <div>
                  <strong>Tip</strong>
                  <p>要获得稳定的限流与并发控制，建议配置 Redis（<span class="mono">REDIS_URL</span>）。</p>
                </div>
                <a class="btn" href="/admin/api/stats">View JSON</a>
              </div>
            </div>
          </div>

          <div class="card" style="margin-top:18px">
            <div class="card-pad">
              <div class="section-head">
                <div>
                  <h2 class="section-title">Debug</h2>
                  <div class="section-desc">服务状态原始数据（只读）。</div>
                </div>
                <button class="btn" type="button" data-copy-el="stats-json">Copy JSON</button>
              </div>
            </div>
            <div class="card-pad" style="padding-top:0">
              <pre id="stats-json" class="mono">${escapeHtml(JSON.stringify(stats, null, 2))}</pre>
            </div>
          </div>
        </section>

        <section data-tab-panel-group="main" data-tab-panel="libraries" style="display:none">
          <div class="card">
            <div class="card-pad">
              <div class="section-head">
                <div>
                  <h2 class="section-title">Public Tool Access</h2>
                  <div class="section-desc">控制客户端可以访问的工具范围（展示为只读示意）。</div>
                </div>
              </div>

              <div class="radio-group" role="radiogroup" aria-label="Public tool access">
                <div class="radio" data-selected="true">
                  <input type="radio" checked disabled aria-label="All tools" />
                  <div>
                    <div class="title">All Tools</div>
                    <div class="desc">允许访问全部时间工具：time_now / time_convert / time_shift / time_range</div>
                  </div>
                </div>
                <div class="radio" data-selected="false">
                  <input type="radio" disabled aria-label="Only basic tools" />
                  <div>
                    <div class="title">Only Select Tools</div>
                    <div class="desc">仅允许访问部分工具（计划功能）。</div>
                  </div>
                </div>
                <div class="radio" data-selected="false" style="opacity:0.75">
                  <input type="radio" disabled aria-label="Disable public access" />
                  <div>
                    <div class="title">Disable Public Access</div>
                    <div class="desc">通过启用 Bearer Token 限制访问（推荐）。</div>
                  </div>
                </div>
              </div>
            </div>

            <div class="card-pad" style="border-top:1px solid hsl(var(--border))">
              <div class="callout">
                <div>
                  <strong>Note</strong>
                  <p>当前访问控制由环境变量驱动：<span class="mono">MCP_BEARER_TOKENS</span>（认证）与 <span class="mono">RATE_LIMIT_PER_IP_PER_MINUTE</span>（限流）。</p>
                </div>
                <a class="btn" href="/admin/login">Re-auth</a>
              </div>
            </div>
          </div>
        </section>
      </div>
    </div>
  </main>
</div>
          `,
        }),
      );
  });

  app.get("/admin/api/stats", (req: Request, res: Response) => {
    const s = requireSession(req, res, cfg);
    if (!s) return;
    res.status(200).json(getStats());
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
