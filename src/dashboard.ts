import type { Express, Request, Response } from "express";
import { randomUUID } from "node:crypto";
import type { Db } from "./db.js";
import type { RedisClientLike } from "./redisLike.js";
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

export function registerDashboardRoutes(
  app: Express,
  deps: { db: Db; redis: RedisClientLike; cookieName: string; ttlSeconds: number; cookieSecure: boolean },
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
        <div class="muted" style="font-size:12px">管理员入口：<a href="/admin">/admin</a></div>
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
          <a href="/dashboard" data-active="true">Dashboard</a>
          <a href="/admin">Admin</a>
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
        <div class="card">
          <div class="card-pad">
            <div class="section-head">
              <div>
                <h2 class="section-title">API Keys</h2>
                <div class="section-desc">默认仅显示掩码；点击复制将临时解密并写入剪贴板。</div>
              </div>
              <button class="btn btn-primary" type="button" id="btnCreate">Create API Key</button>
            </div>

            <div style="display:grid;gap:12px;margin-top:14px">
              <div class="field">
                <div class="kicker" style="width:74px;flex:0 0 auto">Account</div>
                <input id="acct" readonly value="loading…" class="mono" />
              </div>
              <div class="field">
                <div class="kicker" style="width:74px;flex:0 0 auto">Quota</div>
                <input readonly value="UTC · tools/call" class="mono" />
              </div>
              <div class="muted" id="status" style="font-size:12px"></div>
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
            function fmtIso(s){ if(!s) return 'Never'; return s.length>=19 ? s.slice(0,19).replace('T',' ') : s; }
            function esc(s){ return String(s||'').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;'); }
            const copyIcon = ${JSON.stringify(iconCopySvg())};

            async function load(){
              const me = await fetch('/me', {credentials:'same-origin'});
              if(me.status===401){ location.href='/dashboard/login'; return; }
              const meJson = await me.json();
              const acctEl = document.getElementById('acct');
              if(acctEl) acctEl.value = (meJson.account && (meJson.account.email || meJson.account.id)) || '';

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
                await load();
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
                await load();
              });
            }

            load().catch(()=>flash('加载失败'));
          })();
        `,
      }),
    );
  });
}
