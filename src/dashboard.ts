import type { Express, Request, Response } from "express";
import { randomUUID } from "node:crypto";
import type { Db } from "./db.js";
import type { RedisClientLike } from "./redisLike.js";
import { hashPassword, verifyPassword } from "./security.js";

function iconCopy() {
  return `<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor">
  <rect x="9" y="9" width="13" height="13" rx="2" stroke-width="2"></rect>
  <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" stroke-width="2"></path>
</svg>`;
}

function page(title: string, body: string) {
  return `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${title}</title>
  <style>
    :root{
      --bg:#0b1020;
      --card:#121a33;
      --muted:#a9b2d0;
      --text:#e9ecf8;
      --pri:#4f8cff;
      --danger:#ff5b6e;
      --border:rgba(255,255,255,.10)
    }
    *{box-sizing:border-box}
    body{margin:0;background:var(--bg);color:var(--text);font-family:ui-sans-serif,system-ui}
    a{color:var(--pri);text-decoration:none}
    a:hover{text-decoration:underline}
    .wrap{max-width:980px;margin:0 auto;padding:28px 16px}
    .top{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:18px}
    .card{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:16px}
    .row{display:flex;gap:12px;flex-wrap:wrap}
    .muted{color:var(--muted)}
    .input{width:100%;padding:10px 12px;border-radius:10px;border:1px solid var(--border);background:transparent;color:var(--text)}
    .btn{padding:10px 12px;border-radius:10px;border:1px solid var(--border);background:transparent;color:var(--text);cursor:pointer}
    .btn-pri{background:var(--pri);border-color:transparent;color:#081022;font-weight:650}
    .btn-danger{border-color:rgba(255,91,110,.35);color:#ffd6dc}
    table{width:100%;border-collapse:collapse}
    th,td{padding:10px 8px;border-bottom:1px solid var(--border);text-align:left}
    .mono{font-family:ui-monospace,Menlo,Consolas,monospace}
    .icon{width:16px;height:16px;vertical-align:-3px}
    .actions{display:flex;gap:10px;align-items:center}
    .toast{position:fixed;right:14px;bottom:14px;background:#0e1630;border:1px solid var(--border);padding:10px 12px;border-radius:12px;display:none}
  </style>
</head>
<body>${body}</body></html>`;
}

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
      page(
        "Dashboard Login",
        `<div class="wrap">
          <div class="top">
            <div>
              <div style="font-weight:750;font-size:18px">Dashboard</div>
              <div class="muted">用户后台登录</div>
            </div>
            <a class="muted" href="/admin">Admin</a>
          </div>

          <div class="card" style="max-width:520px;margin:0 auto">
            <form method="post" action="/dashboard/login">
              <div style="display:grid;gap:10px">
                <div>
                  <div class="muted" style="font-size:12px;margin-bottom:6px">Email</div>
                  <input class="input" name="email" autocomplete="email" required />
                </div>
                <div>
                  <div class="muted" style="font-size:12px;margin-bottom:6px">Password</div>
                  <input class="input" type="password" name="password" autocomplete="current-password" required />
                </div>
                <button class="btn btn-pri" type="submit">登录</button>
                <div class="muted" style="font-size:12px">没有账号？<a href="/dashboard/register">去注册</a></div>
              </div>
            </form>
          </div>
        </div>`,
      ),
    );
  });

  app.get("/dashboard/register", (_req, res) => {
    res.status(200).type("html").send(
      page(
        "Dashboard Register",
        `<div class="wrap">
          <div class="top">
            <div>
              <div style="font-weight:750;font-size:18px">Dashboard</div>
              <div class="muted">注册账号</div>
            </div>
            <a class="muted" href="/dashboard/login">登录</a>
          </div>

          <div class="card" style="max-width:520px;margin:0 auto">
            <form method="post" action="/dashboard/register">
              <div style="display:grid;gap:10px">
                <div>
                  <div class="muted" style="font-size:12px;margin-bottom:6px">Email</div>
                  <input class="input" name="email" autocomplete="email" required />
                </div>
                <div>
                  <div class="muted" style="font-size:12px;margin-bottom:6px">Password (>=8)</div>
                  <input class="input" type="password" name="password" autocomplete="new-password" required />
                </div>
                <button class="btn btn-pri" type="submit">注册并登录</button>
                <div class="muted" style="font-size:12px">已有账号？<a href="/dashboard/login">去登录</a></div>
              </div>
            </form>
          </div>
        </div>`,
      ),
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
        .send(page("Register failed", `<div class="wrap"><div class="card">Email 已存在。<a href="/dashboard/login">去登录</a></div></div>`));
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
      page(
        "Dashboard",
        `<div class="wrap">
          <div class="top">
            <div>
              <div style="font-weight:800;font-size:18px">Dashboard</div>
              <div class="muted">用户后台 · API Keys & Quota</div>
            </div>
            <div class="actions">
              <a class="muted" href="/admin">Admin</a>
              <form method="post" action="/dashboard/logout" style="margin:0"><button class="btn" type="submit">退出</button></form>
            </div>
          </div>

          <div class="card" style="margin-bottom:14px">
            <div class="row" style="justify-content:space-between;align-items:center">
              <div>
                <div class="muted" style="font-size:12px">Account</div>
                <div id="acct" class="mono">loading…</div>
              </div>
              <div>
                <div class="muted" style="font-size:12px">Quota</div>
                <div class="mono">UTC · tools/call</div>
              </div>
              <button class="btn btn-pri" type="button" id="btnCreate">创建 API Key</button>
            </div>
          </div>

          <div class="card">
            <div style="display:flex;justify-content:space-between;align-items:end;gap:12px;margin-bottom:10px">
              <div>
                <div style="font-weight:750">API Keys</div>
                <div class="muted" style="font-size:12px">默认仅显示掩码；点击复制将临时解密并写入剪贴板。</div>
              </div>
            </div>
            <table>
              <thead><tr><th>Name</th><th>Key</th><th>Created</th><th>Last Used</th><th>Actions</th></tr></thead>
              <tbody id="rows"><tr><td colspan="5" class="muted">loading…</td></tr></tbody>
            </table>
          </div>

          <div class="toast" id="toast"></div>

          <script>
            const toastEl = document.getElementById('toast');
            function toast(msg){
              toastEl.textContent = msg;
              toastEl.style.display = 'block';
              setTimeout(()=>toastEl.style.display='none', 1800);
            }
            function fmtIso(s){ if(!s) return 'Never'; return s.length>=19 ? s.slice(0,19).replace('T',' ') : s; }
            function esc(s){ return String(s||'').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;'); }

            async function load(){
              const me = await fetch('/me', {credentials:'same-origin'});
              if(me.status===401){ location.href='/dashboard/login'; return; }
              const meJson = await me.json();
              document.getElementById('acct').textContent = meJson.account.email || meJson.account.id;

              const r = await fetch('/me/api-keys', {credentials:'same-origin'});
              const j = await r.json();
              const rows = document.getElementById('rows');
              if(!j.keys || j.keys.length===0){ rows.innerHTML = '<tr><td colspan=\"5\" class=\"muted\">No keys yet.</td></tr>'; return; }
              rows.innerHTML = j.keys.map(k => {
                const masked = (k.prefix || 'mcp_') + '…';
                const disabled = k.revoked_at ? 'disabled' : '';
                return '<tr>'
                  + '<td>' + esc(k.name) + '</td>'
                  + '<td class=\"mono\">' + esc(masked) + '</td>'
                  + '<td class=\"mono\">' + esc(fmtIso(k.created_at)) + '</td>'
                  + '<td class=\"mono\">' + esc(fmtIso(k.last_used_at)) + '</td>'
                  + '<td>'
                    + '<button class=\"btn\" data-copy=\"'+ esc(k.id) +'\" '+disabled+' title=\"复制明文 key\">${iconCopy()}</button> '
                    + (k.revoked_at ? '<span class=\"muted\">revoked</span>' : '<button class=\"btn btn-danger\" data-revoke=\"'+ esc(k.id) +'\">吊销</button>')
                  + '</td>'
                + '</tr>';
              }).join('');
            }

            document.addEventListener('click', async (e) => {
              const t = e.target.closest('button');
              if(!t) return;
              const idCopy = t.getAttribute('data-copy');
              const idRev = t.getAttribute('data-revoke');
              if(idCopy){
                const r = await fetch('/me/api-keys/' + encodeURIComponent(idCopy) + '/reveal', {method:'POST', credentials:'same-origin'});
                const j = await r.json().catch(()=>({ok:false}));
                if(!j.ok){ toast(j.error || '复制失败'); return; }
                await navigator.clipboard.writeText(j.secret);
                toast('已复制到剪贴板');
                return;
              }
              if(idRev){
                if(!confirm('确定吊销该 Key？吊销后将立即失效。')) return;
                const r = await fetch('/me/api-keys/' + encodeURIComponent(idRev), {method:'DELETE', credentials:'same-origin'});
                const j = await r.json().catch(()=>({ok:false}));
                if(!j.ok){ toast(j.error || '吊销失败'); return; }
                toast('已吊销');
                await load();
              }
            });

            document.getElementById('btnCreate').addEventListener('click', async () => {
              const name = prompt('Key 名称（可选）','');
              const r = await fetch('/me/api-keys', {
                method:'POST',
                credentials:'same-origin',
                headers:{'Content-Type':'application/json'},
                body: JSON.stringify({ name: name || '' })
              });
              const j = await r.json().catch(()=>({ok:false}));
              if(!j.ok){ toast(j.error || '创建失败'); return; }
              await navigator.clipboard.writeText(j.secret);
              toast('Key 已创建并已复制（仅创建时返回一次）');
              await load();
            });

            load().catch(()=>toast('加载失败'));
          </script>
        </div>`,
      ),
    );
  });
}

