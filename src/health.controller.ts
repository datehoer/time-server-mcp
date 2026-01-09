import { Controller, Get, Req, Res } from "@nestjs/common";
import type { FastifyReply, FastifyRequest } from "fastify";
import { AppContextService } from "./appContext.service.js";
import { escapeHtml, layoutHtml } from "./ui.js";
import { getOrigin } from "./origin.js";

type HealthPayload = {
  ok: boolean;
  uptime_s: number;
  transports: number;
  redis: boolean;
  db: boolean;
  auth: { mode: string; env_enabled: boolean; db_enabled: boolean };
};

function pickHealthFormat(req: FastifyRequest): "json" | "html" {
  const q = (req.query as any)?.format;
  const forced = typeof q === "string" ? q : "";
  if (forced === "json" || forced === "html") return forced;

  // 浏览器通常带 text/html；程序/CLI 常是 */* 或 application/json。
  const accept = String(req.headers["accept"] ?? "").toLowerCase();
  if (accept.includes("text/html") && !accept.includes("application/json")) return "html";
  return "json";
}

function renderHealthHtml(req: FastifyRequest, payload: HealthPayload) {
  const origin = getOrigin(req);
  const curlJson = `curl -sS '${origin}/health?format=json'`;
  return layoutHtml({
    title: "Health",
    body: `
<div class="shell">
  <header class="topbar">
    <div class="container">
      <div class="topbar-inner">
        <div class="brand">
          <div class="logo"><img class="logo-img" src="/assets/logo.png" alt="MCP" width="28" height="28" /></div>
          <div>
            <div class="brand-title">Time Server</div>
            <div class="muted" style="font-size:12px">Health</div>
          </div>
        </div>
        <div class="actions">
          <a class="btn" href="/">Home</a>
          <a class="btn btn-primary" href="/health?format=json">JSON</a>
        </div>
      </div>
    </div>
  </header>

  <main>
    <div class="container">
      <div class="stack">
        <section class="card card-pad" aria-label="Status">
          <div class="section-head">
            <div>
              <h1 class="section-title" style="margin:0">Health</h1>
              <div class="section-desc">默认 JSON；浏览器访问时返回 HTML（也可用 <span class="mono">?format=json</span> 强制）。</div>
            </div>
            <div>
              ${
                payload.ok
                  ? `<span class="badge badge-ok"><span class="dot dot-ok" aria-hidden="true"></span>OK</span>`
                  : `<span class="badge badge-danger"><span class="dot dot-danger" aria-hidden="true"></span>ERROR</span>`
              }
            </div>
          </div>
        </section>

        <section class="grid grid-4" aria-label="Summary">
          <article class="card card-pad">
            <div class="kicker">Uptime</div>
            <div class="value">${escapeHtml(payload.uptime_s)}s</div>
            <div class="sub">process.uptime()</div>
          </article>
          <article class="card card-pad">
            <div class="kicker">Transports</div>
            <div class="value">${escapeHtml(payload.transports)}</div>
            <div class="sub">active sessions</div>
          </article>
          <article class="card card-pad">
            <div class="kicker">Redis</div>
            <div class="value">${payload.redis ? "Enabled" : "Disabled"}</div>
            <div class="sub">quota / session</div>
          </article>
          <article class="card card-pad">
            <div class="kicker">Database</div>
            <div class="value">${payload.db ? "Enabled" : "Disabled"}</div>
            <div class="sub">accounts / api keys</div>
          </article>
        </section>

        <section aria-label="Payload">
          <div class="section-head">
            <div>
              <h2 class="section-title">JSON Payload</h2>
              <div class="section-desc">复制给监控/排障更方便；也可用 <span class="mono">?format=html</span> 强制打开页面。</div>
            </div>
          </div>
          <pre class="mono">${escapeHtml(JSON.stringify(payload, null, 2))}</pre>
        </section>

        <section aria-label="CLI">
          <div class="section-head">
            <div>
              <h2 class="section-title">CLI</h2>
              <div class="section-desc">建议显式指定 format，确保稳定行为。</div>
            </div>
          </div>
          <pre class="mono">${escapeHtml(curlJson)}</pre>
        </section>
      </div>
    </div>
  </main>
</div>
    `,
  });
}

@Controller()
export class HealthController {
  constructor(private readonly ctx: AppContextService) {}

  @Get("health")
  async getHealth(@Req() req: FastifyRequest, @Res() reply: FastifyReply) {
    const payload: HealthPayload = {
      ok: true,
      uptime_s: Math.floor(process.uptime()),
      transports: Object.keys(this.ctx.transports).length,
      redis: Boolean(this.ctx.redis),
      db: Boolean(this.ctx.db),
      auth: { mode: this.ctx.authMode, env_enabled: this.ctx.envAuthEnabled, db_enabled: this.ctx.dbAuthEnabled },
    };

    const format = pickHealthFormat(req);
    if (format === "html") {
      reply.code(200).type("text/html").send(renderHealthHtml(req, payload));
      return;
    }
    reply.code(200).send(payload);
  }
}

