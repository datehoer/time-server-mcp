import { Controller, Get, Req, Res } from "@nestjs/common";
import type { FastifyReply, FastifyRequest } from "fastify";
import { escapeHtml, layoutHtml } from "./ui.js";
import { getOrigin } from "./origin.js";
import { AppContextService } from "./appContext.service.js";

/**
 * 主页（Landing Page）
 * - 视觉：复用 Dashboard 的基础样式（src/ui.ts）
 * - 规范：不使用行内样式；颜色只用 CSS Variables（避免 hardcode）
 */
@Controller()
export class HomeController {
  constructor(private readonly ctx: AppContextService) {}

  @Get("/")
  async home(@Req() req: FastifyRequest, @Res() reply: FastifyReply) {
    const origin = getOrigin(req);
    const mcpUrl = `${origin}/mcp`;

    const dashboardHref = this.ctx.dashboardEnabled ? "/dashboard" : "#";
    const dashboardDisabledAttr = this.ctx.dashboardEnabled ? "" : ' aria-disabled="true"';

    reply.code(200).type("text/html").send(
      layoutHtml({
        title: "Time Server",
        body: `
          <div class="shell">
            <header class="topbar">
              <div class="container">
                <div class="topbar-inner">
                  <div class="brand">
                    <div class="logo"><img class="logo-img" src="/assets/logo.png" alt="MCP" width="28" height="28" /></div>
                    <div class="brand-title">Time Server</div>
                    <div class="workspace" title="Auth mode">
                      <span class="mono">${escapeHtml(this.ctx.authMode)}</span>
                    </div>
                  </div>

                  <nav class="nav" aria-label="Primary">
                    <a href="/" data-active="true">Home</a>
                    <a href="${dashboardHref}"${dashboardDisabledAttr}>Dashboard</a>
                    <a href="/health">Health</a>
                  </nav>

                  <div class="actions">
                    ${
                      this.ctx.dashboardEnabled
                        ? `<a class="btn btn-primary" href="/dashboard">进入 Dashboard</a>`
                        : `<a class="btn btn-primary" href="/health">查看 Health</a>`
                    }
                  </div>
                </div>
              </div>
            </header>

            <main>
              <div class="container">
                <div class="home">
                  <section class="hero">
                    <div class="hero-grid">
                      <div>
                        <div class="kicker">Model Context Protocol</div>
                        <h1 class="hero-title">时间工具服务</h1>
                        <p class="hero-lede">提供获取当前时间、时区转换、时间偏移与常见时间范围计算，并通过 Streamable HTTP + SSE 暴露为 MCP 服务。</p>

                        <div class="hero-actions">
                          <a class="btn btn-primary" href="/health">快速自检</a>
                          ${
                            this.ctx.dashboardEnabled
                              ? `<a class="btn" href="/dashboard/login">登录</a><a class="btn" href="/dashboard/register">注册</a>`
                              : ""
                          }
                        </div>

                        ${
                          this.ctx.dashboardEnabled
                            ? ""
                            : `<div class="callout">
                                 <div>
                                   <strong>Dashboard 未启用</strong>
                                   <p>如需页面版登录/Key 管理，请配置 <span class="mono">DATABASE_URL</span>、<span class="mono">REDIS_URL</span> 并设置 <span class="mono">AUTH_MODE=db</span>（以及 <span class="mono">API_KEY_ENCRYPTION_SECRET</span>）。</p>
                                 </div>
                               </div>`
                        }
                      </div>

                      <aside class="hero-aside" aria-label="Endpoints">
                        <div class="spec">
                          <div class="row"><div class="key">Base URL</div><div class="val mono">${escapeHtml(origin)}</div></div>
                          <div class="row"><div class="key">MCP Endpoint</div><div class="val mono">${escapeHtml(mcpUrl)}</div></div>
                          <div class="row"><div class="key">Dashboard</div><div class="val">${this.ctx.dashboardEnabled ? "Enabled" : "Disabled"}</div></div>
                        </div>
                        <div class="links" aria-label="Quick links">
                          <a href="/health">/health</a>
                          ${this.ctx.dashboardEnabled ? `<a href="/dashboard">/dashboard</a>` : ""}
                        </div>
                      </aside>
                    </div>
                  </section>

                  <section aria-label="Capabilities">
                    <div class="section-head">
                      <div>
                        <h2 class="section-title">Capabilities</h2>
                        <div class="section-desc">四类时间能力，默认输出稳定且适合程序消费。</div>
                      </div>
                    </div>

                    <div class="grid grid-4">
                      <article class="card card-pad">
                        <div class="kicker">Tool</div>
                        <div class="value">time_now</div>
                        <div class="sub">获取当前时间（默认 UTC），支持 IANA 时区与多格式输出。</div>
                      </article>
                      <article class="card card-pad">
                        <div class="kicker">Tool</div>
                        <div class="value">time_convert</div>
                        <div class="sub">把一个输入时间转换到多个目标时区。</div>
                      </article>
                      <article class="card card-pad">
                        <div class="kicker">Tool</div>
                        <div class="value">time_shift</div>
                        <div class="sub">对基准时间做偏移（支持负数回到过去）。</div>
                      </article>
                      <article class="card card-pad">
                        <div class="kicker">Tool</div>
                        <div class="value">time_range</div>
                        <div class="sub">计算 today/this_week/last_week/last_7_days 等范围起止。</div>
                      </article>
                    </div>
                  </section>

                  <section aria-label="Quickstart">
                    <div class="section-head">
                      <div>
                        <h2 class="section-title">Quickstart</h2>
                        <div class="section-desc">先验证服务可用，再接入 MCP 客户端。</div>
                      </div>
                    </div>
                    <pre class="mono">curl -s ${escapeHtml(origin)}/health</pre>
                  </section>
                </div>
              </div>
            </main>
          </div>
        `,
      }),
    );
  }
}

