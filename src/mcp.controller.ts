import { Controller, Delete, Get, Post, Req, Res } from "@nestjs/common";
import type { FastifyReply, FastifyRequest } from "fastify";
import { randomUUID } from "node:crypto";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { AppContextService } from "./appContext.service.js";
import { requireApiKey } from "./mcpAuth.js";
import { ToolsCallSchema } from "./mcpTools.js";
import { incrDailyIfBelow, incrDailyPairIfBelow, secondsUntilNextUtcDay, utcDayKey } from "./mcpQuota.js";
import { getGlobalDailyLimitCached, getToolDailyLimitCached } from "./quota.js";
import { getClientIp } from "./httpUtil.js";

@Controller()
export class McpController {
  constructor(private readonly ctx: AppContextService) {}

  @Post("mcp")
  async postMcp(@Req() req: FastifyRequest, @Res() reply: FastifyReply) {
    if (!(await this.ctx.enforceRateLimit(req, reply))) return;
    const toolCall = ToolsCallSchema.safeParse((req as any).body);
    const toolName = toolCall.success ? toolCall.data.params.name : null;

    let accountId: string | null = null;
    let apiKeyId: string | null = null;

    // 1) DB API Key（推荐）
    if (this.ctx.dbAuthEnabled && this.ctx.db && this.ctx.redis) {
      const auth = await requireApiKey(req as any, reply as any, { db: this.ctx.db, redis: this.ctx.redis as any });
      if (!auth) {
        if (toolName) {
          this.ctx.requestLog?.push({
            ts: new Date(),
            accountId: null,
            apiKeyId: null,
            tool: toolName,
            allowed: false,
            httpStatus: 401,
            ip: getClientIp(req),
          });
        }
        return;
      }
      accountId = auth.accountId;
      apiKeyId = auth.apiKeyId;
      this.ctx.apiKeyLastUsed?.touch(apiKeyId, Date.now());
    } else if (this.ctx.envAuthEnabled) {
      // 2) 兼容旧的环境变量 token（迁移期）
      if (!this.ctx.requireBearerEnv(req, reply)) return;
    } else {
      reply.code(401).send("Unauthorized");
      return;
    }

    // 配额：仅 tools/call 计数，按 UTC 日切
    if (toolName && this.ctx.dbAuthEnabled && this.ctx.db && this.ctx.redis) {
      const day = utcDayKey();
      const ttlSeconds = secondsUntilNextUtcDay();

      const globalLimit = await getGlobalDailyLimitCached({
        redis: this.ctx.redis as any,
        db: this.ctx.db,
        accountId: accountId!,
        metric: "requests",
        defaultFree: this.ctx.cfg.DEFAULT_FREE_DAILY_REQUEST_LIMIT,
        cacheSeconds: this.ctx.cfg.POLICY_CACHE_SECONDS,
      });

      const toolLimit = await getToolDailyLimitCached({
        redis: this.ctx.redis as any,
        db: this.ctx.db,
        accountId: accountId!,
        metric: "requests",
        tool: toolName,
        cacheSeconds: this.ctx.cfg.POLICY_CACHE_SECONDS,
      });

      const globalKey = `quota:acct:${accountId}:${day}:requests:all`;
      const toolKey = `quota:acct:${accountId}:${day}:requests:tool:${toolName}`;

      let allowed = true;
      let usedAccount = 0;
      let usedTool: number | null = null;

      if (toolLimit === null) {
        const q1 = await incrDailyIfBelow({ redis: this.ctx.redis as any, key: globalKey, limit: globalLimit, ttlSeconds });
        allowed = q1.allowed;
        usedAccount = q1.used;
      } else {
        const q2 = await incrDailyPairIfBelow({
          redis: this.ctx.redis as any,
          key1: globalKey,
          limit1: globalLimit,
          key2: toolKey,
          limit2: toolLimit,
          ttlSeconds,
        });
        allowed = q2.allowed;
        usedAccount = q2.used1;
        usedTool = q2.used2;
      }

      if (!allowed) {
        const id = toolCall.success ? toolCall.data.id ?? null : null;
        reply.code(429).send({
          jsonrpc: "2.0",
          error: {
            code: -32029,
            message: "Daily quota exceeded",
            data:
              toolLimit === null
                ? { timezone: "UTC", day, scope: "account", limit: globalLimit, used: usedAccount }
                : {
                    timezone: "UTC",
                    day,
                    scope: "account+tool",
                    account_limit: globalLimit,
                    tool_limit: toolLimit,
                    used_account: usedAccount,
                    used_tool: usedTool,
                  },
          },
          id,
        });
        this.ctx.requestLog?.push({
          ts: new Date(),
          accountId,
          apiKeyId,
          tool: toolName,
          allowed: false,
          httpStatus: 429,
          ip: getClientIp(req),
        });
        return;
      }
    }

    try {
      const sessionId = req.headers["mcp-session-id"] as string | undefined;

      // 1) 已有 session：复用 transport
      if (sessionId && this.ctx.transports[sessionId]) {
        reply.hijack();
        await this.ctx.transports[sessionId].handleRequest(req.raw as any, reply.raw as any, (req as any).body);
        if (toolName) {
          this.ctx.requestLog?.push({
            ts: new Date(),
            accountId,
            apiKeyId,
            tool: toolName,
            allowed: true,
            httpStatus: reply.raw.statusCode || 200,
            ip: getClientIp(req),
          });
        }
        return;
      }

      // 2) 无 session 且是 initialize：创建新的 transport + connect
      if (!sessionId && isInitializeRequest((req as any).body)) {
        let transport!: StreamableHTTPServerTransport;

        transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => randomUUID(),
          onsessioninitialized: (newSessionId) => {
            this.ctx.transports[newSessionId] = transport;
          },
        });

        await this.ctx.mcpServer.connect(transport);
        reply.hijack();
        await transport.handleRequest(req.raw as any, reply.raw as any, (req as any).body);
        if (toolName) {
          this.ctx.requestLog?.push({
            ts: new Date(),
            accountId,
            apiKeyId,
            tool: toolName,
            allowed: true,
            httpStatus: reply.raw.statusCode || 200,
            ip: getClientIp(req),
          });
        }
        return;
      }

      // 3) 其他情况：Bad Request
      reply.code(400).send({
        jsonrpc: "2.0",
        error: { code: -32000, message: "Bad Request: No valid session ID provided" },
        id: null,
      });
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error("POST /mcp error:", err);
      if (!reply.raw.headersSent) {
        reply.code(500).send({
          jsonrpc: "2.0",
          error: { code: -32603, message: "Internal server error" },
          id: null,
        });
      }
      if (toolName) {
        this.ctx.requestLog?.push({
          ts: new Date(),
          accountId,
          apiKeyId,
          tool: toolName,
          allowed: false,
          httpStatus: 500,
          ip: getClientIp(req),
        });
      }
    }
  }

  // GET: establish SSE stream for server-to-client messages
  @Get("mcp")
  async getMcp(@Req() req: FastifyRequest, @Res() reply: FastifyReply) {
    if (!(await this.ctx.enforceRateLimit(req, reply))) return;

    if (this.ctx.dbAuthEnabled && this.ctx.db && this.ctx.redis) {
      const auth = await requireApiKey(req as any, reply as any, { db: this.ctx.db, redis: this.ctx.redis as any });
      if (!auth) return;
      this.ctx.apiKeyLastUsed?.touch(auth.apiKeyId, Date.now());
    } else if (this.ctx.envAuthEnabled) {
      if (!this.ctx.requireBearerEnv(req, reply)) return;
    } else {
      reply.code(401).send("Unauthorized");
      return;
    }

    const sessionId = req.headers["mcp-session-id"] as string | undefined;
    if (!sessionId || !this.ctx.transports[sessionId]) {
      reply.code(400).send("Invalid or missing session ID");
      return;
    }

    const ip = getClientIp(req);
    const acquired = await this.ctx.sseLimiter.tryAcquire(ip);
    if (!acquired.allowed) {
      reply.header("Retry-After", String(acquired.retryAfterSeconds));
      reply.code(429).send(`Too Many SSE connections (active=${acquired.active})`);
      return;
    }

    const connId = acquired.connId;
    const heartbeat = setInterval(() => {
      if (reply.raw.headersSent) {
        try {
          reply.raw.write(`: ping ${Date.now()}\n\n`);
        } catch {
          // ignore
        }
      }
      this.ctx.sseLimiter.refresh(ip, connId).catch(() => {});
    }, this.ctx.sseHeartbeatMs);

    const cleanup = () => {
      clearInterval(heartbeat);
      this.ctx.sseLimiter.release(ip, connId).catch(() => {});
    };
    reply.raw.on("close", cleanup);
    reply.raw.on("finish", cleanup);

    try {
      reply.hijack();
      await this.ctx.transports[sessionId].handleRequest(req.raw as any, reply.raw as any);
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error("GET /mcp error:", err);
      if (!reply.raw.headersSent) reply.code(500).send("Internal server error");
    }
  }

  // DELETE: terminate session
  @Delete("mcp")
  async deleteMcp(@Req() req: FastifyRequest, @Res() reply: FastifyReply) {
    if (!(await this.ctx.enforceRateLimit(req, reply))) return;

    if (this.ctx.dbAuthEnabled && this.ctx.db && this.ctx.redis) {
      const auth = await requireApiKey(req as any, reply as any, { db: this.ctx.db, redis: this.ctx.redis as any });
      if (!auth) return;
      this.ctx.apiKeyLastUsed?.touch(auth.apiKeyId, Date.now());
    } else if (this.ctx.envAuthEnabled) {
      if (!this.ctx.requireBearerEnv(req, reply)) return;
    } else {
      reply.code(401).send("Unauthorized");
      return;
    }

    const sessionId = req.headers["mcp-session-id"] as string | undefined;
    if (!sessionId || !this.ctx.transports[sessionId]) {
      reply.code(400).send("Invalid or missing session ID");
      return;
    }

    try {
      reply.hijack();
      await this.ctx.transports[sessionId].handleRequest(req.raw as any, reply.raw as any);
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error("DELETE /mcp error:", err);
      if (!reply.raw.headersSent) reply.code(500).send("Internal server error");
    } finally {
      delete this.ctx.transports[sessionId];
    }
  }
}

