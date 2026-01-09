import { Injectable, Logger, OnModuleDestroy, OnModuleInit } from "@nestjs/common";
import { createHash, randomUUID } from "node:crypto";
import { createRequire } from "node:module";
import { createClient, type RedisClientType } from "redis";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { createDb, type Db } from "./db.js";
import { loadConfig, type AppConfig } from "./config.js";
import { createFixedWindowPerMinuteLimiter, createInMemoryCounterStore, createInMemorySseLimiter, createRedisCounterStore, createRedisSseLimiter } from "./limits.js";
import { createRequestLogBuffer } from "./requestLog.js";
import { createApiKeyLastUsedTracker } from "./lastUsed.js";
import { safeEqual, getClientIp } from "./httpUtil.js";
import { createMcpServer } from "./mcpTools.js";

@Injectable()
export class AppContextService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(AppContextService.name);

  cfg: AppConfig;
  redis: RedisClientType | null = null;
  db: Db | null = null;

  // MCP
  mcpServer = createMcpServer();
  transports: Record<string, StreamableHTTPServerTransport> = {};

  // Auth mode
  authMode: "env" | "db" | "both";
  envAuthEnabled: boolean;
  dbAuthEnabled: boolean;

  // Env Bearer tokens（兼容旧模式）
  bearerTokens: string[] = [];
  bearerTokenIds: string[] = [];
  bearerTokenLastUsedMsById = new Map<string, number>();

  // Limits
  rateLimitPerMinute = Number(process.env.RATE_LIMIT_PER_IP_PER_MINUTE ?? 120);
  sseMaxConnsPerIp = Number(process.env.SSE_MAX_CONNS_PER_IP ?? 5);
  sseMaxAgeMs = Number(process.env.SSE_MAX_AGE_MS ?? 2 * 60_000);
  sseHeartbeatMs = Number(process.env.SSE_HEARTBEAT_MS ?? 25_000);

  rateLimiter = createFixedWindowPerMinuteLimiter({
    store: createInMemoryCounterStore(),
    keyPrefix: "mcp:rl",
    limitPerMinute: this.rateLimitPerMinute,
  });
  sseLimiter = createInMemorySseLimiter({ maxConnsPerIp: this.sseMaxConnsPerIp, maxAgeMs: this.sseMaxAgeMs });

  requestLog: ReturnType<typeof createRequestLogBuffer> | null = null;
  apiKeyLastUsed: ReturnType<typeof createApiKeyLastUsedTracker> | null = null;

  // Admin
  adminUser = process.env.ADMIN_USERNAME ?? "";
  adminPass = process.env.ADMIN_PASSWORD ?? "";
  adminCookieSecret = process.env.ADMIN_COOKIE_SECRET ?? "";
  adminDbSnapshot: any = null;
  private adminRefreshTimer: NodeJS.Timeout | null = null;

  // Assets
  echartsDistPath: string | null = null;

  constructor() {
    this.cfg = loadConfig(process.env);

    // DB/Redis 依赖在 onModuleInit 中完成连接与校验
    this.db = this.cfg.DATABASE_URL ? createDb(this.cfg.DATABASE_URL) : null;

    // AUTH_MODE 默认：配置了 DATABASE_URL 则走 db；否则走 env（兼容旧 MCP_BEARER_TOKENS）
    this.authMode = (this.cfg.AUTH_MODE ?? (this.db ? "db" : "env")) as "env" | "db" | "both";
    this.envAuthEnabled = this.authMode === "env" || this.authMode === "both";
    this.dbAuthEnabled = this.authMode === "db" || this.authMode === "both";
  }

  get adminEnabled() {
    return Boolean(this.adminUser && this.adminPass && this.adminCookieSecret && this.redis);
  }

  get dashboardEnabled() {
    return this.dbAuthEnabled && Boolean(this.db) && Boolean(this.redis);
  }

  bearerTokenId(token: string) {
    return createHash("sha256").update(token).digest("hex").slice(0, 12);
  }

  async onModuleInit() {
    // Redis
    const redisUrl = this.cfg.REDIS_URL;
    this.redis = redisUrl ? createClient({ url: redisUrl }) : null;
    this.redis?.on("error", (err) => this.logger.error(`Redis error: ${String(err?.message ?? err)}`));
    if (this.redis) await this.redis.connect();

    // 启用 dbAuth 必须具备 DB + Redis（会话/配额/日志）
    if (this.dbAuthEnabled && !this.db) {
      throw new Error("AUTH_MODE=db|both requires DATABASE_URL (PostgreSQL).");
    }
    if (this.dbAuthEnabled && !this.redis) {
      throw new Error("AUTH_MODE=db|both requires REDIS_URL (Redis) for session + quota.");
    }
    if (this.dbAuthEnabled && !this.cfg.API_KEY_ENCRYPTION_SECRET) {
      throw new Error("AUTH_MODE=db|both requires API_KEY_ENCRYPTION_SECRET (32 bytes base64).");
    }

    // Admin 开启需要 Redis（验证码）
    if (this.adminUser && this.adminPass && this.adminCookieSecret && !this.redis) {
      this.logger.warn("Admin dashboard disabled: set REDIS_URL (required for captcha).");
    }

    // Rate limiter & SSE limiter：优先用 Redis（多实例部署一致），否则内存
    const counterStore = this.redis ? createRedisCounterStore(this.redis as any) : createInMemoryCounterStore();
    this.rateLimiter = createFixedWindowPerMinuteLimiter({
      store: counterStore,
      keyPrefix: "mcp:rl",
      limitPerMinute: this.rateLimitPerMinute,
    });
    this.sseLimiter = this.redis
      ? createRedisSseLimiter({
          redis: this.redis as any,
          keyPrefix: "mcp:sse",
          maxConnsPerIp: this.sseMaxConnsPerIp,
          maxAgeMs: this.sseMaxAgeMs,
          ttlSeconds: Math.max(120, Math.ceil(this.sseMaxAgeMs / 1000) * 3),
        })
      : createInMemorySseLimiter({ maxConnsPerIp: this.sseMaxConnsPerIp, maxAgeMs: this.sseMaxAgeMs });

    // Env Bearer tokens
    this.bearerTokens = this.envAuthEnabled
      ? (process.env.MCP_BEARER_TOKENS ?? process.env.MCP_BEARER_TOKEN ?? "")
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean)
      : [];
    if (this.envAuthEnabled && this.bearerTokens.length === 0) {
      this.logger.warn("Env Bearer auth enabled but no tokens set: set MCP_BEARER_TOKENS (or MCP_BEARER_TOKEN).");
    }
    this.bearerTokenIds = this.bearerTokens.map((t) => this.bearerTokenId(t));

    // Request logs & API key last used
    this.requestLog =
      this.db && this.redis
        ? createRequestLogBuffer({
            db: this.db,
            maxBuffer: this.cfg.REQUEST_LOG_MAX_BUFFER,
            flushEveryMs: this.cfg.REQUEST_LOG_FLUSH_EVERY_MS,
            retentionDays: this.cfg.REQUEST_LOG_RETENTION_DAYS,
          })
        : null;
    this.apiKeyLastUsed = this.db ? createApiKeyLastUsedTracker({ db: this.db, flushEveryMs: 30_000 }) : null;

    // Admin DB snapshot（用于 /admin 页面概览）
    if (this.db) {
      const refresh = async () => {
        try {
          const now = new Date();
          const dayStart = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), 0, 0, 0));
          const dayEnd = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 1, 0, 0, 0));
          const last7Start = new Date(dayStart);
          last7Start.setUTCDate(last7Start.getUTCDate() - 6);

          const accounts = await this.db!.query<{ n: string }>("SELECT COUNT(*)::text AS n FROM accounts");
          const activeKeys = await this.db!.query<{ n: string }>("SELECT COUNT(*)::text AS n FROM api_keys WHERE revoked_at IS NULL");
          const todayTotals = await this.db!.query<{ allowed: string; denied: string }>(
            `
SELECT
  SUM(CASE WHEN allowed THEN 1 ELSE 0 END)::text AS allowed,
  SUM(CASE WHEN NOT allowed THEN 1 ELSE 0 END)::text AS denied
FROM request_logs
WHERE ts >= $1 AND ts < $2
`,
            [dayStart.toISOString(), dayEnd.toISOString()],
          );

          const hourlyTotals = await this.db!.query<{ hour_utc: number | string; allowed: string | null; denied: string | null }>(
            `
SELECT
  EXTRACT(HOUR FROM ts AT TIME ZONE 'UTC')::int AS hour_utc,
  SUM(CASE WHEN allowed THEN 1 ELSE 0 END)::text AS allowed,
  SUM(CASE WHEN NOT allowed THEN 1 ELSE 0 END)::text AS denied
FROM request_logs
WHERE ts >= $1 AND ts < $2
GROUP BY 1
ORDER BY 1
`,
            [dayStart.toISOString(), dayEnd.toISOString()],
          );

          const dailyTotalsLast7 = await this.db!.query<{ day_utc: string; allowed: string | null; denied: string | null }>(
            `
SELECT
  to_char(ts AT TIME ZONE 'UTC', 'YYYYMMDD') AS day_utc,
  SUM(CASE WHEN allowed THEN 1 ELSE 0 END)::text AS allowed,
  SUM(CASE WHEN NOT allowed THEN 1 ELSE 0 END)::text AS denied
FROM request_logs
WHERE ts >= $1 AND ts < $2
GROUP BY 1
ORDER BY 1
`,
            [last7Start.toISOString(), dayEnd.toISOString()],
          );

          const topKeys = await this.db!.query<{ api_key_id: string; allowed: string; denied: string }>(
            `
SELECT
  api_key_id,
  SUM(CASE WHEN allowed THEN 1 ELSE 0 END)::text AS allowed,
  SUM(CASE WHEN NOT allowed THEN 1 ELSE 0 END)::text AS denied
FROM request_logs
WHERE ts >= $1 AND ts < $2 AND api_key_id IS NOT NULL
GROUP BY api_key_id
ORDER BY (SUM(CASE WHEN allowed THEN 1 ELSE 0 END)) DESC
LIMIT 10
`,
            [dayStart.toISOString(), dayEnd.toISOString()],
          );

          const keyMeta =
            topKeys.rows.length > 0
              ? await this.db!.query<{ id: string; prefix: string; name: string; account_id: string; last_used_at: string | null }>(
                  `SELECT id, prefix, name, account_id, last_used_at FROM api_keys WHERE id = ANY($1::uuid[])`,
                  [topKeys.rows.map((r) => r.api_key_id)],
                )
              : { rows: [] as any[] };
          const metaById = new Map<string, any>(keyMeta.rows.map((r) => [r.id, r]));

          // 折线图：按 UTC 补齐缺口（便于前端直接渲染）
          const hourBuckets = new Map<number, { allowed: number; denied: number }>();
          for (const r of hourlyTotals.rows) {
            const hour = Number(r.hour_utc);
            if (!Number.isFinite(hour) || hour < 0 || hour > 23) continue;
            hourBuckets.set(hour, { allowed: Number(r.allowed ?? "0"), denied: Number(r.denied ?? "0") });
          }
          const hourlyLabels = Array.from({ length: 24 }, (_, h) => `${String(h).padStart(2, "0")}:00`);
          const hourlyAllowed = hourlyLabels.map((_, h) => hourBuckets.get(h)?.allowed ?? 0);
          const hourlyDenied = hourlyLabels.map((_, h) => hourBuckets.get(h)?.denied ?? 0);

          const dayBuckets = new Map<string, { allowed: number; denied: number }>();
          for (const r of dailyTotalsLast7.rows) {
            const key = String(r.day_utc ?? "");
            if (!key) continue;
            dayBuckets.set(key, { allowed: Number(r.allowed ?? "0"), denied: Number(r.denied ?? "0") });
          }
          const dailyLabels = Array.from({ length: 7 }, (_, i) => {
            const d = new Date(last7Start);
            d.setUTCDate(d.getUTCDate() + i);
            return `${d.getUTCFullYear()}${String(d.getUTCMonth() + 1).padStart(2, "0")}${String(d.getUTCDate()).padStart(2, "0")}`;
          });
          const dailyAllowed = dailyLabels.map((k) => dayBuckets.get(k)?.allowed ?? 0);
          const dailyDenied = dailyLabels.map((k) => dayBuckets.get(k)?.denied ?? 0);

          this.adminDbSnapshot = {
            utc_day: dailyLabels[dailyLabels.length - 1] ?? "",
            accounts: Number(accounts.rows[0]?.n ?? "0"),
            active_api_keys: Number(activeKeys.rows[0]?.n ?? "0"),
            tool_calls_today: {
              allowed: Number(todayTotals.rows[0]?.allowed ?? "0"),
              denied: Number(todayTotals.rows[0]?.denied ?? "0"),
            },
            tool_calls_hourly_today: { labels: hourlyLabels, allowed: hourlyAllowed, denied: hourlyDenied },
            tool_calls_daily_last_7d: { labels: dailyLabels, allowed: dailyAllowed, denied: dailyDenied },
            top_api_keys_today: topKeys.rows.map((r) => {
              const meta = metaById.get(r.api_key_id);
              return {
                api_key_id: r.api_key_id,
                prefix: meta?.prefix ?? "",
                name: meta?.name ?? "",
                account_id: meta?.account_id ?? "",
                last_used_at: meta?.last_used_at ?? null,
                allowed: Number(r.allowed ?? "0"),
                denied: Number(r.denied ?? "0"),
              };
            }),
          };
        } catch {
          this.adminDbSnapshot = null;
        }
      };

      refresh().catch(() => {});
      this.adminRefreshTimer = setInterval(() => refresh().catch(() => {}), 15_000);
      this.adminRefreshTimer.unref?.();
    }

    // ECharts 静态资源（node_modules 内部文件）
    const require = createRequire(__filename);
    try {
      this.echartsDistPath = require.resolve("echarts/dist/echarts.min.js");
    } catch {
      this.echartsDistPath = null;
      this.logger.warn("ECharts asset disabled: run `pnpm add echarts` to enable /assets/echarts.min.js.");
    }
  }

  async onModuleDestroy() {
    this.adminRefreshTimer && clearInterval(this.adminRefreshTimer);
    await this.mcpServer.close();
    await this.requestLog?.close();
    await this.apiKeyLastUsed?.close();
    await this.db?.close();
    await this.redis?.quit();
  }

  async enforceRateLimit(req: { headers: Record<string, unknown>; socket?: any; ip?: string }, reply: { header: any; code: any; send: any }) {
    const ip = getClientIp(req);
    const r = await this.rateLimiter.check([ip]);
    if (r.allowed) return true;
    reply.header("Retry-After", String(r.retryAfterSeconds));
    reply.code(429).send("Too Many Requests");
    return false;
  }

  requireBearerEnv(req: { headers: Record<string, unknown> }, reply: { code: any; send: any }) {
    if (this.bearerTokens.length === 0) {
      reply.code(500).send("Server auth misconfigured");
      return false;
    }
    const auth = String((req.headers["authorization"] ?? req.headers["Authorization"]) ?? "");
    const prefix = "Bearer ";
    if (!auth.startsWith(prefix)) {
      reply.code(401).send("Unauthorized");
      return false;
    }
    const token = auth.slice(prefix.length);
    let matchedId: string | null = null;
    for (let i = 0; i < this.bearerTokens.length; i++) {
      if (safeEqual(this.bearerTokens[i]!, token)) matchedId = this.bearerTokenIds[i] ?? null;
    }
    if (!matchedId) {
      reply.code(401).send("Unauthorized");
      return false;
    }
    this.bearerTokenLastUsedMsById.set(matchedId, Date.now());
    return true;
  }

  newSessionId() {
    return randomUUID();
  }
}
