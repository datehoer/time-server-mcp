import express, { Request, Response } from "express";
import cookieParser from "cookie-parser";
import { createHash, randomUUID } from "node:crypto";
import { DateTime, DurationLikeObject } from "luxon";
import { z } from "zod";
import { createClient } from "redis";

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { getClientIp, safeEqual } from "./httpUtil.js";
import { loadConfig } from "./config.js";
import { createDb, type Db } from "./db.js";
import {
  createFixedWindowPerMinuteLimiter,
  createInMemoryCounterStore,
  createInMemorySseLimiter,
  createRedisCounterStore,
  createRedisSseLimiter,
} from "./limits.js";
import { registerAdminRoutes } from "./admin.js";
import { registerAuthRoutes } from "./auth.js";
import { registerMeRoutes } from "./me.js";
import { registerDashboardRoutes } from "./dashboard.js";
import { requireApiKey } from "./mcpAuth.js";
import { incrDailyIfBelow, incrDailyPairIfBelow, secondsUntilNextUtcDay, utcDayKey } from "./mcpQuota.js";
import { getGlobalDailyLimitCached, getToolDailyLimitCached } from "./quota.js";
import { createRequestLogBuffer } from "./requestLog.js";
import { createApiKeyLastUsedTracker } from "./lastUsed.js";

/* -----------------------------
 * Helpers
 * ----------------------------- */

function assertIanaZone(tz: string) {
  const dt = DateTime.now().setZone(tz);
  if (!dt.isValid) throw new Error(`Invalid IANA timezone: ${tz}`);
}

type FormatKey =
  | "iso"
  | "rfc3339"
  | "epoch_ms"
  | "epoch_s"
  | "date"
  | "time"
  | "readable"
  | "offset"
  | "zone";

const FormatKeySchema = z.enum([
  "iso",
  "rfc3339",
  "epoch_ms",
  "epoch_s",
  "date",
  "time",
  "readable",
  "offset",
  "zone",
]);

function normalizeFormats(formats?: FormatKey[]) {
  // 默认：模型/程序最常用、最稳定的输出
  return formats?.length ? formats : (["iso", "epoch_ms", "readable", "offset", "zone"] as FormatKey[]);
}

function formatInZone(dtUtc: DateTime, tz: string, formats: FormatKey[]) {
  assertIanaZone(tz);

  const local = dtUtc.setZone(tz);
  const want = new Set(formats);

  const out: Record<string, string | number> = { timezone: tz };

  if (want.has("iso")) out.iso = local.toISO() ?? "";
  if (want.has("rfc3339")) out.rfc3339 = local.toISO({ suppressMilliseconds: false }) ?? "";
  if (want.has("epoch_ms")) out.epoch_ms = local.toMillis();
  if (want.has("epoch_s")) out.epoch_s = Math.floor(local.toSeconds());
  if (want.has("date")) out.date = local.toFormat("yyyy-LL-dd");
  if (want.has("time")) out.time = local.toFormat("HH:mm:ss");
  if (want.has("offset")) out.offset = local.toFormat("ZZ");
  if (want.has("zone")) out.zone = local.zoneName ?? "";
  if (want.has("readable")) out.readable = local.toFormat("yyyy-LL-dd HH:mm:ss ZZZZ");

  return out;
}

const TimeInputSchema = z.object({
  type: z.enum(["iso", "epoch_ms", "epoch_s"]),
  value: z.union([z.string(), z.number()]),
  input_timezone: z.string().optional(), // iso 且不带 offset 时使用
});

type TimeInput = z.infer<typeof TimeInputSchema>;

function parseToUtc(input: TimeInput): DateTime {
  if (input.type === "epoch_ms") {
    if (typeof input.value !== "number") throw new Error("epoch_ms value must be a number");
    return DateTime.fromMillis(input.value, { zone: "utc" });
  }
  if (input.type === "epoch_s") {
    if (typeof input.value !== "number") throw new Error("epoch_s value must be a number");
    return DateTime.fromSeconds(input.value, { zone: "utc" });
  }

  // iso
  if (typeof input.value !== "string") throw new Error("iso value must be a string");
  const s = input.value;

  // 1) 如果字符串自带 offset/zone，按自带解析并转 UTC
  //    简单判断：末尾 Z 或 ±hh:mm
  const hasOffset = /[zZ]$|[+-]\d{2}:\d{2}$/.test(s);
  if (hasOffset) {
    const dt = DateTime.fromISO(s, { setZone: true });
    if (!dt.isValid) throw new Error(`Invalid ISO time: ${s}`);
    return dt.toUTC();
  }

  // 2) 否则用 input_timezone 补全
  const tz = input.input_timezone ?? "UTC";
  assertIanaZone(tz);
  const dt = DateTime.fromISO(s, { zone: tz });
  if (!dt.isValid) throw new Error(`Invalid ISO time: ${s}`);
  return dt.toUTC();
}

/* -----------------------------
 * MCP Server
 * ----------------------------- */

const server = new McpServer({
  name: "time_server",
  version: "1.0.0",
});

// time.now
server.tool(
  "time_now",
  "Get current time (default UTC) or in a specified IANA timezone.",
  {
    timezone: z.string().describe("IANA timezone, e.g. Asia/Singapore").optional(),
    formats: z.array(FormatKeySchema).optional(),
  },
  async ({ timezone, formats }) => {
    const tz = timezone ?? "UTC";
    const f = normalizeFormats(formats);
    const nowUtc = DateTime.utc();

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(
            {
              utc_iso: nowUtc.toISO(),
              ...formatInZone(nowUtc, tz, f),
            },
            null,
            2,
          ),
        },
      ],
    };
  },
);

// time.convert
server.tool(
  "time_convert",
  "Convert a time input into multiple output timezones.",
  {
    time: TimeInputSchema.describe("Time input {type, value, input_timezone?}"),
    output_timezones: z.array(z.string()).describe("List of IANA timezones"),
    formats: z.array(FormatKeySchema).optional(),
  },
  async ({ time, output_timezones, formats }) => {
    const f = normalizeFormats(formats);
    const dtUtc = parseToUtc(time);

    const results = output_timezones.map((tz) => formatInZone(dtUtc, tz, f));

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(
            {
              base_utc_iso: dtUtc.toISO(),
              results,
            },
            null,
            2,
          ),
        },
      ],
    };
  },
);

// time.shift（一天前/一周前/任意偏移）
server.tool(
  "time_shift",
  "Shift a base time by a duration delta (negative values go to the past).",
  {
    base_time: TimeInputSchema.optional().describe("Optional base time; omit to use now()"),
    delta: z
      .object({
        weeks: z.number().optional(),
        days: z.number().optional(),
        hours: z.number().optional(),
        minutes: z.number().optional(),
        seconds: z.number().optional(),
      })
      .describe("Duration delta; e.g. {days:-1}, {weeks:-1}, {hours:2}"),
    output_timezone: z.string().describe("Output IANA timezone; default UTC").optional(),
    formats: z.array(FormatKeySchema).optional(),
  },
  async ({ base_time, delta, output_timezone, formats }) => {
    const f = normalizeFormats(formats);
    const baseUtc = base_time ? parseToUtc(base_time) : DateTime.utc();
    const shiftedUtc = baseUtc.plus(delta as DurationLikeObject);
    const tz = output_timezone ?? "UTC";

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(
            {
              base_utc_iso: baseUtc.toISO(),
              shifted_utc_iso: shiftedUtc.toISO(),
              shifted: formatInZone(shiftedUtc, tz, f),
            },
            null,
            2,
          ),
        },
      ],
    };
  },
);

// time.range（常见范围：today/this_week/last_week…）
server.tool(
  "time_range",
  "Get start/end of common ranges (today, yesterday, this_week, last_week, last_7_days) in a timezone.",
  {
    range: z.enum(["today", "yesterday", "this_week", "last_week", "last_7_days"]),
    timezone: z.string().describe("IANA timezone; default UTC").optional(),
    week_starts_on: z.number().int().min(0).max(1).optional().describe("0=Sunday, 1=Monday (default 1)"),
    formats: z.array(FormatKeySchema).optional(),
  },
  async ({ range, timezone, week_starts_on, formats }) => {
    const tz = timezone ?? "UTC";
    const f = normalizeFormats(formats);
    const wso = (week_starts_on ?? 1) as 0 | 1;

    assertIanaZone(tz);

    const nowLocal = DateTime.utc().setZone(tz);

    const startOfDay = (d: DateTime) => d.startOf("day");
    const endOfDay = (d: DateTime) => d.endOf("day");

    let startLocal: DateTime;
    let endLocal: DateTime;

    if (range === "today") {
      startLocal = startOfDay(nowLocal);
      endLocal = endOfDay(nowLocal);
    } else if (range === "yesterday") {
      const y = nowLocal.minus({ days: 1 });
      startLocal = startOfDay(y);
      endLocal = endOfDay(y);
    } else if (range === "last_7_days") {
      // 自然日范围：包含今天在内的最近 7 天
      startLocal = startOfDay(nowLocal.minus({ days: 6 }));
      endLocal = endOfDay(nowLocal);
    } else {
      // week: Luxon weekday 1..7 (Mon..Sun)
      const weekday = nowLocal.weekday;
      const daysSinceWeekStart = wso === 1 ? weekday - 1 : weekday % 7;
      const thisWeekStart = startOfDay(nowLocal.minus({ days: daysSinceWeekStart }));
      const thisWeekEnd = endOfDay(thisWeekStart.plus({ days: 6 }));

      if (range === "this_week") {
        startLocal = thisWeekStart;
        endLocal = thisWeekEnd;
      } else {
        const lastWeekStart = thisWeekStart.minus({ days: 7 });
        startLocal = lastWeekStart;
        endLocal = endOfDay(lastWeekStart.plus({ days: 6 }));
      }
    }

    const startUtc = startLocal.toUTC();
    const endUtc = endLocal.toUTC();

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(
            {
              timezone: tz,
              start: { utc_iso: startUtc.toISO(), ...formatInZone(startUtc, tz, f) },
              end: { utc_iso: endUtc.toISO(), ...formatInZone(endUtc, tz, f) },
            },
            null,
            2,
          ),
        },
      ],
    };
  },
);

/* -----------------------------
 * HTTP Server (Streamable HTTP + SSE)
 * ----------------------------- */

const cfg = loadConfig(process.env);

const app = express();
app.set("trust proxy", Number(process.env.TRUST_PROXY_HOPS ?? 1));
app.use(cookieParser());

const MCP_BODY_LIMIT = process.env.MCP_BODY_LIMIT ?? "512kb";
app.use("/mcp", express.json({ limit: MCP_BODY_LIMIT, type: ["application/json", "application/*+json"] }));
app.use("/admin", express.urlencoded({ extended: false, limit: "16kb" }));
app.use("/admin", express.json({ limit: "16kb" }));
app.use("/auth", express.json({ limit: "16kb" }));
app.use("/me", express.json({ limit: "16kb" }));
app.use("/dashboard", express.urlencoded({ extended: false, limit: "16kb" }));
app.use("/dashboard", express.json({ limit: "16kb" }));

// sessionId -> transport
const transports: Record<string, StreamableHTTPServerTransport> = {};

const redisUrl = cfg.REDIS_URL;
const redis = redisUrl ? createClient({ url: redisUrl }) : null;
redis?.on("error", (err) => console.error("Redis error:", err));
if (redis) await redis.connect();

const db: Db | null = cfg.DATABASE_URL ? createDb(cfg.DATABASE_URL) : null;

// AUTH_MODE 默认：配置了 DATABASE_URL 则走 db；否则走 env（兼容旧 MCP_BEARER_TOKENS）
const authMode = cfg.AUTH_MODE ?? (db ? "db" : "env");
const envAuthEnabled = authMode === "env" || authMode === "both";
const dbAuthEnabled = authMode === "db" || authMode === "both";

if (dbAuthEnabled && !db) {
  throw new Error("AUTH_MODE=db|both requires DATABASE_URL (PostgreSQL).");
}
if (dbAuthEnabled && !redis) {
  throw new Error("AUTH_MODE=db|both requires REDIS_URL (Redis) for session + quota.");
}
if (dbAuthEnabled && !cfg.API_KEY_ENCRYPTION_SECRET) {
  throw new Error("AUTH_MODE=db|both requires API_KEY_ENCRYPTION_SECRET (32 bytes base64).");
}

// /admin 需要同步返回 stats；这里用后台定时刷新 DB 统计快照
let adminDbSnapshot: any = null;
if (db) {
  const refresh = async () => {
    try {
      const now = new Date();
      const dayStart = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), 0, 0, 0));
      const dayEnd = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 1, 0, 0, 0));

      const accounts = await db.query<{ n: string }>("SELECT COUNT(*)::text AS n FROM accounts");
      const activeKeys = await db.query<{ n: string }>("SELECT COUNT(*)::text AS n FROM api_keys WHERE revoked_at IS NULL");
      const todayTotals = await db.query<{ allowed: string; denied: string }>(
        `
SELECT
  SUM(CASE WHEN allowed THEN 1 ELSE 0 END)::text AS allowed,
  SUM(CASE WHEN NOT allowed THEN 1 ELSE 0 END)::text AS denied
FROM request_logs
WHERE ts >= $1 AND ts < $2
`,
        [dayStart.toISOString(), dayEnd.toISOString()],
      );

      const topKeys = await db.query<{ api_key_id: string; allowed: string; denied: string }>(
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
          ? await db.query<{ id: string; prefix: string; name: string; account_id: string; last_used_at: string | null }>(
              `SELECT id, prefix, name, account_id, last_used_at FROM api_keys WHERE id = ANY($1::uuid[])`,
              [topKeys.rows.map((r) => r.api_key_id)],
            )
          : { rows: [] as any[] };

      const metaById = new Map<string, any>(keyMeta.rows.map((r) => [r.id, r]));
      adminDbSnapshot = {
        utc_day: utcDayKey(now),
        accounts: Number(accounts.rows[0]?.n ?? "0"),
        active_api_keys: Number(activeKeys.rows[0]?.n ?? "0"),
        tool_calls_today: {
          allowed: Number(todayTotals.rows[0]?.allowed ?? "0"),
          denied: Number(todayTotals.rows[0]?.denied ?? "0"),
        },
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
      // DB 未初始化/不可用时不影响服务启动
      adminDbSnapshot = null;
    }
  };
  refresh().catch(() => {});
  const timer = setInterval(() => refresh().catch(() => {}), 15_000);
  timer.unref?.();
}

const rateLimitPerMinute = Number(process.env.RATE_LIMIT_PER_IP_PER_MINUTE ?? 120);
const sseMaxConnsPerIp = Number(process.env.SSE_MAX_CONNS_PER_IP ?? 5);
const sseMaxAgeMs = Number(process.env.SSE_MAX_AGE_MS ?? 2 * 60_000);
const sseHeartbeatMs = Number(process.env.SSE_HEARTBEAT_MS ?? 25_000);

const counterStore = redis ? createRedisCounterStore(redis) : createInMemoryCounterStore();
const rateLimiter = createFixedWindowPerMinuteLimiter({
  store: counterStore,
  keyPrefix: "mcp:rl",
  limitPerMinute: rateLimitPerMinute,
});

const sseLimiter = redis
  ? createRedisSseLimiter({
      redis,
      keyPrefix: "mcp:sse",
      maxConnsPerIp: sseMaxConnsPerIp,
      maxAgeMs: sseMaxAgeMs,
      ttlSeconds: Math.max(120, Math.ceil(sseMaxAgeMs / 1000) * 3),
    })
  : createInMemorySseLimiter({ maxConnsPerIp: sseMaxConnsPerIp, maxAgeMs: sseMaxAgeMs });

const bearerTokens = envAuthEnabled
  ? (process.env.MCP_BEARER_TOKENS ?? process.env.MCP_BEARER_TOKEN ?? "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean)
  : [];
if (envAuthEnabled && bearerTokens.length === 0) {
  console.warn("Env Bearer auth enabled but no tokens set: set MCP_BEARER_TOKENS (or MCP_BEARER_TOKEN).");
}

function bearerTokenId(token: string) {
  return createHash("sha256").update(token).digest("hex").slice(0, 12);
}

const bearerTokenIds = bearerTokens.map(bearerTokenId);
const bearerTokenLastUsedMsById = new Map<string, number>();

function requireBearerEnv(req: Request, res: Response) {
  if (bearerTokens.length === 0) {
    res.status(500).send("Server auth misconfigured");
    return false;
  }
  const auth = req.header("authorization") ?? "";
  const prefix = "Bearer ";
  if (!auth.startsWith(prefix)) {
    res.status(401).send("Unauthorized");
    return false;
  }
  const token = auth.slice(prefix.length);
  let matchedId: string | null = null;
  for (let i = 0; i < bearerTokens.length; i++) {
    if (safeEqual(bearerTokens[i]!, token)) matchedId = bearerTokenIds[i] ?? null;
  }
  if (!matchedId) {
    res.status(401).send("Unauthorized");
    return false;
  }
  bearerTokenLastUsedMsById.set(matchedId, Date.now());
  return true;
}

async function enforceRateLimit(req: Request, res: Response) {
  const ip = getClientIp(req);
  const r = await rateLimiter.check([ip]);
  if (r.allowed) return true;
  res.setHeader("Retry-After", String(r.retryAfterSeconds));
  res.status(429).send("Too Many Requests");
  return false;
}

const ToolsCallSchema = z
  .object({
    method: z.literal("tools/call"),
    params: z.object({ name: z.string() }).passthrough(),
    id: z.any().optional(),
  })
  .passthrough();

app.get("/health", (req: Request, res: Response) => {
  res.status(200).json({
    ok: true,
    uptime_s: Math.floor(process.uptime()),
    transports: Object.keys(transports).length,
    redis: Boolean(redis),
    db: Boolean(db),
    auth: { mode: authMode, env_enabled: envAuthEnabled, db_enabled: dbAuthEnabled },
  });
});

const adminUser = process.env.ADMIN_USERNAME ?? "";
const adminPass = process.env.ADMIN_PASSWORD ?? "";
const adminCookieSecret = process.env.ADMIN_COOKIE_SECRET ?? "";
if (adminUser && adminPass && adminCookieSecret) {
  registerAdminRoutes(
    app,
    {
      username: adminUser,
      password: adminPass,
      cookieSecret: adminCookieSecret,
      cookieSecure: (process.env.ADMIN_COOKIE_SECURE ?? "1") !== "0",
      sessionTtlSeconds: Number(process.env.ADMIN_SESSION_TTL_SECONDS ?? 7 * 24 * 3600),
    },
    () => ({
      ok: true,
      uptime_s: Math.floor(process.uptime()),
      transports: Object.keys(transports).length,
      limits: { rate_limit_per_ip_per_minute: rateLimitPerMinute, sse_max_conns_per_ip: sseMaxConnsPerIp },
      redis: Boolean(redis),
      db: Boolean(db),
      quota: {
        timezone: "UTC",
        counts: "tools/call",
        default_free_daily_request_limit: cfg.DEFAULT_FREE_DAILY_REQUEST_LIMIT,
      },
      db_stats: adminDbSnapshot,
      auth: {
        mode: authMode,
        env_bearer_enabled: envAuthEnabled && bearerTokens.length > 0,
        env_bearer_token_count: bearerTokens.length,
        env_bearer_tokens: bearerTokenIds.map((id) => ({
          id,
          last_used_iso: bearerTokenLastUsedMsById.has(id) ? new Date(bearerTokenLastUsedMsById.get(id)!).toISOString() : null,
        })),
      },
    }),
  );
} else {
  console.warn("Admin dashboard disabled: set ADMIN_USERNAME, ADMIN_PASSWORD, ADMIN_COOKIE_SECRET to enable /admin.");
}

// 账号体系（/auth + /me）只在 dbAuth 模式下启用
if (dbAuthEnabled && db && redis) {
  registerAuthRoutes(app, {
    db,
    redis,
    cookieName: cfg.AUTH_SESSION_COOKIE_NAME,
    ttlSeconds: cfg.AUTH_SESSION_TTL_SECONDS,
    cookieSecure: cfg.AUTH_COOKIE_SECURE,
  });
  registerMeRoutes(app, {
    db,
    redis,
    cookieName: cfg.AUTH_SESSION_COOKIE_NAME,
    maxKeysPerAccount: 10,
    encryptionSecret: cfg.API_KEY_ENCRYPTION_SECRET!,
  });
  registerDashboardRoutes(app, {
    db,
    redis,
    cookieName: cfg.AUTH_SESSION_COOKIE_NAME,
    ttlSeconds: cfg.AUTH_SESSION_TTL_SECONDS,
    cookieSecure: cfg.AUTH_COOKIE_SECURE,
  });
} else {
  console.warn("Account/API key management disabled: set DATABASE_URL, REDIS_URL and AUTH_MODE=db to enable /auth and /me.");
}

// 请求日志（仅 tools/call）。若未启用 DB，则不记录。
const requestLog =
  db && redis
    ? createRequestLogBuffer({
        db,
        maxBuffer: cfg.REQUEST_LOG_MAX_BUFFER,
        flushEveryMs: cfg.REQUEST_LOG_FLUSH_EVERY_MS,
        retentionDays: cfg.REQUEST_LOG_RETENTION_DAYS,
      })
    : null;

const apiKeyLastUsed = db ? createApiKeyLastUsedTracker({ db, flushEveryMs: 30_000 }) : null;

// POST: client requests (including initialize)
app.post("/mcp", async (req: Request, res: Response) => {
  if (!(await enforceRateLimit(req, res))) return;
  const toolCall = ToolsCallSchema.safeParse(req.body);
  const toolName = toolCall.success ? toolCall.data.params.name : null;

  let accountId: string | null = null;
  let apiKeyId: string | null = null;

  // 1) DB API Key（推荐）
  if (dbAuthEnabled && db && redis) {
    const auth = await requireApiKey(req, res, { db, redis });
    if (!auth) {
      if (toolName) {
        requestLog?.push({
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
    apiKeyLastUsed?.touch(apiKeyId, Date.now());
  } else if (envAuthEnabled) {
    // 2) 兼容旧的环境变量 token（迁移期）
    if (!requireBearerEnv(req, res)) return;
  } else {
    res.status(401).send("Unauthorized");
    return;
  }

  // 配额：仅 tools/call 计数，按 UTC 日切
  if (toolName && dbAuthEnabled && db && redis) {
    const day = utcDayKey();
    const ttlSeconds = secondsUntilNextUtcDay();

    const globalLimit = await getGlobalDailyLimitCached({
      redis,
      db,
      accountId: accountId!,
      metric: "requests",
      defaultFree: cfg.DEFAULT_FREE_DAILY_REQUEST_LIMIT,
      cacheSeconds: cfg.POLICY_CACHE_SECONDS,
    });

    const toolLimit = await getToolDailyLimitCached({
      redis,
      db,
      accountId: accountId!,
      metric: "requests",
      tool: toolName,
      cacheSeconds: cfg.POLICY_CACHE_SECONDS,
    });

    const globalKey = `quota:acct:${accountId}:${day}:requests:all`;
    const toolKey = `quota:acct:${accountId}:${day}:requests:tool:${toolName}`;

    let allowed = true;
    let usedAccount = 0;
    let usedTool: number | null = null;

    if (toolLimit === null) {
      const q1 = await incrDailyIfBelow({ redis, key: globalKey, limit: globalLimit, ttlSeconds });
      allowed = q1.allowed;
      usedAccount = q1.used;
    } else {
      const q2 = await incrDailyPairIfBelow({ redis, key1: globalKey, limit1: globalLimit, key2: toolKey, limit2: toolLimit, ttlSeconds });
      allowed = q2.allowed;
      usedAccount = q2.used1;
      usedTool = q2.used2;
    }

    if (!allowed) {
      const id = toolCall.success ? toolCall.data.id ?? null : null;
      res.status(429).json({
        jsonrpc: "2.0",
        error: {
          code: -32029,
          message: "Daily quota exceeded",
          data:
            toolLimit === null
              ? { timezone: "UTC", day, scope: "account", limit: globalLimit, used: usedAccount }
              : { timezone: "UTC", day, scope: "account+tool", account_limit: globalLimit, tool_limit: toolLimit, used_account: usedAccount, used_tool: usedTool },
        },
        id,
      });
      requestLog?.push({
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
    if (sessionId && transports[sessionId]) {
      await transports[sessionId].handleRequest(req, res, req.body);
      if (toolName) {
        requestLog?.push({
          ts: new Date(),
          accountId,
          apiKeyId,
          tool: toolName,
          allowed: true,
          httpStatus: res.statusCode || 200,
          ip: getClientIp(req),
        });
      }
      return;
    }

    // 2) 无 session 且是 initialize：创建新的 transport + connect
    if (!sessionId && isInitializeRequest(req.body)) {
      let transport!: StreamableHTTPServerTransport;

      transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        onsessioninitialized: (newSessionId) => {
          transports[newSessionId] = transport;
        },
      });

      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
      if (toolName) {
        requestLog?.push({
          ts: new Date(),
          accountId,
          apiKeyId,
          tool: toolName,
          allowed: true,
          httpStatus: res.statusCode || 200,
          ip: getClientIp(req),
        });
      }
      return;
    }

    // 3) 其他情况：Bad Request
    res.status(400).json({
      jsonrpc: "2.0",
      error: { code: -32000, message: "Bad Request: No valid session ID provided" },
      id: null,
    });
  } catch (err) {
    console.error("POST /mcp error:", err);
    if (!res.headersSent) {
      res.status(500).json({
        jsonrpc: "2.0",
        error: { code: -32603, message: "Internal server error" },
        id: null,
      });
    }
    if (toolName) {
      requestLog?.push({
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
});

// GET: establish SSE stream for server-to-client messages
app.get("/mcp", async (req: Request, res: Response) => {
  if (!(await enforceRateLimit(req, res))) return;
  if (dbAuthEnabled && db && redis) {
    const auth = await requireApiKey(req, res, { db, redis });
    if (!auth) return;
    apiKeyLastUsed?.touch(auth.apiKeyId, Date.now());
  } else if (envAuthEnabled) {
    if (!requireBearerEnv(req, res)) return;
  } else {
    res.status(401).send("Unauthorized");
    return;
  }
  const sessionId = req.headers["mcp-session-id"] as string | undefined;
  if (!sessionId || !transports[sessionId]) {
    res.status(400).send("Invalid or missing session ID");
    return;
  }

  const ip = getClientIp(req);
  const acquired = await sseLimiter.tryAcquire(ip);
  if (!acquired.allowed) {
    res.setHeader("Retry-After", String(acquired.retryAfterSeconds));
    res.status(429).send(`Too Many SSE connections (active=${acquired.active})`);
    return;
  }

  const connId = acquired.connId;
  const heartbeat = setInterval(() => {
    if (res.headersSent) {
      try {
        res.write(`: ping ${Date.now()}\n\n`);
      } catch {
        // ignore
      }
    }
    sseLimiter.refresh(ip, connId).catch(() => {});
  }, sseHeartbeatMs);

  const cleanup = () => {
    clearInterval(heartbeat);
    sseLimiter.release(ip, connId).catch(() => {});
  };
  res.on("close", cleanup);
  res.on("finish", cleanup);

  try {
    await transports[sessionId].handleRequest(req, res);
  } catch (err) {
    console.error("GET /mcp error:", err);
    if (!res.headersSent) res.status(500).send("Internal server error");
  }
});

// DELETE: terminate session
app.delete("/mcp", async (req: Request, res: Response) => {
  if (!(await enforceRateLimit(req, res))) return;
  if (dbAuthEnabled && db && redis) {
    const auth = await requireApiKey(req, res, { db, redis });
    if (!auth) return;
    apiKeyLastUsed?.touch(auth.apiKeyId, Date.now());
  } else if (envAuthEnabled) {
    if (!requireBearerEnv(req, res)) return;
  } else {
    res.status(401).send("Unauthorized");
    return;
  }
  const sessionId = req.headers["mcp-session-id"] as string | undefined;
  if (!sessionId || !transports[sessionId]) {
    res.status(400).send("Invalid or missing session ID");
    return;
  }

  try {
    await transports[sessionId].handleRequest(req, res);
  } catch (err) {
    console.error("DELETE /mcp error:", err);
    if (!res.headersSent) res.status(500).send("Internal server error");
  } finally {
    delete transports[sessionId];
  }
});

const HOST = "127.0.0.1";
const PORT = Number(process.env.PORT ?? 3001);
const LISTEN_HOST = process.env.HOST ?? HOST;

app.listen(PORT, LISTEN_HOST, (err?: any) => {
  if (err) {
    console.error("Failed to start server:", err);
    process.exit(1);
  }
  console.log(`MCP time server listening on http://${LISTEN_HOST}:${PORT}/mcp`);
});

// graceful shutdown
async function shutdown(signal: string) {
  console.log(`Shutting down (${signal})...`);
  await server.close();
  await requestLog?.close();
  await apiKeyLastUsed?.close();
  await db?.close();
  await redis?.quit();
  process.exit(0);
}

process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));
