import express, { Request, Response } from "express";
import { createHash, randomUUID } from "node:crypto";
import { DateTime, DurationLikeObject } from "luxon";
import { z } from "zod";
import { createClient } from "redis";

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { getClientIp, safeEqual } from "./httpUtil.js";
import {
  createFixedWindowPerMinuteLimiter,
  createInMemoryCounterStore,
  createInMemorySseLimiter,
  createRedisCounterStore,
  createRedisSseLimiter,
} from "./limits.js";
import { registerAdminRoutes } from "./admin.js";

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

const app = express();
app.set("trust proxy", Number(process.env.TRUST_PROXY_HOPS ?? 1));

const MCP_BODY_LIMIT = process.env.MCP_BODY_LIMIT ?? "512kb";
app.use("/mcp", express.json({ limit: MCP_BODY_LIMIT, type: ["application/json", "application/*+json"] }));
app.use("/admin", express.urlencoded({ extended: false, limit: "16kb" }));
app.use("/admin", express.json({ limit: "16kb" }));

// sessionId -> transport
const transports: Record<string, StreamableHTTPServerTransport> = {};

const redisUrl = process.env.REDIS_URL;
const redis = redisUrl ? createClient({ url: redisUrl }) : null;
redis?.on("error", (err) => console.error("Redis error:", err));
if (redis) await redis.connect();

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

const bearerTokens = (process.env.MCP_BEARER_TOKENS ?? process.env.MCP_BEARER_TOKEN ?? "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);
if (bearerTokens.length === 0) {
  console.warn("Bearer auth disabled: set MCP_BEARER_TOKENS (or MCP_BEARER_TOKEN) to protect /mcp.");
}

function bearerTokenId(token: string) {
  return createHash("sha256").update(token).digest("hex").slice(0, 12);
}

const bearerTokenIds = bearerTokens.map(bearerTokenId);
const bearerTokenLastUsedMsById = new Map<string, number>();

function requireBearer(req: Request, res: Response) {
  if (bearerTokens.length === 0) return true;
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

app.get("/health", (req: Request, res: Response) => {
  res.status(200).json({
    ok: true,
    uptime_s: Math.floor(process.uptime()),
    transports: Object.keys(transports).length,
    redis: Boolean(redis),
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
      auth: {
        bearer_enabled: bearerTokens.length > 0,
        bearer_token_count: bearerTokens.length,
        bearer_tokens: bearerTokenIds.map((id) => ({
          id,
          last_used_iso: bearerTokenLastUsedMsById.has(id) ? new Date(bearerTokenLastUsedMsById.get(id)!).toISOString() : null,
        })),
      },
    }),
  );
} else {
  console.warn("Admin dashboard disabled: set ADMIN_USERNAME, ADMIN_PASSWORD, ADMIN_COOKIE_SECRET to enable /admin.");
}

// POST: client requests (including initialize)
app.post("/mcp", async (req: Request, res: Response) => {
  if (!(await enforceRateLimit(req, res))) return;
  if (!requireBearer(req, res)) return;
  try {
    const sessionId = req.headers["mcp-session-id"] as string | undefined;

    // 1) 已有 session：复用 transport
    if (sessionId && transports[sessionId]) {
      await transports[sessionId].handleRequest(req, res, req.body);
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
  }
});

// GET: establish SSE stream for server-to-client messages
app.get("/mcp", async (req: Request, res: Response) => {
  if (!(await enforceRateLimit(req, res))) return;
  if (!requireBearer(req, res)) return;
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
  if (!requireBearer(req, res)) return;
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
  await redis?.quit();
  process.exit(0);
}

process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));
