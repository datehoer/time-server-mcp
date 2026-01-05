import { z } from "zod";

const Bool01 = z.preprocess((v) => (v === undefined ? "1" : v), z.enum(["0", "1"])).transform((v) => v === "1");
const ReservedCookieNames = new Set(["admin_session", "admin_captcha"]);

export const AppConfigSchema = z.object({
  // 基础依赖
  DATABASE_URL: z.string().url().optional(),
  REDIS_URL: z.string().optional(),

  // 鉴权模式：
  // - env: 兼容旧的 MCP_BEARER_TOKENS
  // - db: 使用 Postgres 中的 API Key
  // - both: 两者都允许（迁移期）
  AUTH_MODE: z.enum(["env", "db", "both"]).optional(),

  // 免费默认额度（UTC 每日，仅 tools/call 计数）
  DEFAULT_FREE_DAILY_REQUEST_LIMIT: z.coerce.number().int().min(0).default(200),
  POLICY_CACHE_SECONDS: z.coerce.number().int().min(1).default(60),

  // 登录会话（用于 /me/* 管理 API Key）
  AUTH_SESSION_COOKIE_NAME: z
    .string()
    .default("sid")
    .refine((name) => !ReservedCookieNames.has(name), {
      message: "AUTH_SESSION_COOKIE_NAME 不能使用保留名：admin_session/admin_captcha（避免与 /admin 登录态冲突）",
    }),
  AUTH_SESSION_TTL_SECONDS: z.coerce.number().int().min(60).default(3 * 3600),
  AUTH_COOKIE_SECURE: Bool01,

  // 方案B：用于加密存储 API Key 明文（AES-256-GCM，32 bytes base64）
  API_KEY_ENCRYPTION_SECRET: z.string().optional(),

  // 验证码（注册/登录/后台登录）
  CAPTCHA_SESSION_SECRET: z.string().optional(),
  CAPTCHA_TTL_SECONDS: z.coerce.number().int().min(30).default(180),
  CAPTCHA_LENGTH: z.coerce.number().int().min(4).max(10).default(6),
  CAPTCHA_IGNORE_CASE: Bool01,

  // 请求日志
  REQUEST_LOG_RETENTION_DAYS: z.coerce.number().int().min(1).default(7),
  REQUEST_LOG_FLUSH_EVERY_MS: z.coerce.number().int().min(200).default(1000),
  REQUEST_LOG_MAX_BUFFER: z.coerce.number().int().min(50).default(200),
});

export type AppConfig = z.infer<typeof AppConfigSchema>;

export function loadConfig(env: NodeJS.ProcessEnv): AppConfig {
  return AppConfigSchema.parse({
    DATABASE_URL: env.DATABASE_URL,
    REDIS_URL: env.REDIS_URL,
    AUTH_MODE: env.AUTH_MODE,
    DEFAULT_FREE_DAILY_REQUEST_LIMIT: env.DEFAULT_FREE_DAILY_REQUEST_LIMIT,
    POLICY_CACHE_SECONDS: env.POLICY_CACHE_SECONDS,
    AUTH_SESSION_COOKIE_NAME: env.AUTH_SESSION_COOKIE_NAME,
    AUTH_SESSION_TTL_SECONDS: env.AUTH_SESSION_TTL_SECONDS,
    AUTH_COOKIE_SECURE: env.AUTH_COOKIE_SECURE,
    API_KEY_ENCRYPTION_SECRET: env.API_KEY_ENCRYPTION_SECRET,
    CAPTCHA_SESSION_SECRET: env.CAPTCHA_SESSION_SECRET,
    CAPTCHA_TTL_SECONDS: env.CAPTCHA_TTL_SECONDS,
    CAPTCHA_LENGTH: env.CAPTCHA_LENGTH,
    CAPTCHA_IGNORE_CASE: env.CAPTCHA_IGNORE_CASE,
    REQUEST_LOG_RETENTION_DAYS: env.REQUEST_LOG_RETENTION_DAYS,
    REQUEST_LOG_FLUSH_EVERY_MS: env.REQUEST_LOG_FLUSH_EVERY_MS,
    REQUEST_LOG_MAX_BUFFER: env.REQUEST_LOG_MAX_BUFFER,
  });
}
