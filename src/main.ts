import "reflect-metadata";
import { NestFactory } from "@nestjs/core";
import { FastifyAdapter, type NestFastifyApplication } from "@nestjs/platform-fastify";
import cookie from "@fastify/cookie";
import fastifyStatic from "@fastify/static";
import { join } from "node:path";
import { AppModule } from "./app.module";

function parseSizeToBytes(input: string | undefined, fallbackBytes: number) {
  const s = String(input ?? "").trim().toLowerCase();
  if (!s) return fallbackBytes;
  const m = s.match(/^(\d+)(b|kb|mb)?$/);
  if (!m) return fallbackBytes;
  const n = Number(m[1]);
  const unit = m[2] ?? "b";
  if (!Number.isFinite(n) || n <= 0) return fallbackBytes;
  if (unit === "b") return n;
  if (unit === "kb") return n * 1024;
  if (unit === "mb") return n * 1024 * 1024;
  return fallbackBytes;
}

async function bootstrap() {
  const trustProxyHops = Number(process.env.TRUST_PROXY_HOPS ?? 1);
  const mcpBodyLimitBytes = parseSizeToBytes(process.env.MCP_BODY_LIMIT, 512 * 1024);

  const app = await NestFactory.create<NestFastifyApplication>(
    AppModule,
    new FastifyAdapter({
      trustProxy: trustProxyHops,
      bodyLimit: mcpBodyLimitBytes,
      // Fastify 默认 logger 过于冗长；生产环境建议用 Nest Logger/自定义。
      logger: false,
    }),
  );

  const fastify = app.getHttpAdapter().getInstance();

  // Cookie 支持（/dashboard 登录态、/admin 登录态、验证码会话）
  await fastify.register(cookie);

  // 注意：Nest FastifyAdapter 会自动注册 urlencoded parser；此处不要重复注册（否则 Fastify 会报重复 parser）。

  // 静态资源：项目 public/（logo/favicon/manifest 等）
  await fastify.register(fastifyStatic, {
    root: join(__dirname, "..", "public"),
    prefix: "/assets/",
    decorateReply: false,
    index: false,
    maxAge: 86_400_000,
  });

  // MCP 客户端可能发送 application/*+json；Fastify 默认只解析 application/json。
  fastify.addContentTypeParser(/^application\/.+\+json$/i, { parseAs: "string" }, (_req, body, done) => {
    try {
      const text = typeof body === "string" ? body : body.toString("utf8");
      done(null, text ? JSON.parse(text) : null);
    } catch (err) {
      done(err as Error, undefined);
    }
  });

  const port = Number(process.env.PORT ?? 3001);
  const host = process.env.HOST ?? "127.0.0.1";
  await app.listen(port, host);
  // eslint-disable-next-line no-console
  console.log(`MCP time server listening on http://${host}:${port}/mcp`);
}

bootstrap().catch((err) => {
  // eslint-disable-next-line no-console
  console.error("Failed to start server:", err);
  process.exit(1);
});
