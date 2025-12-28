# mcp-time-server

一个基于 **Model Context Protocol (MCP)** 的时间工具服务，提供“获取当前时间 / 时区转换 / 时间偏移 / 常见时间范围”四类能力，并通过 **Streamable HTTP + SSE** 暴露为 `http://127.0.0.1:<PORT>/mcp`。

## 功能

- `time_now`：获取当前时间（默认 UTC），可指定 IANA 时区与输出格式
- `time_convert`：把一个时间输入转换到多个输出时区
- `time_shift`：对基准时间做偏移（支持负数，表示回到过去）
- `time_range`：获取常见范围的起止（today/yesterday/this_week/last_week/last_7_days）

## 快速开始

> 该项目使用 TypeScript + ESM，编译产物输出到 `dist/`，运行时入口为 `dist/index.js`。

```bash
pnpm install
pnpm build
pnpm start
```

启动后会监听：

- `http://127.0.0.1:<PORT>/mcp`（默认 `PORT=7545`）

## 环境变量

- `PORT`：监听端口（默认 `7545`）
- `HOST`：监听地址（默认 `127.0.0.1`；Docker 部署建议 `0.0.0.0`）
- `MCP_BEARER_TOKENS`：保护 `/mcp` 的 Bearer Token（逗号分隔多个）
- `REDIS_URL`：Redis 连接串（用于按 IP 限流与 SSE 并发上限）
- `MCP_BODY_LIMIT`：最大请求体（默认 `512kb`，仅对 `/mcp` 的 JSON 生效）
- `RATE_LIMIT_PER_IP_PER_MINUTE`：按 IP 每分钟请求数（默认 `120`，对 `/mcp` 的 GET/POST/DELETE 生效）
- `SSE_MAX_CONNS_PER_IP`：按 IP 最大 SSE 并发连接数（默认 `5`）
- `TRUST_PROXY_HOPS`：反代层数（默认 `1`）

可选（开启 `/admin`）：

- `ADMIN_USERNAME` / `ADMIN_PASSWORD`：Dashboard 固定账号密码
- `ADMIN_COOKIE_SECRET`：Cookie 签名密钥
- `ADMIN_COOKIE_SECURE`：是否设置 `Secure` Cookie（默认 `1`，HTTPS 站点建议保持开启）
- `ADMIN_SESSION_TTL_SECONDS`：登录态有效期（默认 7 天）

> 监听地址默认 `127.0.0.1`，可通过 `HOST` 覆盖（Docker 部署一般用 `0.0.0.0`）。

## MCP HTTP 接口

该服务使用 MCP SDK 的 `StreamableHTTPServerTransport`，并通过 Express 提供三个路由（同一路径 `/mcp`）：

- `POST /mcp`：承载客户端请求（包含 `initialize`）
  - 若请求头包含 `mcp-session-id` 且服务端已存在该会话，则复用 transport
  - 若无 `mcp-session-id` 且 body 为 `initialize`，服务端创建新会话并返回会话信息
  - 其他情况返回 `400`
- `GET /mcp`：建立 SSE（server-to-client）通道（必须带 `mcp-session-id`）
- `DELETE /mcp`：终止会话（必须带 `mcp-session-id`）

> 注意：当配置了 `MCP_BEARER_TOKENS` 时，`/mcp` 需要 `Authorization: Bearer <token>`。

## Docker Compose 部署

1) 准备 `.env`（可参考 `.env.example`）

2) 启动

```bash
docker compose up -d --build
```

默认会绑定到 `127.0.0.1:${PORT}`，配合 Nginx 反代即可。

## Nginx（SSE 友好）提示

SSE 场景建议关闭 buffering，并透传真实来源 IP 相关头（按你的环境调整）：

```nginx
location / {
  proxy_pass http://127.0.0.1:7545;
  proxy_http_version 1.1;
  proxy_buffering off;
}
```

## 数据结构与约定

### TimeInput（时间输入）

`time_convert` / `time_shift` 使用同一套输入结构：

```ts
{
  type: "iso" | "epoch_ms" | "epoch_s",
  value: string | number,
  input_timezone?: string
}
```

- `type=epoch_ms`：`value` 必须为毫秒时间戳（number）
- `type=epoch_s`：`value` 必须为秒时间戳（number）
- `type=iso`：`value` 必须为 ISO 字符串
  - 若字符串末尾自带 `Z` 或 `±hh:mm`，则按自带时区解析并转成 UTC
  - 若不带 offset，则使用 `input_timezone`（缺省为 `UTC`）补全后解析

### formats（输出格式）

多数工具都支持 `formats?: FormatKey[]`，可选值：

- `iso`：`toISO()`
- `rfc3339`：`toISO({ suppressMilliseconds: false })`
- `epoch_ms`：毫秒时间戳
- `epoch_s`：秒时间戳（向下取整）
- `date`：`yyyy-LL-dd`
- `time`：`HH:mm:ss`
- `readable`：`yyyy-LL-dd HH:mm:ss ZZZZ`
- `offset`：`ZZ`
- `zone`：Luxon `zoneName`

未传 `formats` 时，默认返回：`["iso","epoch_ms","readable","offset","zone"]`。

## 工具说明

### `time_now`

获取当前时间（默认 UTC），并在目标时区输出多种格式。

参数：

- `timezone?: string`：IANA 时区（例如 `Asia/Shanghai`），默认 `UTC`
- `formats?: FormatKey[]`：输出格式集合（可选）

输出：工具返回 `content[0].text`，其内容为 JSON 字符串，包含：

- `utc_iso`：当前 UTC 时间的 ISO
- `timezone` + 相关格式字段（由 `formats` 决定）

### `time_convert`

把一个时间输入转换到多个输出时区。

参数：

- `time: TimeInput`
- `output_timezones: string[]`：IANA 时区列表
- `formats?: FormatKey[]`

输出：`base_utc_iso`（输入解析后的 UTC 基准）与 `results[]`（每个时区的格式化结果）。

### `time_shift`

对基准时间做偏移（负数回到过去）。

参数：

- `base_time?: TimeInput`：缺省表示“现在”
- `delta: { weeks?, days?, hours?, minutes?, seconds? }`
- `output_timezone?: string`：输出时区（默认 `UTC`）
- `formats?: FormatKey[]`

输出：`base_utc_iso`、`shifted_utc_iso` 与 `shifted`（按目标时区格式化的结果）。

### `time_range`

获取常见时间范围的起止（先在目标时区计算自然日/周边界，再转回 UTC 并同时输出多格式）。

参数：

- `range: "today" | "yesterday" | "this_week" | "last_week" | "last_7_days"`
- `timezone?: string`：IANA 时区（默认 `UTC`）
- `week_starts_on?: 0 | 1`：0=周日，1=周一（默认 1）
- `formats?: FormatKey[]`

输出：`start` / `end`，每个都包含 `utc_iso` 与该时区下的格式化字段。
