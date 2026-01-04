# Work Log

2026-01-04T02:47:46.480Z --- 增加账号/登录、API Key、配额与监控（Redis+PostgreSQL）--- 新增 Postgres 表结构(sql/001_init.sql)，引入 AUTH_MODE=db|env|both；实现 /auth、/me/api-keys；/mcp 按 UTC 日对 tools/call 做配额与 7 天游标；/admin 增加 DB/配额概览 --- 修改了 package.json pnpm-lock.yaml .env.example docker-compose.yml README.md src/index.ts src/admin.ts src/db.ts src/quota.ts src/mcpQuota.ts src/security.ts；新增 sql/001_init.sql src/config.ts src/auth.ts src/me.ts src/mcpAuth.ts src/requestLog.ts src/lastUsed.ts src/redisLike.ts work.md
