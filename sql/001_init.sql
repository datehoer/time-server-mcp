-- mcp-time-server: 账号 / API Key / 套餐&用户组 / 请求日志（7天留存）
-- 约定：
-- 1) 账号 email 在应用层统一转小写
-- 2) API Key 只存 sha256 哈希，不存明文
-- 3) 配额按 UTC 自然日切换

CREATE TABLE IF NOT EXISTS accounts (
  id uuid PRIMARY KEY,
  email text NOT NULL UNIQUE,
  password_hash text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  disabled_at timestamptz
);

CREATE TABLE IF NOT EXISTS api_keys (
  id uuid PRIMARY KEY,
  account_id uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  name text NOT NULL DEFAULT '',
  prefix text NOT NULL,
  key_hash text NOT NULL UNIQUE,
  secret_enc text,                       -- 方案B：明文 key 加密存库（可为空以兼容历史 key）
  created_at timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz,
  revoked_at timestamptz
);
CREATE INDEX IF NOT EXISTS api_keys_account_active_idx
  ON api_keys(account_id) WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS groups (
  id uuid PRIMARY KEY,
  name text NOT NULL UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS group_members (
  group_id uuid NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  account_id uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (group_id, account_id)
);

CREATE TABLE IF NOT EXISTS plans (
  id uuid PRIMARY KEY,
  code text NOT NULL UNIQUE,
  name text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- kind: base=取最大, addon=叠加
CREATE TABLE IF NOT EXISTS plan_grants (
  id uuid PRIMARY KEY,
  plan_id uuid NOT NULL REFERENCES plans(id) ON DELETE CASCADE,
  metric text NOT NULL,                 -- 目前先用 "requests"
  tool text,                            -- NULL 表示全局；否则为 MCP tool name
  kind text NOT NULL CHECK (kind IN ('base','addon')),
  daily_limit integer NOT NULL CHECK (daily_limit >= 0),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS plan_grants_plan_metric_tool_idx
  ON plan_grants(plan_id, metric, tool);

-- subject_type: account | group（此处不做外键，避免多态 FK 复杂化）
CREATE TABLE IF NOT EXISTS subscriptions (
  id uuid PRIMARY KEY,
  subject_type text NOT NULL CHECK (subject_type IN ('account','group')),
  subject_id uuid NOT NULL,
  plan_id uuid NOT NULL REFERENCES plans(id) ON DELETE CASCADE,
  enabled boolean NOT NULL DEFAULT true,
  starts_at timestamptz NOT NULL DEFAULT now(),
  ends_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS subscriptions_subject_idx
  ON subscriptions(subject_type, subject_id, enabled);

-- 每次 tools/call 的请求明细（保留 7 天由应用层定时清理）
CREATE TABLE IF NOT EXISTS request_logs (
  id bigserial PRIMARY KEY,
  ts timestamptz NOT NULL DEFAULT now(),
  account_id uuid,
  api_key_id uuid,
  tool text,
  allowed boolean NOT NULL,
  http_status integer NOT NULL,
  ip text
);
CREATE INDEX IF NOT EXISTS request_logs_ts_idx ON request_logs(ts);
CREATE INDEX IF NOT EXISTS request_logs_account_ts_idx ON request_logs(account_id, ts);
CREATE INDEX IF NOT EXISTS request_logs_key_ts_idx ON request_logs(api_key_id, ts);
