-- 方案B：为已初始化库增加加密密钥字段（允许为空）
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS secret_enc text;

