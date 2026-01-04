import { createHash, randomBytes, scrypt, timingSafeEqual, type ScryptOptions } from "node:crypto";

function scryptAsync(password: string, salt: Buffer, keylen: number, options: ScryptOptions): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scrypt(password, salt, keylen, options, (err, derivedKey) => {
      if (err) return reject(err);
      resolve(derivedKey as Buffer);
    });
  });
}

// 密码：scrypt + 16B salt（避免 bcrypt 原生依赖，部署更简单）
export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16);
  const key = await scryptAsync(password, salt, 32, { N: 16384, r: 8, p: 1 });
  return `scrypt$N=16384$r=8$p=1$${salt.toString("hex")}$${key.toString("hex")}`;
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const parts = stored.split("$");
  if (parts.length !== 6 || parts[0] !== "scrypt") return false;
  const salt = Buffer.from(parts[4] ?? "", "hex");
  const expected = Buffer.from(parts[5] ?? "", "hex");
  if (salt.length !== 16 || expected.length === 0) return false;
  const key = await scryptAsync(password, salt, expected.length, { N: 16384, r: 8, p: 1 });
  return timingSafeEqual(key, expected);
}

// API Key：只存哈希，用于查找与比较
export function sha256Hex(input: string): string {
  return createHash("sha256").update(input).digest("hex");
}

// 创建 API Key 明文（仅创建时返回一次）
export function newApiKeySecret(): string {
  const raw = randomBytes(32).toString("base64url");
  return `mcp_${raw}`;
}
