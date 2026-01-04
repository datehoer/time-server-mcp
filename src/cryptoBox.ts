import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

// 方案B：AES-256-GCM 加密/解密工具
// 存储格式：base64( iv(12) | tag(16) | ciphertext )

function decodeBase64Key(secretB64: string): Buffer {
  const key = Buffer.from(secretB64, "base64");
  if (key.length !== 32) throw new Error("API_KEY_ENCRYPTION_SECRET must be 32 bytes base64");
  return key;
}

export function encryptApiKeySecret(plain: string, secretB64: string): string {
  const key = decodeBase64Key(secretB64);
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(Buffer.from(plain, "utf8")), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, ciphertext]).toString("base64");
}

export function decryptApiKeySecret(encB64: string, secretB64: string): string {
  const key = decodeBase64Key(secretB64);
  const raw = Buffer.from(encB64, "base64");
  if (raw.length < 12 + 16 + 1) throw new Error("Invalid secret_enc");
  const iv = raw.subarray(0, 12);
  const tag = raw.subarray(12, 28);
  const ciphertext = raw.subarray(28);
  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  const plain = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return plain.toString("utf8");
}

