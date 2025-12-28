import { createHmac, timingSafeEqual } from "node:crypto";

export function getClientIp(req: { headers: Record<string, unknown>; socket?: any; ip?: string }) {
  const cf = req.headers["cf-connecting-ip"];
  if (typeof cf === "string" && cf.trim()) return normalizeIp(cf.trim());

  const xff = req.headers["x-forwarded-for"];
  if (typeof xff === "string" && xff.trim()) {
    const first = xff.split(",")[0]?.trim();
    if (first) return normalizeIp(first);
  }

  const xrip = req.headers["x-real-ip"];
  if (typeof xrip === "string" && xrip.trim()) return normalizeIp(xrip.trim());

  if (typeof req.ip === "string" && req.ip.trim()) return normalizeIp(req.ip.trim());
  const ra = req.socket?.remoteAddress;
  if (typeof ra === "string" && ra.trim()) return normalizeIp(ra.trim());
  return "unknown";
}

export function normalizeIp(ip: string) {
  if (ip.startsWith("::ffff:")) return ip.slice("::ffff:".length);
  return ip;
}

export function parseCookies(header: string | undefined) {
  const out: Record<string, string> = {};
  if (!header) return out;
  for (const part of header.split(";")) {
    const idx = part.indexOf("=");
    if (idx === -1) continue;
    const key = part.slice(0, idx).trim();
    const value = part.slice(idx + 1).trim();
    if (!key) continue;
    out[key] = decodeURIComponent(value);
  }
  return out;
}

function base64urlEncode(buf: Buffer) {
  return buf.toString("base64").replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function base64urlDecode(s: string) {
  const padLen = (4 - (s.length % 4)) % 4;
  const padded = s.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat(padLen);
  return Buffer.from(padded, "base64");
}

export function signCookie(secret: string, payload: unknown) {
  const body = base64urlEncode(Buffer.from(JSON.stringify(payload), "utf8"));
  const sig = base64urlEncode(createHmac("sha256", secret).update(body).digest());
  return `${body}.${sig}`;
}

export function verifySignedCookie<T>(secret: string, value: string | undefined): T | null {
  if (!value) return null;
  const idx = value.lastIndexOf(".");
  if (idx === -1) return null;
  const body = value.slice(0, idx);
  const sig = value.slice(idx + 1);

  const expected = base64urlEncode(createHmac("sha256", secret).update(body).digest());
  try {
    const a = Buffer.from(sig, "utf8");
    const b = Buffer.from(expected, "utf8");
    if (a.length !== b.length) return null;
    if (!timingSafeEqual(a, b)) return null;
  } catch {
    return null;
  }

  try {
    const json = base64urlDecode(body).toString("utf8");
    return JSON.parse(json) as T;
  } catch {
    return null;
  }
}

export function safeEqual(a: string, b: string) {
  try {
    const ab = Buffer.from(a, "utf8");
    const bb = Buffer.from(b, "utf8");
    if (ab.length !== bb.length) return false;
    return timingSafeEqual(ab, bb);
  } catch {
    return false;
  }
}

