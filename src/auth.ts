import type { Express, Request, Response } from "express";
import { randomUUID } from "node:crypto";
import { z } from "zod";
import type { Db } from "./db.js";
import type { RedisClientLike } from "./redisLike.js";
import { hashPassword, verifyPassword } from "./security.js";

export function registerAuthRoutes(
  app: Express,
  deps: { db: Db; redis: RedisClientLike; cookieName: string; ttlSeconds: number; cookieSecure: boolean },
) {
  const { db, redis, cookieName, ttlSeconds, cookieSecure } = deps;

  const RegisterSchema = z.object({ email: z.string().email(), password: z.string().min(8).max(200) });
  const LoginSchema = RegisterSchema;

  function setSession(res: Response, sid: string) {
    res.cookie(cookieName, sid, {
      httpOnly: true,
      sameSite: "lax",
      secure: cookieSecure,
      maxAge: ttlSeconds * 1000,
      path: "/",
    });
  }

  app.post("/auth/register", async (req: Request, res: Response) => {
    const input = RegisterSchema.safeParse(req.body);
    if (!input.success) return res.status(400).json({ ok: false, error: "Invalid input" });

    const email = input.data.email.toLowerCase();
    const passwordHash = await hashPassword(input.data.password);
    const id = randomUUID();

    try {
      await db.query("INSERT INTO accounts (id, email, password_hash) VALUES ($1,$2,$3)", [id, email, passwordHash]);
      return res.status(201).json({ ok: true });
    } catch {
      return res.status(409).json({ ok: false, error: "Email already exists" });
    }
  });

  app.post("/auth/login", async (req: Request, res: Response) => {
    const input = LoginSchema.safeParse(req.body);
    if (!input.success) return res.status(400).json({ ok: false, error: "Invalid input" });

    const email = input.data.email.toLowerCase();
    const r = await db.query<{ id: string; password_hash: string; disabled_at: string | null }>(
      "SELECT id, password_hash, disabled_at FROM accounts WHERE email=$1 LIMIT 1",
      [email],
    );
    const row = r.rows[0];
    if (!row || row.disabled_at) return res.status(401).json({ ok: false, error: "Invalid credentials" });

    const ok = await verifyPassword(input.data.password, row.password_hash);
    if (!ok) return res.status(401).json({ ok: false, error: "Invalid credentials" });

    const sid = randomUUID();
    await redis.set(`sess:${sid}`, row.id, { EX: ttlSeconds });
    setSession(res, sid);
    return res.status(200).json({ ok: true });
  });

  app.post("/auth/logout", async (req: Request, res: Response) => {
    const sid = (req.cookies?.[cookieName] as string | undefined) ?? "";
    if (sid) await redis.del(`sess:${sid}`);
    res.clearCookie(cookieName, { path: "/" });
    return res.status(200).json({ ok: true });
  });
}

export async function requireSession(req: Request, res: Response, deps: { redis: RedisClientLike; cookieName: string }) {
  const sid = (req.cookies?.[deps.cookieName] as string | undefined) ?? "";
  if (!sid) {
    res.status(401).json({ ok: false, error: "Unauthorized" });
    return null;
  }
  const accountId = await deps.redis.get(`sess:${sid}`);
  if (!accountId) {
    res.status(401).json({ ok: false, error: "Unauthorized" });
    return null;
  }
  return { accountId };
}
