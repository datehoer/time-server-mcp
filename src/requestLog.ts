import type { Db } from "./db.js";

export type RequestLogRow = {
  ts: Date;
  accountId: string | null;
  apiKeyId: string | null;
  tool: string | null;
  allowed: boolean;
  httpStatus: number;
  ip: string | null;
};

// 写入缓冲：避免每个请求都同步写 Postgres
export function createRequestLogBuffer(opts: {
  db: Db;
  maxBuffer: number;
  flushEveryMs: number;
  retentionDays: number;
}) {
  const { db, maxBuffer, flushEveryMs, retentionDays } = opts;
  let buf: RequestLogRow[] = [];
  let flushing = false;

  async function flush() {
    if (flushing) return;
    if (buf.length === 0) return;
    flushing = true;
    const batch = buf;
    buf = [];

    try {
      const values: any[] = [];
      const rowsSql: string[] = [];
      for (let i = 0; i < batch.length; i++) {
        const b = batch[i]!;
        const base = i * 7;
        rowsSql.push(`($${base + 1},$${base + 2},$${base + 3},$${base + 4},$${base + 5},$${base + 6},$${base + 7})`);
        values.push(b.ts.toISOString(), b.accountId, b.apiKeyId, b.tool, b.allowed, b.httpStatus, b.ip);
      }
      await db.query(
        `INSERT INTO request_logs (ts, account_id, api_key_id, tool, allowed, http_status, ip) VALUES ${rowsSql.join(",")}`,
        values,
      );
    } finally {
      flushing = false;
    }
  }

  const timer = setInterval(() => {
    flush().catch(() => {});
  }, flushEveryMs);
  timer.unref?.();

  // 定时清理：每小时删除 7 天前日志（简单可用版）
  const cleaner = setInterval(() => {
    const cutoff = new Date(Date.now() - retentionDays * 24 * 3600 * 1000).toISOString();
    db.query("DELETE FROM request_logs WHERE ts < $1", [cutoff]).catch(() => {});
  }, 3600_000);
  cleaner.unref?.();

  return {
    push(row: RequestLogRow) {
      buf.push(row);
      if (buf.length >= maxBuffer) void flush();
    },
    async close() {
      clearInterval(timer);
      clearInterval(cleaner);
      await flush();
    },
  };
}

