import type { Db } from "./db.js";

// 将 API Key 的 last_used_at 批量刷回 Postgres（降低每请求写库压力）
export function createApiKeyLastUsedTracker(opts: { db: Db; flushEveryMs: number }) {
  const { db, flushEveryMs } = opts;
  const map = new Map<string, number>();
  let flushing = false;

  async function flush() {
    if (flushing) return;
    if (map.size === 0) return;
    flushing = true;
    const entries = Array.from(map.entries());
    map.clear();

    try {
      const values: any[] = [];
      const rowsSql: string[] = [];
      for (let i = 0; i < entries.length; i++) {
        const [id, ms] = entries[i]!;
        const base = i * 2;
        rowsSql.push(`($${base + 1}::uuid, $${base + 2}::timestamptz)`);
        values.push(id, new Date(ms).toISOString());
      }
      await db.query(
        `
UPDATE api_keys a
SET last_used_at = GREATEST(a.last_used_at, v.ts)
FROM (VALUES ${rowsSql.join(",")}) AS v(id, ts)
WHERE a.id = v.id
`,
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

  return {
    touch(apiKeyId: string, tsMs: number) {
      const prev = map.get(apiKeyId);
      if (!prev || tsMs > prev) map.set(apiKeyId, tsMs);
    },
    async close() {
      clearInterval(timer);
      await flush();
    },
  };
}

