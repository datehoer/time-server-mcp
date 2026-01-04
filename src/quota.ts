import type { Db } from "./db.js";
import type { RedisClientLike } from "./redisLike.js";

type GrantRow = {
  kind: "base" | "addon";
  daily_limit: number;
};

async function fetchGrants(opts: {
  db: Db;
  accountId: string;
  metric: "requests";
  where: string;
  args: Array<string | number>;
}): Promise<GrantRow[]> {
  const { db, accountId, metric, where, args } = opts;
  const nowIso = new Date().toISOString();
  const rows = await db.query<GrantRow>(
    `
WITH my_groups AS (
  SELECT group_id FROM group_members WHERE account_id=$1
),
my_subjects AS (
  SELECT 'account'::text AS subject_type, $1::uuid AS subject_id
  UNION ALL
  SELECT 'group'::text AS subject_type, group_id::uuid AS subject_id FROM my_groups
),
active_subs AS (
  SELECT s.plan_id
  FROM subscriptions s
  JOIN my_subjects ms ON ms.subject_type=s.subject_type AND ms.subject_id=s.subject_id
  WHERE s.enabled=true AND s.starts_at <= $2::timestamptz AND (s.ends_at IS NULL OR s.ends_at >= $2::timestamptz)
)
SELECT pg.kind, pg.daily_limit
FROM plan_grants pg
JOIN active_subs s ON s.plan_id = pg.plan_id
WHERE pg.metric=$3 AND (${where})
`,
    [accountId, nowIso, metric, ...args],
  );
  return rows.rows;
}

function aggregate(rows: GrantRow[]) {
  let maxBase = 0;
  let addonSum = 0;

  for (const r of rows) {
    if (r.kind === "base") {
      maxBase = Math.max(maxBase, r.daily_limit);
    } else {
      addonSum += r.daily_limit;
    }
  }
  return { maxBase, addonSum };
}

// 全局额度：仅看 tool IS NULL（默认免费额度也在此生效）
export async function getGlobalDailyLimit(opts: {
  db: Db;
  accountId: string;
  metric: "requests";
  defaultFree: number;
}): Promise<number> {
  const rows = await fetchGrants({ db: opts.db, accountId: opts.accountId, metric: opts.metric, where: "pg.tool IS NULL", args: [] });
  const a = aggregate(rows);
  return Math.max(opts.defaultFree, a.maxBase) + a.addonSum;
}

// 工具级额度：仅看 tool = <toolName>（若无任何 grant，则返回 null 表示“不开启工具级封顶”）
export async function getToolDailyLimit(opts: {
  db: Db;
  accountId: string;
  metric: "requests";
  tool: string;
}): Promise<number | null> {
  const rows = await fetchGrants({ db: opts.db, accountId: opts.accountId, metric: opts.metric, where: "pg.tool = $4", args: [opts.tool] });
  const a = aggregate(rows);
  if (a.maxBase === 0 && a.addonSum === 0) return null;
  return a.maxBase + a.addonSum;
}

export async function getGlobalDailyLimitCached(opts: {
  redis: RedisClientLike;
  db: Db;
  accountId: string;
  metric: "requests";
  defaultFree: number;
  cacheSeconds: number;
}): Promise<number> {
  const { redis, cacheSeconds } = opts;
  const cacheKey = `policy:acct:${opts.accountId}:requests:__all__`;
  const cached = await redis.get(cacheKey);
  if (cached) return Number(cached) || 0;
  const v = await getGlobalDailyLimit(opts);
  await redis.set(cacheKey, String(v), { EX: cacheSeconds });
  return v;
}

export async function getToolDailyLimitCached(opts: {
  redis: RedisClientLike;
  db: Db;
  accountId: string;
  metric: "requests";
  tool: string;
  cacheSeconds: number;
}): Promise<number | null> {
  const { redis, cacheSeconds } = opts;
  const cacheKey = `policy:acct:${opts.accountId}:requests:tool:${opts.tool}`;
  const cached = await redis.get(cacheKey);
  if (cached !== null) return cached === "" ? null : Number(cached) || 0;
  const v = await getToolDailyLimit(opts);
  await redis.set(cacheKey, v === null ? "" : String(v), { EX: cacheSeconds });
  return v;
}
