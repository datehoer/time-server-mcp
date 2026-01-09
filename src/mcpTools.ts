import { DateTime, type DurationLikeObject } from "luxon";
import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

function assertIanaZone(tz: string) {
  const dt = DateTime.now().setZone(tz);
  if (!dt.isValid) throw new Error(`Invalid IANA timezone: ${tz}`);
}

type FormatKey =
  | "iso"
  | "rfc3339"
  | "epoch_ms"
  | "epoch_s"
  | "date"
  | "time"
  | "readable"
  | "offset"
  | "zone";

const FormatKeySchema = z.enum([
  "iso",
  "rfc3339",
  "epoch_ms",
  "epoch_s",
  "date",
  "time",
  "readable",
  "offset",
  "zone",
]);

function normalizeFormats(formats?: FormatKey[]) {
  // 默认：模型/程序最常用、最稳定的输出
  return formats?.length ? formats : (["iso", "epoch_ms", "readable", "offset", "zone"] as FormatKey[]);
}

function formatInZone(dtUtc: DateTime, tz: string, formats: FormatKey[]) {
  assertIanaZone(tz);

  const local = dtUtc.setZone(tz);
  const want = new Set(formats);

  const out: Record<string, string | number> = { timezone: tz };

  if (want.has("iso")) out.iso = local.toISO() ?? "";
  if (want.has("rfc3339")) out.rfc3339 = local.toISO({ suppressMilliseconds: false }) ?? "";
  if (want.has("epoch_ms")) out.epoch_ms = local.toMillis();
  if (want.has("epoch_s")) out.epoch_s = Math.floor(local.toSeconds());
  if (want.has("date")) out.date = local.toFormat("yyyy-LL-dd");
  if (want.has("time")) out.time = local.toFormat("HH:mm:ss");
  if (want.has("offset")) out.offset = local.toFormat("ZZ");
  if (want.has("zone")) out.zone = local.zoneName ?? "";
  if (want.has("readable")) out.readable = local.toFormat("yyyy-LL-dd HH:mm:ss ZZZZ");

  return out;
}

const TimeInputSchema = z.object({
  type: z.enum(["iso", "epoch_ms", "epoch_s"]),
  value: z.union([z.string(), z.number()]),
  input_timezone: z.string().optional(), // iso 且不带 offset 时使用
});

type TimeInput = z.infer<typeof TimeInputSchema>;

function parseToUtc(input: TimeInput): DateTime {
  if (input.type === "epoch_ms") {
    if (typeof input.value !== "number") throw new Error("epoch_ms value must be a number");
    return DateTime.fromMillis(input.value, { zone: "utc" });
  }
  if (input.type === "epoch_s") {
    if (typeof input.value !== "number") throw new Error("epoch_s value must be a number");
    return DateTime.fromSeconds(input.value, { zone: "utc" });
  }

  // iso
  if (typeof input.value !== "string") throw new Error("iso value must be a string");
  const s = input.value;

  // 1) 如果字符串自带 offset/zone，按自带解析并转 UTC
  //    简单判断：末尾 Z 或 ±hh:mm
  const hasOffset = /[zZ]$|[+-]\d{2}:\d{2}$/.test(s);
  if (hasOffset) {
    const dt = DateTime.fromISO(s, { setZone: true });
    if (!dt.isValid) throw new Error(`Invalid ISO time: ${s}`);
    return dt.toUTC();
  }

  // 2) 否则用 input_timezone 补全
  const tz = input.input_timezone ?? "UTC";
  assertIanaZone(tz);
  const dt = DateTime.fromISO(s, { zone: tz });
  if (!dt.isValid) throw new Error(`Invalid ISO time: ${s}`);
  return dt.toUTC();
}

export const ToolsCallSchema = z
  .object({
    method: z.literal("tools/call"),
    params: z.object({ name: z.string() }).passthrough(),
    id: z.any().optional(),
  })
  .passthrough();

export function createMcpServer() {
  const server = new McpServer({
    name: "time_server",
    version: "1.0.0",
  });

  // time.now
  server.tool(
    "time_now",
    "Get current time (default UTC) or in a specified IANA timezone.",
    {
      timezone: z.string().describe("IANA timezone, e.g. Asia/Singapore").optional(),
      formats: z.array(FormatKeySchema).optional(),
    },
    async ({ timezone, formats }) => {
      const tz = timezone ?? "UTC";
      const f = normalizeFormats(formats);
      const nowUtc = DateTime.utc();

      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(
              {
                utc_iso: nowUtc.toISO(),
                ...formatInZone(nowUtc, tz, f),
              },
              null,
              2,
            ),
          },
        ],
      };
    },
  );

  // time.convert
  server.tool(
    "time_convert",
    "Convert a time input into multiple output timezones.",
    {
      time: TimeInputSchema.describe("Time input {type, value, input_timezone?}"),
      output_timezones: z.array(z.string()).describe("List of IANA timezones"),
      formats: z.array(FormatKeySchema).optional(),
    },
    async ({ time, output_timezones, formats }) => {
      const f = normalizeFormats(formats);
      const dtUtc = parseToUtc(time);

      const results = output_timezones.map((tz) => formatInZone(dtUtc, tz, f));

      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(
              {
                base_utc_iso: dtUtc.toISO(),
                results,
              },
              null,
              2,
            ),
          },
        ],
      };
    },
  );

  // time.shift（一天前/一周前/任意偏移）
  server.tool(
    "time_shift",
    "Shift a base time by a duration delta (negative values go to the past).",
    {
      base_time: TimeInputSchema.optional().describe("Optional base time; omit to use now()"),
      delta: z
        .object({
          weeks: z.number().optional(),
          days: z.number().optional(),
          hours: z.number().optional(),
          minutes: z.number().optional(),
          seconds: z.number().optional(),
        })
        .describe("Duration delta; e.g. {days:-1}, {weeks:-1}, {hours:2}"),
      output_timezone: z.string().describe("Output IANA timezone; default UTC").optional(),
      formats: z.array(FormatKeySchema).optional(),
    },
    async ({ base_time, delta, output_timezone, formats }) => {
      const f = normalizeFormats(formats);
      const baseUtc = base_time ? parseToUtc(base_time) : DateTime.utc();
      const shiftedUtc = baseUtc.plus(delta as DurationLikeObject);
      const tz = output_timezone ?? "UTC";

      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(
              {
                base_utc_iso: baseUtc.toISO(),
                shifted_utc_iso: shiftedUtc.toISO(),
                shifted: formatInZone(shiftedUtc, tz, f),
              },
              null,
              2,
            ),
          },
        ],
      };
    },
  );

  // time.range（常见范围：today/this_week/last_week…）
  server.tool(
    "time_range",
    "Get start/end of common ranges (today, yesterday, this_week, last_week, last_7_days) in a timezone.",
    {
      range: z.enum(["today", "yesterday", "this_week", "last_week", "last_7_days"]),
      timezone: z.string().describe("IANA timezone; default UTC").optional(),
      week_starts_on: z.number().int().min(0).max(1).optional().describe("0=Sunday, 1=Monday (default 1)"),
      formats: z.array(FormatKeySchema).optional(),
    },
    async ({ range, timezone, week_starts_on, formats }) => {
      const tz = timezone ?? "UTC";
      const f = normalizeFormats(formats);
      const wso = (week_starts_on ?? 1) as 0 | 1;

      assertIanaZone(tz);

      const nowLocal = DateTime.utc().setZone(tz);

      const startOfDay = (d: DateTime) => d.startOf("day");
      const endOfDay = (d: DateTime) => d.endOf("day");

      let startLocal: DateTime;
      let endLocal: DateTime;

      if (range === "today") {
        startLocal = startOfDay(nowLocal);
        endLocal = endOfDay(nowLocal);
      } else if (range === "yesterday") {
        const y = nowLocal.minus({ days: 1 });
        startLocal = startOfDay(y);
        endLocal = endOfDay(y);
      } else if (range === "last_7_days") {
        // 自然日范围：包含今天在内的最近 7 天
        startLocal = startOfDay(nowLocal.minus({ days: 6 }));
        endLocal = endOfDay(nowLocal);
      } else {
        // week: Luxon weekday 1..7 (Mon..Sun)
        const weekday = nowLocal.weekday;
        const daysSinceWeekStart = wso === 1 ? weekday - 1 : weekday % 7;
        const thisWeekStart = startOfDay(nowLocal.minus({ days: daysSinceWeekStart }));
        const thisWeekEnd = endOfDay(thisWeekStart.plus({ days: 6 }));

        if (range === "this_week") {
          startLocal = thisWeekStart;
          endLocal = thisWeekEnd;
        } else {
          const lastWeekStart = thisWeekStart.minus({ days: 7 });
          startLocal = lastWeekStart;
          endLocal = endOfDay(lastWeekStart.plus({ days: 6 }));
        }
      }

      const startUtc = startLocal.toUTC();
      const endUtc = endLocal.toUTC();

      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(
              {
                timezone: tz,
                start: { utc_iso: startUtc.toISO(), ...formatInZone(startUtc, tz, f) },
                end: { utc_iso: endUtc.toISO(), ...formatInZone(endUtc, tz, f) },
              },
              null,
              2,
            ),
          },
        ],
      };
    },
  );

  return server;
}

