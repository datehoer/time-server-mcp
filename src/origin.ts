export function getOrigin(req: { headers: Record<string, unknown> }) {
  const proto =
    String(req.headers["x-forwarded-proto"] ?? "")
      .split(",")[0]
      ?.trim() || "http";
  const host =
    String(req.headers["x-forwarded-host"] ?? "")
      .split(",")[0]
      ?.trim() ||
    String(req.headers["host"] ?? "") ||
    "127.0.0.1";
  return `${proto}://${host}`;
}

