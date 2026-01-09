import type { FastifyReply, FastifyRequest } from "fastify";

export type ApiLang = "zh" | "en";
export type ApiI18n = { zh: string; en: string };

// 规范化 API 错误输出：稳定 code + 双语文案（按 Accept-Language 选择 error，并附带 error_i18n）。
export function pickLang(req: FastifyRequest): ApiLang {
  const q = (req.query as any)?.lang;
  const qLang = typeof q === "string" ? q.trim().toLowerCase() : "";
  if (qLang === "zh" || qLang === "en") return qLang as ApiLang;

  const acceptLanguage = String(req.headers["accept-language"] ?? "").toLowerCase();
  if (acceptLanguage.includes("zh")) return "zh";
  if (acceptLanguage.includes("en")) return "en";
  return "zh";
}

export function sendApiError(
  req: FastifyRequest,
  reply: FastifyReply,
  opts: { httpStatus: number; format: "json" | "text"; code: string; i18n: ApiI18n },
) {
  const lang = pickLang(req);
  const error = opts.i18n[lang] ?? opts.i18n.zh;

  if (opts.format === "json") {
    reply.code(opts.httpStatus).send({ ok: false, code: opts.code, lang, error, error_i18n: opts.i18n });
    return;
  }

  // 纯文本：两行输出，便于 curl/浏览器直接看到中英双语
  reply.code(opts.httpStatus).type("text/plain").send(`${opts.i18n.zh}\n${opts.i18n.en}`);
}

