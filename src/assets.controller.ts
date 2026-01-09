import { Controller, Get, Req, Res } from "@nestjs/common";
import type { FastifyReply, FastifyRequest } from "fastify";
import fs from "node:fs";
import { AppContextService } from "./appContext.service.js";

@Controller()
export class AssetsController {
  constructor(private readonly ctx: AppContextService) {}

  @Get("assets/echarts.min.js")
  async getEcharts(@Res() reply: FastifyReply) {
    if (!this.ctx.echartsDistPath) {
      reply.code(404).send("ECharts asset disabled");
      return;
    }
    reply.header("Cache-Control", "public, max-age=86400");
    reply.type("application/javascript");
    reply.send(fs.createReadStream(this.ctx.echartsDistPath));
  }

  // 浏览器/系统常会默认请求这些根路径图标；这里重定向到 /assets，避免 404。
  @Get("favicon.svg")
  async faviconSvg(@Res() reply: FastifyReply) {
    reply.redirect("/assets/favicon-32x32.png", 302);
  }

  @Get("apple-touch-icon.png")
  async appleTouch(@Res() reply: FastifyReply) {
    reply.redirect("/assets/apple-touch-icon.png", 302);
  }

  @Get("site.webmanifest")
  async manifest(@Res() reply: FastifyReply) {
    reply.redirect("/assets/site.webmanifest", 302);
  }
}
