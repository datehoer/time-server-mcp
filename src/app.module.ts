import { Module } from "@nestjs/common";
import { AppContextService } from "./appContext.service.js";
import { AssetsController } from "./assets.controller.js";
import { AuthController } from "./auth.js";
import { CaptchaController } from "./captcha.js";
import { DashboardController } from "./dashboard.js";
import { HealthController } from "./health.controller.js";
import { HomeController } from "./home.js";
import { McpController } from "./mcp.controller.js";
import { MeController } from "./me.js";
import { AdminController } from "./admin.js";

@Module({
  controllers: [
    HomeController,
    HealthController,
    AssetsController,
    CaptchaController,
    AuthController,
    MeController,
    DashboardController,
    AdminController,
    McpController,
  ],
  providers: [AppContextService],
})
export class AppModule {}

