import { Injectable, Logger, NestMiddleware } from "@nestjs/common";
import * as bcryptjs from "bcryptjs";
import type { NextFunction, Request, Response } from "express";

import { UserService } from "../user/user.service";
import { AuthService } from "./auth.service";
import { getCookieOptions } from "./utils/cookie";

// The account that `DEV_AUTO_LOGIN` signs you in as. It is created on first use
// and is an otherwise ordinary account, so `vince` / `vince` also works on the
// regular login form if you ever turn auto-login back off.
export const DEV_USER = {
  name: "Vince",
  // Must be a real-looking address: the user DTO validates it with zod
  // `.email()`, which rejects a domain without a dot (e.g. `vince@localhost`).
  email: "vince@example.com",
  username: "vince",
  password: "vince",
  locale: "en-US",
} as const;

// The landing page and the login form are pointless when auto-login is on, and
// neither of them consults the server about the session (`/` is public, and
// GuestGuard reads only the persisted client store). Bounce them to the app.
const REDIRECT_TO = "/dashboard/resumes";
const REDIRECTED_PATHS = new Set(["/", "/auth", "/auth/login", "/auth/register"]);

/**
 * Local-development convenience: mints a valid session for `DEV_USER` on any
 * request that doesn't already carry one, so the app never shows a login page.
 *
 * Minting a real JWT (rather than faking `request.user`) means every guard,
 * strategy and controller downstream stays completely untouched.
 *
 * Only applied when `DEV_AUTO_LOGIN` is set -- see AuthModule.configure().
 */
@Injectable()
export class AutoLoginMiddleware implements NestMiddleware {
  private readonly logger = new Logger(AutoLoginMiddleware.name);

  // Cached as a promise, not an id: the first page load fires many requests in
  // parallel, and each one would otherwise race to create the same account.
  private userIdPromise: Promise<string> | null = null;

  constructor(
    private readonly userService: UserService,
    private readonly authService: AuthService,
  ) {}

  private getOrCreateUserId() {
    this.userIdPromise ??= this.resolveUserId().catch((error: unknown) => {
      // Never cache a failure -- retry on the next request instead.
      this.userIdPromise = null;
      throw error;
    });

    return this.userIdPromise;
  }

  private async resolveUserId(): Promise<string> {
    const existing = await this.userService.findOneByIdentifier(DEV_USER.username);

    if (existing) {
      // Heal an account left behind by an earlier run with a different email,
      // otherwise the user DTO fails validation on every response.
      if (existing.email !== DEV_USER.email) {
        await this.userService.updateByEmail(existing.email, { email: DEV_USER.email });
      }

      return existing.id;
    }

    const created = await this.userService.create({
      name: DEV_USER.name,
      email: DEV_USER.email,
      username: DEV_USER.username,
      locale: DEV_USER.locale,
      provider: "email",
      emailVerified: true,
      secrets: { create: { password: await bcryptjs.hash(DEV_USER.password, 10) } },
    });

    this.logger.log(
      `Created the default account '${DEV_USER.username}' (password: '${DEV_USER.password}').`,
    );

    return created.id;
  }

  /**
   * A cookie being *present* is not enough. It may be empty, expired, or --
   * after the database is wiped and the account recreated -- still verify
   * against the unchanged token secret while naming a user id that no longer
   * exists. Any of those leaves you stuck on the login page, so re-mint unless
   * the token really is a live session for the current account.
   */
  private isLiveSession(request: Request, userId: string) {
    // Read the raw header too, so this doesn't depend on cookie-parser order.
    const token =
      (request.cookies?.Authentication as string | undefined) ??
      /(?:^|;\s*)Authentication=([^;]*)/.exec(request.headers.cookie ?? "")?.[1];

    const payload = token?.split(".")[1];

    if (!payload) return false;

    try {
      const claims = JSON.parse(Buffer.from(payload, "base64url").toString()) as {
        id?: string;
        exp?: number;
      };

      return claims.id === userId && (claims.exp ?? 0) * 1000 > Date.now();
    } catch {
      return false;
    }
  }

  async use(request: Request, response: Response, next: NextFunction) {
    try {
      const id = await this.getOrCreateUserId();

      if (this.isLiveSession(request, id)) return this.continue(request, response, next);

      const accessToken = this.authService.generateToken("access", { id, isTwoFactorAuth: false });
      const refreshToken = this.authService.generateToken("refresh", { id, isTwoFactorAuth: false });

      await this.authService.setRefreshToken(DEV_USER.email, refreshToken);

      response.cookie("Authentication", accessToken, getCookieOptions("access"));
      response.cookie("Refresh", refreshToken, getCookieOptions("refresh"));

      // Also attach to the current request, so the guards on *this* request
      // already see the session rather than 401-ing on the first page load.
      request.cookies = { ...request.cookies, Authentication: accessToken, Refresh: refreshToken };
    } catch (error) {
      this.logger.error(error);
    }

    this.continue(request, response, next);
  }

  private continue(request: Request, response: Response, next: NextFunction) {
    if (request.method === "GET" && REDIRECTED_PATHS.has(request.path)) {
      response.redirect(REDIRECT_TO);
      return;
    }

    next();
  }
}
