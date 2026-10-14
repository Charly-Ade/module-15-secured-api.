import crypto from "node:crypto";
import { NextFunction, Request, Response, Router } from "express";
import passport from "passport";
import { z } from "zod";
import { env } from "../config/env";
import { issueTokenPair } from "../services/authService";
import { createExchangeCode, redeemExchangeCode } from "../services/oauthCodes";
import * as usersService from "../services/usersService";
import { UnauthorizedError } from "../middleware/errors";
import { authLimiter } from "../middleware/rateLimiters";
import { validateBody } from "../middleware/validateRequest";
import { User } from "../types";
import { securityEvent } from "../utils/securityLog";

const router = Router();

const STATE_COOKIE = "oauth_state";
const COOKIE_PATH = "/api/auth/google";

const readCookie = (req: Request, name: string): string | undefined =>
  req.headers.cookie
    ?.split(";")
    .map((c) => c.trim().split("="))
    .find(([key]) => key === name)?.[1];

const failRedirect = (res: Response, reason: string): void => {
  const url = new URL(env.OAUTH_SUCCESS_REDIRECT!);
  url.searchParams.set("error", reason);
  res.redirect(url.toString());
};

/** Step 1: send the browser to Google. `state` is a random value we ALSO store in an httpOnly
 *  cookie; on return we require them to match (login-CSRF defence). */
router.get("/google", authLimiter, (req: Request, res: Response, next: NextFunction) => {
  const state = crypto.randomBytes(32).toString("base64url");
  res.cookie(STATE_COOKIE, state, {
    httpOnly: true,
    sameSite: "lax", // must be lax (not strict): Google redirects back via a top-level GET
    secure: env.NODE_ENV === "production",
    maxAge: 10 * 60 * 1000,
    path: COOKIE_PATH,
  });
  passport.authenticate("google", {
    scope: ["profile", "email"],
    session: false,
    state,
  })(req, res, next);
});

/** Step 2: Google sends the browser back here with ?code&state. */
router.get(
  "/google/callback",
  authLimiter,
  (req: Request, res: Response, next: NextFunction) => {
    const expected = readCookie(req, STATE_COOKIE);
    const received = typeof req.query.state === "string" ? req.query.state : undefined;
    res.clearCookie(STATE_COOKIE, { path: COOKIE_PATH });

    const ok =
      !!expected &&
      !!received &&
      expected.length === received.length &&
      crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(received));

    if (!ok) {
      securityEvent("oauth_state_invalid", { ip: req.ip });
      failRedirect(res, "invalid_state");
      return;
    }
    next();
  },
  (req: Request, res: Response, next: NextFunction) => {
    passport.authenticate(
      "google",
      { session: false },
      (error: unknown, user: Express.User | false | null, info?: { message?: string }) => {
        if (error || !user) {
          securityEvent("oauth_login_rejected", {
            ip: req.ip,
            reason: info?.message ?? "oauth_failed",
          });
          failRedirect(res, info?.message ?? "oauth_failed");
          return;
        }
        const code = createExchangeCode((user as unknown as User).id);
        const url = new URL(env.OAUTH_SUCCESS_REDIRECT!);
        url.searchParams.set("code", code);
        res.redirect(url.toString());
      },
    )(req, res, next);
  },
);

/** Step 3: the frontend swaps the one-time code for the SAME token pair password login issues. */
router.post(
  "/oauth/exchange",
  authLimiter,
  validateBody(z.object({ code: z.string().min(1) })),
  (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = redeemExchangeCode((req.body as { code: string }).code);
      const user = userId ? usersService.findById(userId) : undefined;
      if (!user) throw new UnauthorizedError("Invalid or expired code");

      res.json({ user: usersService.toPublicUser(user), ...issueTokenPair(user) });
    } catch (error) {
      next(error);
    }
  },
);

export default router;
