import express, { Request, Response } from "express";
import passport from "passport";
import cors from "cors";
import helmet from "helmet";
import { env } from "./config/env";
import accountsRouter from "./routes/account";
import transactionsRouter from "./routes/transactions";
import authRouter from "./routes/auth";
import adminRouter from "./routes/admin";
import oauthRouter from "./routes/oauth";
import { configureGoogleStrategy, isGoogleConfigured } from "./auth/google";
import { errorHandler, notFoundHandler } from "./middleware/errorHandler";
import { globalLimiter } from "./middleware/rateLimiters";
import { createHttpsEnforcer } from "./middleware/requireHttps";

const app = express();

// Don't advertise the framework (helmet also removes the header; this is belt-and-braces).
app.disable("x-powered-by");

// Behind a reverse proxy, trust exactly N hops so req.ip (used by the rate limiter)
// is the real client and can't be spoofed via X-Forwarded-For.
if (env.TRUST_PROXY > 0) {
  app.set("trust proxy", env.TRUST_PROXY);
}

/* ------------------------------ Middleware order ------------------------------
 * 0. https enforcer - production only: never accept credentials over plain HTTP
 * 1. helmet        - security headers on EVERY response, including 4xx/429 ones below
 * 2. cors          - answers preflight (OPTIONS) early, with an explicit allow-list
 * 3. global limiter- reject floods BEFORE spending CPU parsing bodies or hitting bcrypt
 * 4. express.json  - body parsing with a small size cap
 * 5. routes        - (auth routes add their own stricter limiter)
 * 6. 404 + error handler - always last
 * ---------------------------------------------------------------------------- */
app.use(createHttpsEnforcer(env.NODE_ENV === "production"));
app.use(helmet());

app.use(
  cors({
    origin: env.CORS_ORIGINS, // explicit list from env; the schema rejects "*"
    methods: ["GET", "POST", "PATCH", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: false, // tokens travel in the Authorization header, not cookies
    maxAge: 600,
  }),
);

app.use(globalLimiter);

app.use(express.json({ limit: "10kb" }));

app.get("/", (_req: Request, res: Response) => {
  res.end("Hello world");
});

// Google OAuth is opt-in: routes exist only when all GOOGLE_* env vars are set.
if (isGoogleConfigured()) {
  configureGoogleStrategy();
  app.use(passport.initialize());
  app.use("/api/auth", oauthRouter);
}

app.use("/api/auth", authRouter);
app.use("/api/accounts", accountsRouter);
app.use("/api/transactions", transactionsRouter);
app.use("/api/admin", adminRouter);

app.use(notFoundHandler);
app.use(errorHandler);

export default app;
