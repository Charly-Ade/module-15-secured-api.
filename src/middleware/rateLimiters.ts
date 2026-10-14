import rateLimit from "express-rate-limit";
import { env } from "../config/env";

const WINDOW_MS = 15 * 60 * 1000;

const base = {
  windowMs: WINDOW_MS,
  standardHeaders: true, 
  legacyHeaders: false,
} as const;

export const globalLimiter = rateLimit({
   ...base,
  limit: env.RATE_LIMIT_MAX,
  message: { message: "Too many requests, please try again later." },
});

export const authLimiter = rateLimit({
  ...base,
  limit: env.AUTH_RATE_LIMIT_MAX,
  message: { message: "Too many authentication attempts, please try again later." },
});
