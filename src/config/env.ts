import dotenv from "dotenv";
import { z } from "zod";

dotenv.config({ quiet: true });


const secret = z.string().min(32, "must be at least 32 characters");

const originList = z
  .string()
  .min(1, "is required")
  .transform((value) =>
    value
      .split(",")
      .map((origin) => origin.trim())
      .filter(Boolean),
  )
  .refine(
    (origins) =>
      origins.length > 0 && origins.every((o) => o !== "*" && /^https?:\/\/[^/*\s]+$/.test(o)),
    "must be a comma-separated list of explicit origins (e.g. http://localhost:5173) - no wildcards, no paths",
  );

const envSchema = z.object({
    NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
    PORT: z.coerce.number().int().positive(),
    GOOGLE_CLIENT_ID: z.string().optional(),
    GOOGLE_CLIENT_SECRET: z.string().optional(),
    GOOGLE_CALLBACK_URL: z.url().optional(),
    OAUTH_SUCCESS_REDIRECT: z.url().optional(),

    JWT_ACCESS_SECRET: secret,
    JWT_REFRESH_SECRET: secret,
    ACCESS_TOKEN_TTL_SECONDS: z.coerce
      .number()
      .int()
      .positive()
      .default(15 * 60),
    REFRESH_TOKEN_TTL_SECONDS: z.coerce
      .number()
      .int()
      .positive()
      .default(7 * 24 * 60 * 60),

    CORS_ORIGINS: originList,

    TRUST_PROXY: z.coerce.number().int().min(0).default(0),
    RATE_LIMIT_MAX: z.coerce.number().int().positive().default(100),
    AUTH_RATE_LIMIT_MAX: z.coerce.number().int().positive().default(10),

    SEED_ADMIN_EMAIL: z.email().optional(),
    SEED_ADMIN_PASSWORD: z.string().optional(),
  })
  .refine((e) => e.JWT_ACCESS_SECRET !== e.JWT_REFRESH_SECRET, {
    message: "must differ from JWT_ACCESS_SECRET",
    path: ["JWT_REFRESH_SECRET"],
  });


const rawEnv = Object.fromEntries(Object.entries(process.env).filter(([, value]) => value !== ""));

const parsed = envSchema.safeParse(rawEnv);

if (!parsed.success) {
  console.error("Invalid environment configuration:\n" + z.prettifyError(parsed.error));
  process.exit(1);
}

export const env = parsed.data;
