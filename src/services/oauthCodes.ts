import crypto from "node:crypto";

const CODE_TTL_MS = 60_000;

/** One-time codes handed to the frontend after Google login. We never put JWTs in a redirect
 *  URL (they'd end up in browser history, logs and Referer headers). The frontend instead
 *  POSTs the short-lived, single-use code to /api/auth/oauth/exchange to receive the tokens. */
const codes = new Map<string, { userId: string; expiresAt: number }>();

export const createExchangeCode = (userId: string): string => {
  const now = Date.now();
  for (const [code, entry] of codes) if (entry.expiresAt <= now) codes.delete(code);

  const code = crypto.randomBytes(32).toString("base64url");
  codes.set(code, { userId, expiresAt: now + CODE_TTL_MS });
  return code;
};

/** Returns the user id exactly once, or undefined if unknown/used/expired. */
export const redeemExchangeCode = (code: string): string | undefined => {
  const entry = codes.get(code);
  codes.delete(code); // single use, even if expired
  if (!entry || entry.expiresAt <= Date.now()) return undefined;
  return entry.userId;
};
