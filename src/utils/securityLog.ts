import crypto from "node:crypto";

import type { Request } from "express";

type Value = string | number | boolean | undefined;

/** One JSON line per security-relevant event, so a log aggregator can alert on them
 *  (spikes of login_failed, any refresh_reuse_detected, repeated access_denied...).
 *  RULE: callers pass only explicit, safe fields. Never pass passwords, tokens, hashes or
 *  raw request bodies. */
export const securityEvent = (event: string, fields: Record<string, Value> = {}): void => {
  console.warn(
    JSON.stringify({ ts: new Date().toISOString(), type: "security", event, ...fields }),
  );
};

/** Stable short fingerprint so repeated attempts against one email can be correlated
 *  without writing the email address itself into the logs. */
export const fingerprint = (value: string): string =>
  crypto.createHash("sha256").update(value.trim().toLowerCase()).digest("hex").slice(0, 12);

/** Full request path WITHOUT the query string. (Query strings can hold secrets: the OAuth
 *  callback carries `code` and `state`.) baseUrl + path is the same whether we are inside a
 *  router or at app level, so every log line is consistent. */
export const requestPath = (req: Request): string => req.baseUrl + req.path;
