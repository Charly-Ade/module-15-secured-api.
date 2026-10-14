import { beforeAll, describe, expect, it } from "vitest";
import type { Express } from "express";
import request from "supertest";

// Must be set BEFORE the app (and its env parsing) is imported.
process.env.AUTH_RATE_LIMIT_MAX = "3";
process.env.RATE_LIMIT_MAX = "100000";

let app: Express;
beforeAll(async () => {
  app = (await import("../src/app")).default;
});

describe("Part 4 - strict limiter on login/register", () => {
  it("blocks the 4th login attempt with 429 and sends RateLimit headers", async () => {
    const attempt = () =>
      request(app).post("/api/auth/login").send({ email: "x@example.com", password: "whatever-1" });
    for (let i = 0; i < 3; i++) expect((await attempt()).status).toBe(401);
    const blocked = await attempt();
    expect(blocked.status).toBe(429);
    expect(blocked.body.message).toMatch(/too many/i);
    expect(blocked.headers["ratelimit"] ?? blocked.headers["ratelimit-limit"]).toBeDefined();
    expect(blocked.headers["x-ratelimit-limit"]).toBeUndefined(); // legacy headers off
  });

  it("register shares the strict budget, but other routes are unaffected", async () => {
    const reg = await request(app)
      .post("/api/auth/register")
      .send({ name: "Ada Obi", email: "ada@example.com", password: "correct-horse-battery" });
    expect(reg.status).toBe(429); // same limiter, already exhausted above
    expect((await request(app).get("/")).status).toBe(200);
  });
});
