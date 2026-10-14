import { beforeAll, describe, expect, it } from "vitest";
import type { Express } from "express";
import request from "supertest";

process.env.RATE_LIMIT_MAX = "5";
process.env.AUTH_RATE_LIMIT_MAX = "100000";

let app: Express;
beforeAll(async () => {
  app = (await import("../src/app")).default;
});

describe("Part 4 - global limiter", () => {
  it("allows 5 requests then returns 429 for any route", async () => {
    for (let i = 0; i < 5; i++) expect((await request(app).get("/")).status).toBe(200);
    const blocked = await request(app).get("/");
    expect(blocked.status).toBe(429);
    // helmet runs before the limiter, so even the 429 carries security headers
    expect(blocked.headers["x-content-type-options"]).toBe("nosniff");
  });
});
