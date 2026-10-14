import { describe, expect, it, vi } from "vitest";
import express from "express";
import request from "supertest";
import { createHttpsEnforcer } from "../src/middleware/requireHttps";

const appWith = (enabled: boolean) => {
  const app = express();
  app.set("trust proxy", 1); // as in production, behind a TLS-terminating proxy
  app.use(createHttpsEnforcer(enabled));
  app.all("/x", (_req, res) => res.json({ ok: true }));
  return app;
};

describe("A02 - HTTPS enforcement (production)", () => {
  it("redirects plain-HTTP GETs to HTTPS (308)", async () => {
    const res = await request(appWith(true))
      .get("/x?a=1")
      .set("X-Forwarded-Proto", "http")
      .set("Host", "api.example.com");
    expect(res.status).toBe(308);
    expect(res.headers.location).toBe("https://api.example.com/x?a=1");
  });

  it("refuses non-GET requests over HTTP instead of redirecting (credentials never accepted)", async () => {
    const res = await request(appWith(true))
      .post("/x")
      .set("X-Forwarded-Proto", "http")
      .send({ password: "p" });
    expect(res.status).toBe(403);
  });

  it("lets HTTPS traffic through, and does nothing when disabled (dev/test)", async () => {
    expect((await request(appWith(true)).post("/x").set("X-Forwarded-Proto", "https")).status).toBe(
      200,
    );
    expect((await request(appWith(false)).get("/x").set("X-Forwarded-Proto", "http")).status).toBe(
      200,
    );
  });

  it("boot is refused in production without TRUST_PROXY (else every request would look insecure)", async () => {
    vi.resetModules();
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv("TRUST_PROXY", "0");
    const exit = vi.spyOn(process, "exit").mockImplementation((() => {
      throw new Error("process.exit called");
    }) as never);
    const err = vi.spyOn(console, "error").mockImplementation(() => {});
    await expect(import("../src/config/env")).rejects.toThrow("process.exit called");
    expect(exit).toHaveBeenCalledWith(1);
    expect(String(err.mock.calls[0][0])).toMatch(/TRUST_PROXY/);
    vi.unstubAllEnvs();
    vi.restoreAllMocks();
  });
});
