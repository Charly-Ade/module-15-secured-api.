import { describe, expect, it } from "vitest";
import { api, bearer, registerAndLogin } from "./helpers";

describe("Part 4 - helmet, CORS, body limits, error hygiene", () => {
  it("sets helmet security headers and hides x-powered-by", async () => {
    const res = await api().get("/");
    expect(res.headers["x-powered-by"]).toBeUndefined();
    expect(res.headers["x-content-type-options"]).toBe("nosniff");
    expect(res.headers["strict-transport-security"]).toBeDefined();
    expect(res.headers["x-frame-options"]).toBeDefined();
    expect(res.headers["content-security-policy"]).toBeDefined();
  });

  it("CORS: echoes only allow-listed origins, never a wildcard", async () => {
    const good = await api().get("/").set("Origin", "http://localhost:5173");
    expect(good.headers["access-control-allow-origin"]).toBe("http://localhost:5173");

    const evil = await api().get("/").set("Origin", "https://evil.example");
    expect(evil.headers["access-control-allow-origin"]).toBeUndefined();

    const none = await api().get("/");
    expect(none.headers["access-control-allow-origin"]).not.toBe("*");
  });

  it("CORS preflight: allowed origin gets 204 + methods; evil origin gets no allow header", async () => {
    const ok = await api()
      .options("/api/auth/login")
      .set("Origin", "https://app.example.com")
      .set("Access-Control-Request-Method", "POST")
      .set("Access-Control-Request-Headers", "authorization,content-type");
    expect(ok.status).toBe(204);
    expect(ok.headers["access-control-allow-origin"]).toBe("https://app.example.com");
    expect(ok.headers["access-control-allow-headers"]).toMatch(/authorization/i);

    const evil = await api()
      .options("/api/auth/login")
      .set("Origin", "https://evil.example")
      .set("Access-Control-Request-Method", "POST");
    expect(evil.headers["access-control-allow-origin"]).toBeUndefined();
  });

  it("rejects oversized bodies (413) and malformed JSON (400) cleanly", async () => {
    const big = await api()
      .post("/api/auth/login")
      .send({ email: "a@b.co", password: "x".repeat(20_000) });
    expect(big.status).toBe(413);

    const bad = await api()
      .post("/api/auth/login")
      .set("Content-Type", "application/json")
      .send("{not json");
    expect(bad.status).toBe(400);
    expect(bad.body).toEqual({ message: "Malformed JSON body" });
  });

  it("unknown routes get a JSON 404; errors never leak stack traces", async () => {
    const res = await api().get("/api/nope");
    expect(res.status).toBe(404);
    expect(res.body).toEqual({ message: "Route not found" });
    const s = await registerAndLogin();
    const err = await api().get("/api/accounts/x").set(bearer(s.accessToken));
    expect(JSON.stringify(err.body)).not.toMatch(/at .*\.ts|node_modules|stack/i);
  });

  it("401 responses carry a WWW-Authenticate: Bearer challenge", async () => {
    const res = await api().get("/api/accounts");
    expect(res.status).toBe(401);
    expect(res.headers["www-authenticate"]).toBe("Bearer");
  });
});
