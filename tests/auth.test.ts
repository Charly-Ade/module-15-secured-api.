import { describe, expect, it } from "vitest";
import jwt from "jsonwebtoken";
import { api, bearer, PASSWORD, registerAndLogin, uniqueEmail } from "./helpers";
import * as usersService from "../src/services/usersService";

const ACCESS_SECRET = process.env.JWT_ACCESS_SECRET!;
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET!;

describe("Part 1 - registration & login", () => {
  it("registers a user and never returns the password or hash", async () => {
    const email = uniqueEmail();
    const res = await api()
      .post("/api/auth/register")
      .send({ name: "Ada Obi", email, password: PASSWORD });
    expect(res.status).toBe(201);
    expect(res.body.user).toMatchObject({ name: "Ada Obi", email, role: "user" });
    const raw = JSON.stringify(res.body).toLowerCase();
    expect(raw).not.toContain("password");
    expect(raw).not.toContain(PASSWORD);
    expect(raw).not.toContain("$2b$");
  });

  it("stores a bcrypt hash with cost 12 and a unique salt per user", async () => {
    const a = uniqueEmail("a");
    const b = uniqueEmail("b");
    await api().post("/api/auth/register").send({ name: "User A", email: a, password: PASSWORD });
    await api().post("/api/auth/register").send({ name: "User B", email: b, password: PASSWORD });
    const hashA = usersService.findByEmail(a)!.passwordHash;
    const hashB = usersService.findByEmail(b)!.passwordHash;
    expect(hashA).toMatch(/^\$2[aby]\$12\$/);
    expect(hashA).not.toContain(PASSWORD);
    expect(hashA).not.toBe(hashB); // same password, different salt => different hash
  });

  it("ignores a client-supplied role (no mass assignment)", async () => {
    const email = uniqueEmail();
    const res = await api()
      .post("/api/auth/register")
      .send({ name: "Sneaky User", email, password: PASSWORD, role: "admin" });
    expect(res.status).toBe(201);
    expect(res.body.user.role).toBe("user");
    expect(usersService.findByEmail(email)!.role).toBe("user");
  });

  it("validates input with Zod and never echoes the password back", async () => {
    const weak = "short";
    const res = await api()
      .post("/api/auth/register")
      .send({ name: "Ada Obi", email: "nope", password: weak });
    expect(res.status).toBe(400);
    expect(JSON.stringify(res.body)).not.toContain(weak);

    const tooLong = await api()
      .post("/api/auth/register")
      .send({ name: "Ada Obi", email: uniqueEmail(), password: "x".repeat(73) });
    expect(tooLong.status).toBe(400); // bcrypt would silently truncate past 72 bytes
  });

  it("rejects duplicate emails (case-insensitive) with 409", async () => {
    const email = uniqueEmail();
    await api().post("/api/auth/register").send({ name: "Ada Obi", email, password: PASSWORD });
    const dup = await api()
      .post("/api/auth/register")
      .send({ name: "Ada Obi", email: email.toUpperCase(), password: PASSWORD });
    expect(dup.status).toBe(409);
  });

  it("handles concurrent registrations of the same email: exactly one wins", async () => {
    const email = uniqueEmail();
    const body = { name: "Race User", email, password: PASSWORD };
    const results = await Promise.all([
      api().post("/api/auth/register").send(body),
      api().post("/api/auth/register").send(body),
    ]);
    expect(results.map((r) => r.status).sort()).toEqual([201, 409]);
  });

  it("logs in and returns tokens; wrong password and unknown email look identical", async () => {
    const s = await registerAndLogin();
    expect(s.accessToken).toBeTruthy();

    const wrongPw = await api()
      .post("/api/auth/login")
      .send({ email: s.email, password: "wrong-password-1" });
    const noUser = await api()
      .post("/api/auth/login")
      .send({ email: uniqueEmail("ghost"), password: "wrong-password-1" });
    expect(wrongPw.status).toBe(401);
    expect(noUser.status).toBe(401);
    expect(wrongPw.body).toEqual(noUser.body);
  });
});

describe("Part 2 - JWT access & refresh tokens", () => {
  it("signs access and refresh tokens with different secrets", async () => {
    const s = await registerAndLogin();
    const access = jwt.verify(s.accessToken, ACCESS_SECRET) as jwt.JwtPayload;
    expect(access).toMatchObject({ sub: s.id, role: "user" });
    expect(() => jwt.verify(s.accessToken, REFRESH_SECRET)).toThrow();
    expect(() => jwt.verify(s.refreshToken, ACCESS_SECRET)).toThrow();
    const refresh = jwt.verify(s.refreshToken, REFRESH_SECRET) as jwt.JwtPayload;
    expect(refresh.jti).toBeTruthy();
    expect(refresh.role).toBeUndefined();
    // access is short-lived, refresh is long-lived
    expect(access.exp! - access.iat!).toBeLessThan(refresh.exp! - refresh.iat!);
  });

  it("requireAuth: 401 for missing, malformed, tampered, expired, wrong-secret and alg:none tokens", async () => {
    const s = await registerAndLogin();
    const ok = await api().get("/api/auth/me").set(bearer(s.accessToken));
    expect(ok.status).toBe(200);
    expect(ok.body.user.id).toBe(s.id);

    const bad: Record<string, string | undefined> = {
      none: undefined,
      malformed: "Bearer not-a-jwt",
      wrongScheme: `Token ${s.accessToken}`,
      tampered: `Bearer ${s.accessToken.slice(0, -3)}abc`,
      expired: `Bearer ${jwt.sign({ role: "user" }, ACCESS_SECRET, { subject: s.id, expiresIn: -10, issuer: "module-15-secured-api", audience: "module-15-secured-api-clients" })}`,
      signedWithRefreshSecret: `Bearer ${jwt.sign({ role: "admin" }, REFRESH_SECRET, { subject: s.id, expiresIn: 60 })}`,
      refreshTokenAsAccess: `Bearer ${s.refreshToken}`,
    };
    for (const [name, header] of Object.entries(bad)) {
      const req = api().get("/api/auth/me");
      const res = await (header ? req.set("Authorization", header) : req);
      expect(res.status, name).toBe(401);
    }

    // alg:none forgery with admin role
    const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString("base64url");
    const forged = `${b64({ alg: "none", typ: "JWT" })}.${b64({ sub: s.id, role: "admin", exp: Math.floor(Date.now() / 1000) + 600 })}.`;
    const none = await api().get("/api/admin/users").set(bearer(forged));
    expect(none.status).toBe(401);
  });

  it("refresh rotates tokens; reusing an old refresh token is rejected and revokes the session", async () => {
    const s = await registerAndLogin();
    const first = await api().post("/api/auth/refresh").send({ refreshToken: s.refreshToken });
    expect(first.status).toBe(200);
    expect(first.body.refreshToken).not.toBe(s.refreshToken);
    const me = await api().get("/api/auth/me").set(bearer(first.body.accessToken));
    expect(me.status).toBe(200);

    // replay the already-used token => 401 and the newer token is revoked too
    const replay = await api().post("/api/auth/refresh").send({ refreshToken: s.refreshToken });
    expect(replay.status).toBe(401);
    const afterReplay = await api()
      .post("/api/auth/refresh")
      .send({ refreshToken: first.body.refreshToken });
    expect(afterReplay.status).toBe(401);
  });

  it("refresh rejects an access token and garbage", async () => {
    const s = await registerAndLogin();
    expect(
      (await api().post("/api/auth/refresh").send({ refreshToken: s.accessToken })).status,
    ).toBe(401);
    expect((await api().post("/api/auth/refresh").send({ refreshToken: "garbage" })).status).toBe(
      401,
    );
    expect((await api().post("/api/auth/refresh").send({})).status).toBe(400);
  });

  it("logout revokes the refresh token", async () => {
    const s = await registerAndLogin();
    expect(
      (await api().post("/api/auth/logout").send({ refreshToken: s.refreshToken })).status,
    ).toBe(204);
    expect(
      (await api().post("/api/auth/refresh").send({ refreshToken: s.refreshToken })).status,
    ).toBe(401);
  });
});
