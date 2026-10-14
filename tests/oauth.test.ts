import { afterAll, beforeAll, describe, expect, it } from "vitest";
import express from "express";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import type { Express } from "express";
import request from "supertest";

const SUCCESS = "http://localhost:5173/auth/callback";

// --- a fake Google: token endpoint + userinfo endpoint -----------------------------------------
let profile: Record<string, unknown> = {};
let fakeGoogle: Server;
let app: Express;
let users: typeof import("../src/services/usersService");
let hashPassword: typeof import("../src/auth/passwords").hashPassword;

beforeAll(async () => {
  const g = express();
  g.use(express.urlencoded({ extended: false }));
  g.post("/token", (_req, res) =>
    res.json({ access_token: "fake-google-token", token_type: "Bearer" }),
  );
  g.get("/userinfo", (_req, res) => res.json(profile));
  await new Promise<void>((resolve) => (fakeGoogle = g.listen(0, resolve)));
  const port = (fakeGoogle.address() as AddressInfo).port;

  // env must be in place BEFORE the app is imported (env is parsed at import time)
  process.env.GOOGLE_TEST_BASE_URL = `http://127.0.0.1:${port}`;
  process.env.GOOGLE_CLIENT_ID = "test-client-id.apps.googleusercontent.com";
  process.env.GOOGLE_CLIENT_SECRET = "test-client-secret";
  process.env.GOOGLE_CALLBACK_URL = "http://localhost:3999/api/auth/google/callback";
  process.env.OAUTH_SUCCESS_REDIRECT = SUCCESS;

  app = (await import("../src/app")).default;
  users = await import("../src/services/usersService");
  hashPassword = (await import("../src/auth/passwords")).hashPassword;
});

afterAll(() => new Promise<void>((resolve) => fakeGoogle.close(() => resolve())));

let n = 0;
const googleProfile = (over: Record<string, unknown> = {}) => ({
  sub: `google-sub-${Date.now()}-${n++}`,
  name: "Gina Google",
  email: `gina${Date.now()}${n}@gmail.com`,
  email_verified: true,
  ...over,
});

/** Step 1 of the flow: hit /google, return the state value and the cookie the browser would hold. */
const startLogin = async () => {
  const res = await request(app).get("/api/auth/google");
  const location = new URL(res.headers.location);
  const cookie = (res.headers["set-cookie"] as unknown as string[])[0];
  return { res, location, state: location.searchParams.get("state")!, cookie };
};

/** Steps 1+2: complete a login with the given Google profile; returns the callback response. */
const loginWith = async (p: Record<string, unknown>) => {
  profile = p;
  const { state, cookie } = await startLogin();
  return request(app)
    .get("/api/auth/google/callback")
    .query({ code: "fake-auth-code", state })
    .set("Cookie", cookie.split(";")[0]);
};

describe("Part 5 - Google OAuth (against a fake Google)", () => {
  it("step 1 redirects to Google with client id, scopes, a random state, and an httpOnly lax cookie", async () => {
    const { res, location, state, cookie } = await startLogin();
    expect(res.status).toBe(302);
    expect(location.searchParams.get("client_id")).toBe(process.env.GOOGLE_CLIENT_ID);
    expect(location.searchParams.get("scope")).toMatch(/email/);
    expect(location.searchParams.get("redirect_uri")).toBe(process.env.GOOGLE_CALLBACK_URL);
    expect(state.length).toBeGreaterThanOrEqual(40);
    expect(cookie).toContain(`oauth_state=${state}`);
    expect(cookie).toMatch(/HttpOnly/i);
    expect(cookie).toMatch(/SameSite=Lax/i);
    expect(cookie).toMatch(/Path=\/api\/auth\/google/);
    // each attempt gets a fresh state
    expect((await startLogin()).state).not.toBe(state);
  });

  it("full flow: new Google user -> one-time code -> the same JWT pair as password login", async () => {
    const p = googleProfile();
    const cb = await loginWith(p);
    expect(cb.status).toBe(302);
    const dest = new URL(cb.headers.location);
    expect(`${dest.origin}${dest.pathname}`).toBe(SUCCESS);
    const code = dest.searchParams.get("code")!;
    expect(code).toBeTruthy();
    expect(cb.headers.location).not.toMatch(/eyJ/); // no JWT ever travels in a URL

    const ex = await request(app).post("/api/auth/oauth/exchange").send({ code });
    expect(ex.status).toBe(200);
    expect(ex.body.user).toMatchObject({ email: p.email, role: "user" });
    const raw = JSON.stringify(ex.body);
    expect(raw).not.toMatch(/passwordHash|googleId|google-sub/);

    const me = await request(app)
      .get("/api/auth/me")
      .set("Authorization", `Bearer ${ex.body.accessToken}`);
    expect(me.status).toBe(200);
    expect(me.body.user.id).toBe(ex.body.user.id);

    // refresh works too: it really is the same token machinery
    const rf = await request(app)
      .post("/api/auth/refresh")
      .send({ refreshToken: ex.body.refreshToken });
    expect(rf.status).toBe(200);

    // the code is single-use
    expect((await request(app).post("/api/auth/oauth/exchange").send({ code })).status).toBe(401);
  });

  it("returning user is matched by Google id, not email (no duplicate account)", async () => {
    const p = googleProfile();
    const first = await loginWith(p);
    const id1 = (
      await request(app)
        .post("/api/auth/oauth/exchange")
        .send({ code: new URL(first.headers.location).searchParams.get("code") })
    ).body.user.id;
    const second = await loginWith({ ...p, email: `changed-${p.email}` });
    const id2 = (
      await request(app)
        .post("/api/auth/oauth/exchange")
        .send({ code: new URL(second.headers.location).searchParams.get("code") })
    ).body.user.id;
    expect(id2).toBe(id1);
  });

  it("rejects a wrong or missing state (login-CSRF) and creates no user", async () => {
    const p = googleProfile();
    profile = p;
    const { cookie } = await startLogin();
    const wrong = await request(app)
      .get("/api/auth/google/callback")
      .query({ code: "c", state: "attacker-chosen" })
      .set("Cookie", cookie.split(";")[0]);
    expect(new URL(wrong.headers.location).searchParams.get("error")).toBe("invalid_state");

    const noCookie = await request(app)
      .get("/api/auth/google/callback")
      .query({ code: "c", state: "x" });
    expect(new URL(noCookie.headers.location).searchParams.get("error")).toBe("invalid_state");

    const noState = await request(app)
      .get("/api/auth/google/callback")
      .query({ code: "c" })
      .set("Cookie", cookie.split(";")[0]);
    expect(new URL(noState.headers.location).searchParams.get("error")).toBe("invalid_state");
    expect(users.findByEmail((p.email as string).toLowerCase())).toBeUndefined();
  });

  it("rejects an unverified Google email", async () => {
    const p = googleProfile({ email_verified: false });
    const cb = await loginWith(p);
    expect(new URL(cb.headers.location).searchParams.get("error")).toBe("google_email_unverified");
    expect(users.findByEmail((p.email as string).toLowerCase())).toBeUndefined();
  });

  it("never auto-links to an existing password account with the same email", async () => {
    const email = `victim${Date.now()}@gmail.com`;
    users.createUser({
      name: "Pre Registered",
      email,
      passwordHash: await hashPassword("some-password-1"),
      role: "user",
    });
    const cb = await loginWith(googleProfile({ email }));
    expect(new URL(cb.headers.location).searchParams.get("error")).toBe("email_already_registered");
    expect(users.findByEmail(email)!.googleId).toBeUndefined();
  });

  it("Google-only accounts cannot password-login, and are never admins", async () => {
    const p = googleProfile();
    const cb = await loginWith(p);
    const ex = await request(app)
      .post("/api/auth/oauth/exchange")
      .send({ code: new URL(cb.headers.location).searchParams.get("code") });
    expect(ex.body.user.role).toBe("user");
    const pw = await request(app)
      .post("/api/auth/login")
      .send({ email: p.email, password: "anything-at-all-1" });
    expect(pw.status).toBe(401);
  });

  it("user cancelling at Google (?error=access_denied) redirects with an error, no crash", async () => {
    const { state, cookie } = await startLogin();
    const cb = await request(app)
      .get("/api/auth/google/callback")
      .query({ error: "access_denied", state })
      .set("Cookie", cookie.split(";")[0]);
    expect(cb.status).toBe(302);
    expect(new URL(cb.headers.location).searchParams.get("error")).toBeTruthy();
  });

  it("exchange rejects garbage and missing codes", async () => {
    expect(
      (await request(app).post("/api/auth/oauth/exchange").send({ code: "nope" })).status,
    ).toBe(401);
    expect((await request(app).post("/api/auth/oauth/exchange").send({})).status).toBe(400);
  });
});
