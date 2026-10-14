import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import jwt from "jsonwebtoken";
import {
  api,
  bearer,
  createAdminAndLogin,
  newAccount,
  PASSWORD,
  registerAndLogin,
  uniqueEmail,
} from "./helpers";

type Event = Record<string, unknown>;
let lines: string[];

beforeEach(() => {
  lines = [];
  vi.spyOn(console, "warn").mockImplementation((line: unknown) => {
    lines.push(String(line));
  });
});
afterEach(() => vi.restoreAllMocks());

const events = (): Event[] =>
  lines.map((l) => JSON.parse(l) as Event).filter((e) => e.type === "security");
const find = (name: string) => events().filter((e) => e.event === name);

describe("A09 - security event logging", () => {
  it("logs failed and successful logins with a fingerprint, never the email or password", async () => {
    const s = await registerAndLogin();
    lines = [];
    await api().post("/api/auth/login").send({ email: s.email, password: "wrong-password-1" });
    const ghost = uniqueEmail("ghost");
    await api().post("/api/auth/login").send({ email: ghost, password: "wrong-password-2" });
    await api().post("/api/auth/login").send({ email: s.email, password: PASSWORD });

    const failed = find("login_failed");
    expect(failed.map((e) => e.reason)).toEqual(["bad_password", "unknown_user"]);
    expect(failed[0].account).toMatch(/^[0-9a-f]{12}$/);
    expect(failed[0].ip).toBeTruthy();
    expect(find("login_success")).toHaveLength(1);

    const all = lines.join("\n");
    expect(all).not.toContain(s.email);
    expect(all).not.toContain(ghost);
    expect(all).not.toContain("wrong-password");
    expect(all).not.toContain(PASSWORD);
  });

  it("logs 403s (access_denied) with who/where, and rejected tokens", async () => {
    const user = await registerAndLogin();
    lines = [];
    await api().get("/api/admin/users").set(bearer(user.accessToken));
    const denied = find("access_denied");
    expect(denied).toHaveLength(1);
    expect(denied[0]).toMatchObject({
      userId: user.id,
      role: "user",
      method: "GET",
      path: "/api/admin/users",
    });

    await api().get("/api/auth/me").set(bearer("garbage.token.value"));
    expect(find("token_rejected")).toHaveLength(1);

    // a request with NO credentials is ordinary traffic, not logged as a rejected token
    lines = [];
    await api().get("/api/accounts");
    expect(find("token_rejected")).toHaveLength(0);
  });

  it("logs the full path but never the query string (could hold OAuth codes)", async () => {
    await api()
      .get("/api/auth/me?code=SECRET-CODE-123&state=SECRET-STATE")
      .set(bearer("bad.token.x"));
    const rejected = find("token_rejected")[0];
    expect(rejected.path).toBe("/api/auth/me");
    expect(lines.join("\n")).not.toMatch(/SECRET-CODE|SECRET-STATE/);
  });

  it("logs ownership 403s on resources too", async () => {
    const a = await registerAndLogin("Alice Adams");
    const b = await registerAndLogin("Bobby Brown");
    const acct = (await newAccount(a.accessToken)).body;
    lines = [];
    await api().get(`/api/accounts/${acct.id}`).set(bearer(b.accessToken));
    expect(find("access_denied")[0]).toMatchObject({ userId: b.id });
  });

  it("flags refresh-token reuse (possible theft)", async () => {
    const s = await registerAndLogin();
    await api().post("/api/auth/refresh").send({ refreshToken: s.refreshToken });
    lines = [];
    await api().post("/api/auth/refresh").send({ refreshToken: s.refreshToken });
    const reuse = find("refresh_reuse_detected");
    expect(reuse).toHaveLength(1);
    expect(reuse[0].userId).toBe(s.id);
  });

  it("no log line anywhere contains a token, a hash, or a secret", async () => {
    const admin = await createAdminAndLogin();
    const user = await registerAndLogin();
    await api().post("/api/auth/refresh").send({ refreshToken: user.refreshToken });
    await api().post("/api/auth/refresh").send({ refreshToken: user.refreshToken });
    await api().get("/api/admin/users").set(bearer(user.accessToken));
    await api()
      .get("/api/auth/me")
      .set(bearer(`${user.accessToken.slice(0, -2)}xx`));
    const forged = jwt.sign({ role: "admin" }, "attacker-secret-attacker-secret-1234", {
      subject: user.id,
    });
    await api().get("/api/admin/users").set(bearer(forged));

    const all = lines.join("\n");
    for (const secret of [
      user.accessToken,
      user.refreshToken,
      admin.accessToken,
      forged,
      "$2b$",
      process.env.JWT_ACCESS_SECRET!,
      process.env.JWT_REFRESH_SECRET!,
    ]) {
      expect(all).not.toContain(secret);
    }
    expect(all).not.toMatch(/eyJ[A-Za-z0-9_-]{10,}/); // nothing JWT-shaped
  });
});
