import { describe, expect, it } from "vitest";
import { api, bearer, createAdminAndLogin, newAccount, registerAndLogin } from "./helpers";

describe("Part 3 - role-based & resource-level authorization", () => {
  it("requireRole: 401 anonymous, 403 for a logged-in non-admin, 200 for admin", async () => {
    const user = await registerAndLogin();
    const admin = await createAdminAndLogin();

    expect((await api().get("/api/admin/users")).status).toBe(401);

    const forbidden = await api().get("/api/admin/users").set(bearer(user.accessToken));
    expect(forbidden.status).toBe(403); // known user, insufficient privilege: 403 NOT 401

    const ok = await api().get("/api/admin/users").set(bearer(admin.accessToken));
    expect(ok.status).toBe(200);
    expect(Array.isArray(ok.body)).toBe(true);
    expect(JSON.stringify(ok.body)).not.toMatch(/password|\$2b\$/i); // no hashes, ever
    expect(ok.body.some((u: { role: string }) => u.role === "admin")).toBe(true);
  });

  it("role claim is in the JWT and admin gets it", async () => {
    const admin = await createAdminAndLogin();
    const payload = JSON.parse(
      Buffer.from(admin.accessToken.split(".")[1], "base64url").toString(),
    );
    expect(payload.role).toBe("admin");
  });

  it("all account routes require authentication (401)", async () => {
    expect((await api().get("/api/accounts")).status).toBe(401);
    expect((await api().post("/api/accounts").send({})).status).toBe(401);
    expect((await api().get("/api/accounts/abc")).status).toBe(401);
    expect((await api().get("/api/accounts/abc/transactions")).status).toBe(401);
    expect((await api().post("/api/transactions").send({})).status).toBe(401);
  });

  it("owner sees own account; other user gets 403; admin gets 200", async () => {
    const alice = await registerAndLogin("Alice Adams");
    const bob = await registerAndLogin("Bobby Brown");
    const admin = await createAdminAndLogin();

    const created = await newAccount(alice.accessToken);
    expect(created.status).toBe(201);
    expect(created.body.ownerId).toBe(alice.id);
    const id = created.body.id;

    expect((await api().get(`/api/accounts/${id}`).set(bearer(alice.accessToken))).status).toBe(
      200,
    );
    expect((await api().get(`/api/accounts/${id}`).set(bearer(bob.accessToken))).status).toBe(403);
    expect((await api().get(`/api/accounts/${id}`).set(bearer(admin.accessToken))).status).toBe(
      200,
    );
  });

  it("ignores a client-supplied ownerId on account creation", async () => {
    const alice = await registerAndLogin("Alice Adams");
    const bob = await registerAndLogin("Bobby Brown");
    const res = await newAccount(alice.accessToken, { ownerId: bob.id });
    expect(res.status).toBe(201);
    expect(res.body.ownerId).toBe(alice.id);
  });

  it("listing: users see only their own accounts, admins see all", async () => {
    const alice = await registerAndLogin("Alice Adams");
    const bob = await registerAndLogin("Bobby Brown");
    const admin = await createAdminAndLogin();
    const a = await newAccount(alice.accessToken);
    const b = await newAccount(bob.accessToken);

    const aliceList = await api().get("/api/accounts").set(bearer(alice.accessToken));
    expect(aliceList.body.map((x: { id: string }) => x.id)).toEqual([a.body.id]);

    const adminIds = (await api().get("/api/accounts").set(bearer(admin.accessToken))).body.map(
      (x: { id: string }) => x.id,
    );
    expect(adminIds).toEqual(expect.arrayContaining([a.body.id, b.body.id]));
  });

  it("transactions: owner and admin allowed, other users 403 (create and read)", async () => {
    const alice = await registerAndLogin("Alice Adams");
    const bob = await registerAndLogin("Bobby Brown");
    const admin = await createAdminAndLogin();
    const acct = (await newAccount(alice.accessToken)).body;
    const tx = { accountId: acct.id, type: "deposit", amount: 50 };

    expect(
      (await api().post("/api/transactions").set(bearer(bob.accessToken)).send(tx)).status,
    ).toBe(403);
    expect(
      (await api().post("/api/transactions").set(bearer(alice.accessToken)).send(tx)).status,
    ).toBe(201);
    expect(
      (await api().post("/api/transactions").set(bearer(admin.accessToken)).send(tx)).status,
    ).toBe(201);

    expect(
      (await api().get(`/api/accounts/${acct.id}/transactions`).set(bearer(bob.accessToken)))
        .status,
    ).toBe(403);
    const read = await api()
      .get(`/api/accounts/${acct.id}/transactions`)
      .set(bearer(alice.accessToken));
    expect(read.status).toBe(200);
    expect(read.body).toHaveLength(2);
  });

  it("returns 404 for a missing account and 422 for an overdraft (not 500)", async () => {
    const alice = await registerAndLogin("Alice Adams");
    expect(
      (await api().get("/api/accounts/does-not-exist").set(bearer(alice.accessToken))).status,
    ).toBe(404);

    const acct = (await newAccount(alice.accessToken, { initialDeposit: 10 })).body;
    const over = await api()
      .post("/api/transactions")
      .set(bearer(alice.accessToken))
      .send({ accountId: acct.id, type: "withdrawal", amount: 999 });
    expect(over.status).toBe(422);
  });

  it("re-enabled Zod validation rejects bad account/transaction bodies with 400", async () => {
    const alice = await registerAndLogin("Alice Adams");
    expect((await newAccount(alice.accessToken, { initialDeposit: -5 })).status).toBe(400);
    const tx = await api()
      .post("/api/transactions")
      .set(bearer(alice.accessToken))
      .send({ accountId: "x", type: "deposit", amount: -1 });
    expect(tx.status).toBe(400);
  });
});
