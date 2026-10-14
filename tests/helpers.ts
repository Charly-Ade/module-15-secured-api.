import request from "supertest";
import app from "../src/app";
import { hashPassword } from "../src/auth/passwords";
import * as usersService from "../src/services/usersService";

export const api = () => request(app);

let counter = 0;
export const uniqueEmail = (prefix = "user") => `${prefix}${Date.now()}${counter++}@example.com`;

export const PASSWORD = "correct-horse-battery";

export interface Session {
  id: string;
  email: string;
  accessToken: string;
  refreshToken: string;
}

export const registerAndLogin = async (name = "Test User"): Promise<Session> => {
  const email = uniqueEmail();
  const reg = await api().post("/api/auth/register").send({ name, email, password: PASSWORD });
  if (reg.status !== 201)
    throw new Error(`register failed: ${reg.status} ${JSON.stringify(reg.body)}`);
  const login = await api().post("/api/auth/login").send({ email, password: PASSWORD });
  if (login.status !== 200) throw new Error(`login failed: ${login.status}`);
  return {
    id: login.body.user.id,
    email,
    accessToken: login.body.accessToken,
    refreshToken: login.body.refreshToken,
  };
};

/** Admins can't self-register (by design), so tests create one directly in the store. */
export const createAdminAndLogin = async (): Promise<Session> => {
  const email = uniqueEmail("admin");
  usersService.createUser({
    name: "Admin User",
    email,
    passwordHash: await hashPassword(PASSWORD),
    role: "admin",
  });
  const login = await api().post("/api/auth/login").send({ email, password: PASSWORD });
  return {
    id: login.body.user.id,
    email,
    accessToken: login.body.accessToken,
    refreshToken: login.body.refreshToken,
  };
};

export const bearer = (token: string) => ({ Authorization: `Bearer ${token}` });

export const newAccount = (token: string, overrides: object = {}) =>
  api()
    .post("/api/accounts")
    .set(bearer(token))
    .send({
      name: "Main Account",
      email: "owner@example.com",
      accountType: "savings",
      initialDeposit: 100,
      ...overrides,
    });
