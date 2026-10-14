import { env } from "../config/env";
import { hashPassword } from "../auth/passwords";
import { passwordSchema } from "../schemas/authSchemas";
import * as usersService from "./usersService";

export const seedAdmin = async (): Promise<void> => {
  const { SEED_ADMIN_EMAIL, SEED_ADMIN_PASSWORD } = env;
  if (!SEED_ADMIN_EMAIL || !SEED_ADMIN_PASSWORD) return;

  const password = passwordSchema.parse(SEED_ADMIN_PASSWORD);
  const email = SEED_ADMIN_EMAIL.trim().toLowerCase();
  if (usersService.findByEmail(email)) return;

  usersService.createUser({
    name: "Seed Admin",
    email,
    passwordHash: await hashPassword(password),
    role: "admin",
  });
  console.log(`Seeded admin user ${email}`);
};
