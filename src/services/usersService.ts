import { PublicUser, Role, User } from "../types";
import { ConflictError } from "../middleware/errors";

const users: User[] = [];

export const toPublicUser = ({
  passwordHash: _omitPassword,
  googleId: _omitGoogleId,
  ...rest
}: User): PublicUser => rest;

export const findByEmail = (email: string): User | undefined =>
  users.find(
    (user) => user.email.toLowerCase() === email.toLowerCase(),
  );

export const findById = (id: string): User | undefined =>
  users.find((user) => user.id === id);

export const findByGoogleId = (
  googleId: string,
): User | undefined =>
  users.find((user) => user.googleId === googleId);

export const listPublicUsers = (): PublicUser[] =>
  users.map(toPublicUser);

interface NewUser {
  name: string;
  email: string;
  passwordHash: string | null;
  role: Role;
  googleId?: string;
}

export const createUser = (data: NewUser): User => {
  const normalizedEmail = data.email.trim().toLowerCase();

  if (findByEmail(normalizedEmail)) {
    throw new ConflictError("Email is already registered");
  }

  if (data.googleId && findByGoogleId(data.googleId)) {
    throw new ConflictError("Google account is already registered");
  }

  const user: User = {
    id: crypto.randomUUID(),
    name: data.name.trim(),
    email: normalizedEmail,
    passwordHash: data.passwordHash,
    role: data.role,
    createdAt: new Date().toISOString(),
    ...(data.googleId ? { googleId: data.googleId } : {}),
  };

  users.push(user);

  return user;
};