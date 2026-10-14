import { env } from "../config/env";
import { getDummyHash, hashPassword, verifyPassword } from "../auth/passwords";
import { signAccessToken, signRefreshToken, verifyRefreshToken } from "../auth/tokens";
import { ConflictError, UnauthorizedError } from "../middleware/errors";
import { LoginInput, RegisterInput } from "../schemas/authSchemas";
import { PublicUser, User } from "../types";
import * as usersService from "./usersService";

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
  tokenType: "Bearer";
  expiresIn: number;
}

const activeRefreshTokens = new Map<string, { userId: string; expiresAt: number }>();

const purgeExpired = (): void => {
  const now = Date.now();
  for (const [jti, entry] of activeRefreshTokens) {
    if (entry.expiresAt <= now) activeRefreshTokens.delete(jti);
  }
};

const revokeAllForUser = (userId: string): void => {
  for (const [jti, entry] of activeRefreshTokens) {
    if (entry.userId === userId) activeRefreshTokens.delete(jti);
  }
};

export const issueTokenPair = (user: Pick<User, "id" | "role">): TokenPair => {
  purgeExpired();
  const jti = crypto.randomUUID();
  activeRefreshTokens.set(jti, {
    userId: user.id,
    expiresAt: Date.now() + env.REFRESH_TOKEN_TTL_SECONDS * 1000,
  });

  return {
    accessToken: signAccessToken({ id: user.id, role: user.role }),
    refreshToken: signRefreshToken(user.id, jti),
    tokenType: "Bearer",
    expiresIn: env.ACCESS_TOKEN_TTL_SECONDS,
  };
};

export const register = async (input: RegisterInput): Promise<PublicUser> => {
  // Cheap early rejection; createUser() re-checks atomically after the slow hash.
  if (usersService.findByEmail(input.email)) {
    throw new ConflictError("Email is already registered");
  }

  const passwordHash = await hashPassword(input.password);
  const user = usersService.createUser({
    name: input.name,
    email: input.email,
    passwordHash,
    role: "user", // always "user": admins are seeded, never self-registered
  });
  return usersService.toPublicUser(user);
};

export const login = async (input: LoginInput): Promise<{ user: PublicUser } & TokenPair> => {
  const user = usersService.findByEmail(input.email);

  // Always run exactly one bcrypt compare, whether or not the user exists.
  const passwordOk = await verifyPassword(
    input.password,
    user?.passwordHash ?? (await getDummyHash()),
  );

  if (!user || !passwordOk) {
    // Same message for "no such user" and "wrong password" (no account enumeration).
    throw new UnauthorizedError("Invalid email or password");
  }

  return { user: usersService.toPublicUser(user), ...issueTokenPair(user) };
};

/** Refresh-token rotation: each refresh token is single-use. Presenting one that was already
 *  used (or revoked) means it may have been stolen, so every session for that user is revoked. */
export const refresh = (refreshToken: string): TokenPair => {
  const { userId, jti } = verifyRefreshToken(refreshToken);

  if (!activeRefreshTokens.has(jti)) {
    revokeAllForUser(userId);
    throw new UnauthorizedError("Invalid refresh token");
  }
  activeRefreshTokens.delete(jti);

  // Re-read the user so role changes / deletions are picked up at refresh time.
  const user = usersService.findById(userId);
  if (!user) throw new UnauthorizedError("Invalid refresh token");

  return issueTokenPair(user);
};

export const logout = (refreshToken: string): void => {
  try {
    const { jti } = verifyRefreshToken(refreshToken);
    activeRefreshTokens.delete(jti);
  } catch {
    // Logging out with a bad/expired token is a no-op, not an error.
  }
};
