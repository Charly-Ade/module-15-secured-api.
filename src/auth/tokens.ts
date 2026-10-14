import jwt from "jsonwebtoken";
import { z } from "zod";
import { env } from "../config/env";
import { UnauthorizedError } from "../middleware/errors";
import { AuthUser, Role } from "../types";

const ISSUER = "module-15-secured-api";
const AUDIENCE = "module-15-secured-api-clients";
const ALGORITHM = "HS256" as const;

const accessClaims = z.object({
  sub: z.string().min(1),
  role: z.enum(["user", "admin"]),
});

const refreshClaims = z.object({
  sub: z.string().min(1),
  jti: z.string().min(1),
});

export const signAccessToken = (user: AuthUser): string =>
  jwt.sign({ role: user.role satisfies Role }, env.JWT_ACCESS_SECRET, {
    algorithm: ALGORITHM,
    subject: user.id,
    issuer: ISSUER,
    audience: AUDIENCE,
    expiresIn: env.ACCESS_TOKEN_TTL_SECONDS,
  });

export const signRefreshToken = (userId: string, jti: string): string =>
  jwt.sign({}, env.JWT_REFRESH_SECRET, {
    algorithm: ALGORITHM,
    subject: userId,
    jwtid: jti,
    issuer: ISSUER,
    audience: AUDIENCE,
    expiresIn: env.REFRESH_TOKEN_TTL_SECONDS,
  });

const verify = (token: string, secret: string, kind: string): jwt.JwtPayload => {
  try {
    return jwt.verify(token, secret, {
      algorithms: [ALGORITHM],
      issuer: ISSUER,
      audience: AUDIENCE,
    }) as jwt.JwtPayload;
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      throw new UnauthorizedError(`${kind} token expired`);
    }
    throw new UnauthorizedError(`Invalid ${kind.toLowerCase()} token`);
  }
};

export const verifyAccessToken = (token: string): AuthUser => {
  const claims = accessClaims.safeParse(verify(token, env.JWT_ACCESS_SECRET, "Access"));
  if (!claims.success) throw new UnauthorizedError("Invalid access token");
  return { id: claims.data.sub, role: claims.data.role };
};

export const verifyRefreshToken = (token: string): { userId: string; jti: string } => {
  const claims = refreshClaims.safeParse(verify(token, env.JWT_REFRESH_SECRET, "Refresh"));
  if (!claims.success) throw new UnauthorizedError("Invalid refresh token");
  return { userId: claims.data.sub, jti: claims.data.jti };
};
