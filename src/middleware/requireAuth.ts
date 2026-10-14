import { Request, Response, NextFunction } from "express";
import { verifyAccessToken } from "../auth/tokens";
import { AuthUser } from "../types";

declare global {
  namespace Express {
    interface Request {
      authUser?: AuthUser;
    }
  }
}

export const requireAuth = (
  req: Request,
  res: Response,
  next: NextFunction,
): void => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    res.status(401).json({ error: "Authentication required" });
    return;
  }

  const token = authHeader.slice(7);

  try {
    req.authUser = verifyAccessToken(token);
    next();
  } catch {
    res.status(401).json({ error: "Invalid or expired access token" });
  }
};