import { Request, Response, NextFunction } from "express";
import { ForbiddenError, UnauthorizedError } from "./errors";
import { Role } from "../types";

/** Role gate. Must run AFTER requireAuth.
 *  - no authenticated user  -> 401 (we don't know who you are)
 *  - known user, wrong role -> 403 (we know who you are; the answer is no) */
export const requireRole =
  (...allowed: Role[]) =>
  (req: Request, _res: Response, next: NextFunction): void => {
    if (!req.user) {
      next(new UnauthorizedError("Authentication required"));
      return;
    }
    if (!allowed.includes(req.user.role)) {
      next(new ForbiddenError());
      return;
    }
    next();
  };
