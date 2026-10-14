import { AuthUser } from "../types";

export const canAccess = (user: AuthUser, ownerId: string): boolean =>
  user.role === "admin" || user.id === ownerId;
