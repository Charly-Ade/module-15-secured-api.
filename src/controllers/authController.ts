import { Request, Response, NextFunction } from "express";
import * as authService from "../services/authService";
import * as usersService from "../services/usersService";
import { LoginInput, RefreshInput, RegisterInput } from "../schemas/authSchemas";
import { NotFoundError, UnauthorizedError } from "../middleware/errors";

export const register = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    const user = await authService.register(req.body as RegisterInput);
    res.status(201).json({ user });
  } catch (error) {
    next(error);
  }
};

export const login = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    res.json(await authService.login(req.body as LoginInput));
  } catch (error) {
    next(error);
  }
};

export const refresh = (req: Request, res: Response, next: NextFunction): void => {
  try {
    res.json(authService.refresh((req.body as RefreshInput).refreshToken));
  } catch (error) {
    next(error);
  }
};

export const logout = (req: Request, res: Response, next: NextFunction): void => {
  try {
    authService.logout((req.body as RefreshInput).refreshToken);
    res.status(204).end();
  } catch (error) {
    next(error);
  }
};

export const me = (req: Request, res: Response, next: NextFunction): void => {
  try {
    if (!req.user) throw new UnauthorizedError();
    const user = usersService.findById(req.user.id);
    if (!user) throw new NotFoundError("User not found");
    res.json({ user: usersService.toPublicUser(user) });
  } catch (error) {
    next(error);
  }
};
