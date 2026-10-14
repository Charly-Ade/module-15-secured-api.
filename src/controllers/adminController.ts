import { Request, Response, NextFunction } from "express";
import * as usersService from "../services/usersService";

export const listUsers = (req: Request, res: Response, next: NextFunction): void => {
  try {
    res.json(usersService.listPublicUsers());
  } catch (error) {
    next(error);
  }
};
