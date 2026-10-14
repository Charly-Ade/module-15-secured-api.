import { Request, Response, NextFunction } from "express";
import * as accountsService from "../services/accountsService";
import {accounts} from "../services/accountsService"
import * as transactionsService from "../services/transactionsService";
import { CreateAccountInput } from "../schemas/accountSchemas";
import { canAccess } from "../auth/ownership";
import { ForbiddenError, UnauthorizedError } from "../middleware/errors";

export const getAccounts = (req: Request, res: Response, next: NextFunction): void => {
  try {
    if (!req.user) throw new UnauthorizedError();
      req.user.role === "admin"
        ? accountsService.getAccounts()
        : accountsService.getAccountsByOwner(req.user.id);
    res.json(accounts);
  } catch (error) {
    next(error);
  }
};

export const getAccountById = (req: Request, res: Response, next: NextFunction): void => {
  try {
    if (!req.user) throw new UnauthorizedError();

    const account = accountsService.getAccountById(String(req.params.id)); 
    if (!canAccess(req.user, account.ownerId)) {
      throw new ForbiddenError("You do not have access to this account");
    }

    res.json(account);
  } catch (error) {
    next(error);
  }
};

export const getAccountTransactions = (req: Request, res: Response, next: NextFunction): void => {
  try {
    if (!req.user) throw new UnauthorizedError();

    const account = accountsService.getAccountById(String(req.params.id));

    if (!canAccess(req.user, account.ownerId)) {
      throw new ForbiddenError("You do not have access to this account");
    }

    res.json(transactionsService.getTransactionsByAccountId(account.id));
  } catch (error) {
    next(error);
  }
};

export const createAccount = (req: Request, res: Response, next: NextFunction): void => {
  try {
    if (!req.user) throw new UnauthorizedError();

    // ownerId comes from the verified token, never from the request body.
    const account = accountsService.createAccount(req.body as CreateAccountInput, req.user.id);
    res.status(201).json(account);
  } catch (error) {
    next(error);
  }
};
