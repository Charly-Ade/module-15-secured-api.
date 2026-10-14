import { Request, Response, NextFunction } from "express";
import { CreateTransactionInput } from "../schemas/transactionsSchemas";
import * as transactionsService from "../services/transactionsService";
import * as accountsService from "../services/accountsService";
import { canAccess } from "../auth/ownership";
import { ForbiddenError, UnauthorizedError } from "../middleware/errors";

export const createTransaction = async (
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> => {
  try {
    if (!req.user) throw new UnauthorizedError();

    const input = req.body as CreateTransactionInput;
    const account = accountsService.getAccountById(input.accountId); // 404 if missing

   
    if (!canAccess(req.user, account.ownerId)) {
      throw new ForbiddenError("You do not have access to this account");
    }

    const transaction = await transactionsService.createTransaction(input);

    res.status(201).json(transaction);
  } catch (error) {
    next(error);
  }
};
