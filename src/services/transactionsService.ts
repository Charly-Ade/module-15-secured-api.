import { Transaction } from "../types";
import { CreateTransactionInput } from "../schemas/transactionsSchemas";
import { BusinessRuleError } from "../middleware/errors";
import * as accountsService from "./accountsService";

const transactions: Transaction[] = [];

export const getTransactions = (): Transaction[] => {
  return transactions;
};

export const getTransactionsByAccountId = (accountId: string): Transaction[] => {
  accountsService.getAccountById(accountId);

  return transactions.filter((transaction) => transaction.accountId === accountId);
};

export const createTransaction = (data: CreateTransactionInput): Transaction => {
  const account = accountsService.getAccountById(data.accountId);

  if (data.type === "withdrawal" && account.balance < data.amount) {
    throw new BusinessRuleError("Insufficient account balance");
  }

  if (data.type === "deposit") {
    account.balance += data.amount;
  } else {
    account.balance -= data.amount;
  }

  const transaction: Transaction = {
    id: crypto.randomUUID(),
    accountId: data.accountId,
    type: data.type,
    amount: data.amount,
    description: data.description,
    createdAt: new Date().toISOString(),
  };

  transactions.push(transaction);

  return transaction;
};
