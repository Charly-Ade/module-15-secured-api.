export type AccountType = "savings" | "current";

export type TransactionType = "deposit" | "withdrawal";

export type Role = "user" | "admin";

export interface Account {
  id: string;
  ownerId: string;
  name: string;
  email: string;
  accountType: AccountType;
  balance: number;
}

export interface Transaction {
  id: string;
  accountId: string;
  type: TransactionType;
  amount: number;
  description?: string;
  createdAt: string;
}

export interface User {
  id: string;
  name: string;
  email: string;
  passwordHash: string | null;
  role: Role;
  createdAt: string;
  googleId?: string;
}

export type PublicUser = Omit<User, "passwordHash">;

export interface AuthUser {
  id: string;
  role: Role;
}
