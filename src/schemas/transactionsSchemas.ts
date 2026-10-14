import { z } from "zod";

export const createTransactionSchema = z.object({
  accountId: z.string().min(1, "Account ID is required"),
  type: z.enum(["deposit", "withdrawal"]),
  amount: z.number().positive("Amount must be greater than zero"),
  description: z.string().optional(),
});

export type CreateTransactionInput = z.infer<typeof createTransactionSchema>;
