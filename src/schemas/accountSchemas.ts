import { z } from "zod";

export const createAccountSchema = z.object({
  name: z.string().min(5, "Name must be at least 5 characters"),
  email: z.string().email("Invalid email address"),
  accountType: z.enum(["savings", "current"]),
  initialDeposit: z.number().nonnegative("Initial deposit cannot be negative"),
});

export type CreateAccountInput = z.infer<typeof createAccountSchema>;
