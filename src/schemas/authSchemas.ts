import { z } from "zod";

const email = z.string().trim().toLowerCase().pipe(z.email("Invalid email address"));


const MAX_PASSWORD_BYTES = 72;
const withinBcryptLimit = (value: string) => Buffer.byteLength(value, "utf8") <= MAX_PASSWORD_BYTES;

export const passwordSchema = z
  .string()
  .min(8, "Password must be at least 8 characters")
  .refine(withinBcryptLimit, `Password must be at most ${MAX_PASSWORD_BYTES} bytes`);

export const registerSchema = z.object({
  name: z.string().trim().min(2, "Name must be at least 2 characters").max(100),
  email,
  password: passwordSchema,
});

export const loginSchema = z.object({
  email,
  password: z.string().min(1, "Password is required").refine(withinBcryptLimit, "Invalid password"),
});

export const refreshSchema = z.object({
  refreshToken: z.string().min(1, "refreshToken is required"),
});

export type RegisterInput = z.infer<typeof registerSchema>;
export type LoginInput = z.infer<typeof loginSchema>;
export type RefreshInput = z.infer<typeof refreshSchema>;
