import { Router } from "express";
import {
  createAccount,
  getAccountById,
  getAccountTransactions,
  getAccounts,
} from "../controllers/accountController";
import { requireAuth } from "../middleware/requireAuth";
import { validateBody } from "../middleware/validateRequest";
import { createAccountSchema } from "../schemas/accountSchemas";

const router = Router();

router.use(requireAuth);

router.get("/", getAccounts);

router.get("/:id", getAccountById);

router.get("/:id/transactions", getAccountTransactions);

router.post("/", validateBody(createAccountSchema), createAccount);

export default router;
