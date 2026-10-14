import { Router } from "express";
import { createTransaction } from "../controllers/transactionsController";
import { requireAuth } from "../middleware/requireAuth";
import { validateBody } from "../middleware/validateRequest";
import { createTransactionSchema } from "../schemas/transactionsSchemas";

const router = Router();

router.post("/", requireAuth, validateBody(createTransactionSchema), createTransaction);

export default router;
