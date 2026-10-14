import { Router } from "express";
import * as authController from "../controllers/authController";
import { authLimiter } from "../middleware/rateLimiters";
import { requireAuth } from "../middleware/requireAuth";
import { validateBody } from "../middleware/validateRequest";
import { loginSchema, refreshSchema, registerSchema } from "../schemas/authSchemas";

const router = Router();


router.post("/register", authLimiter, validateBody(registerSchema), authController.register);
router.post("/login", authLimiter, validateBody(loginSchema), authController.login);

router.post("/refresh", validateBody(refreshSchema), authController.refresh);
router.post("/logout", validateBody(refreshSchema), authController.logout);
router.get("/me", requireAuth, authController.me);

export default router;
