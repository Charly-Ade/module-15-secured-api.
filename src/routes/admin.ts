import { Router } from "express";
import { listUsers } from "../controllers/adminController";
import { requireAuth } from "../middleware/requireAuth";
import { requireRole } from "../middleware/requireRole";

const router = Router();


router.use(requireAuth, requireRole("admin"));

router.get("/users", listUsers);

export default router;
