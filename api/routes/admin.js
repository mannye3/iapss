import express from 'express';
import { onboardUser } from '../controllers/adminController.js';
import { isAdmin } from '../middlewares/adminMiddleware.js';
import { verifyToken } from '../middlewares/authMiddleware.js';

const router = express.Router();

router.post('/onboard', verifyToken, isAdmin, onboardUser);

export default router;
