import { Router } from 'express';
import { AdminController } from '../controllers/admin.controller.js';
import { authenticate, requireRole } from '../middleware/auth.middleware.js';

const router = Router();

// All admin routes strictly require valid authentication and ADMIN role
router.use(authenticate, requireRole(['ADMIN']));

router.get('/users', AdminController.listUsers);
router.patch('/users/:id/status', AdminController.updateUserStatus);
router.post('/users', AdminController.createUser);

export default router;
