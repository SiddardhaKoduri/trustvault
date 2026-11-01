import { Router } from 'express';
import { AuditController } from '../controllers/audit.controller.js';
import { authenticate } from '../middleware/auth.middleware.js';

const router = Router();

// Chain verification status is accessible to authenticated users
router.get('/verify', authenticate, AuditController.verifyAuditChain);

// Full system audit logs (Admin only)
router.get('/', authenticate, AuditController.getSystemAuditLogs);

// Document-specific audit trail (Owner only)
router.get('/document/:id', authenticate, AuditController.getDocumentAuditLogs);

export default router;
