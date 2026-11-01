import { Router } from 'express';
import multer from 'multer';
import { DocumentController } from '../controllers/document.controller.js';
import { authenticate } from '../middleware/auth.middleware.js';

const router = Router();

// Configure strictly memory-based upload with 5 MB threshold
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
});

// All document vault routes require active authentication
router.use(authenticate);

// Document CRUD & Streaming
router.post('/', upload.single('file'), DocumentController.uploadDocument);
router.get('/', DocumentController.listDocuments);
router.get('/:id', DocumentController.getDocument);
router.get('/:id/download', DocumentController.downloadDocument);

// Versioning
router.post('/:id/versions', upload.single('file'), DocumentController.uploadNewVersion);
router.get('/:id/versions/:versionNumber/download', DocumentController.downloadVersion);

// Permissions & Sharing (Owner Only)
router.post('/:id/permissions', DocumentController.shareDocument);
router.delete('/:id/permissions/:userId', DocumentController.revokePermission);

// Trash / Restore
router.delete('/:id', DocumentController.softDeleteDocument);
router.post('/:id/restore', DocumentController.restoreDocument);

export default router;
