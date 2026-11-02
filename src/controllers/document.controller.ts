import { Response } from 'express';
import { z } from 'zod';
import { prisma } from '../lib/prisma.js';
import { FileService } from '../services/file.service.js';
import { PolicyDecisionPoint } from '../services/pdp.service.js';
import { AuditService } from '../services/audit.service.js';
import { AuthenticatedRequest } from '../types/index.js';

const ShareSchema = z.object({
  email: z.string().email(),
  accessLevel: z.enum(['READ', 'EDIT']),
});

export class DocumentController {
  /**
   * Uploads a new document to the vault.
   * Enforces 5 MB limit, magic-byte inspection, filename sanitization, and isolated UUID disk storage.
   */
  static async uploadDocument(req: AuthenticatedRequest, res: Response) {
    if (!req.user) return res.status(401).json({ error: 'Authentication required' });

    // Multer single file in memory
    const file = req.file;
    if (!file) {
      return res.status(400).json({ error: 'No file uploaded.' });
    }

    // 1. File Size Guard (5 MB max)
    const MAX_SIZE = 5 * 1024 * 1024;
    if (file.size > MAX_SIZE) {
      await AuditService.recordEvent({
        userId: req.user.id,
        userEmail: req.user.email,
        action: 'MALICIOUS_UPLOAD_ATTEMPT',
        resourceType: 'DOCUMENT',
        resourceId: 'UPLOAD_REJECTED',
        outcome: 'DENIED',
        reason: `PAYLOAD_TOO_LARGE: ${file.size} bytes exceeds 5MB limit`,
        clientIp: req.clientIp,
      });
      return res.status(400).json({ error: 'File size exceeds 5 MB limit.' });
    }

    // 2. Binary Magic-Byte Inspection (Sniffs true header bytes)
    const validation = FileService.validateMagicBytes(file.buffer);
    if (!validation.valid || !validation.detectedMimeType) {
      await AuditService.recordEvent({
        userId: req.user.id,
        userEmail: req.user.email,
        action: 'MALICIOUS_UPLOAD_ATTEMPT',
        resourceType: 'DOCUMENT',
        resourceId: 'UPLOAD_REJECTED',
        outcome: 'DENIED',
        reason: `MIME_SPOOF_OR_UNSUPPORTED: ${validation.error}`,
        clientIp: req.clientIp,
      });
      return res.status(400).json({ error: validation.error });
    }

    // 3. Path Traversal Neutralization & Title Extraction
    const originalName = file.originalname || 'document.pdf';
    const sanitizedTitle = req.body.title
      ? FileService.sanitizeFilename(req.body.title)
      : FileService.sanitizeFilename(originalName);

    const description = req.body.description ? String(req.body.description).slice(0, 500) : null;
    const category = req.body.category ? String(req.body.category).slice(0, 50) : 'General';

    try {
      // 4. Save blob to isolated storage using non-deterministic UUID
      const storageKey = await FileService.saveBlob(file.buffer);

      // 5. Commit document & initial version to database in transaction
      const document = await prisma.$transaction(async (tx) => {
        const doc = await tx.document.create({
          data: {
            title: sanitizedTitle,
            description,
            category,
            ownerId: req.user!.id,
            currentStorageKey: storageKey,
            currentMimeType: validation.detectedMimeType!,
            currentByteSize: file.size,
            currentVersion: 1,
          },
        });

        await tx.documentVersion.create({
          data: {
            documentId: doc.id,
            versionNumber: 1,
            storageKey,
            mimeType: validation.detectedMimeType!,
            byteSize: file.size,
            changeSummary: 'Initial upload',
            uploadedById: req.user!.id,
          },
        });

        return doc;
      });

      // 6. Record successful upload in audit trail
      await AuditService.recordEvent({
        userId: req.user.id,
        userEmail: req.user.email,
        action: 'DOC_UPLOAD',
        resourceType: 'DOCUMENT',
        resourceId: document.id,
        outcome: 'SUCCESS',
        reason: `Created document '${sanitizedTitle}' (v1, ${file.size} bytes)`,
        clientIp: req.clientIp,
      });

      return res.status(201).json({
        message: 'Document uploaded successfully',
        document: {
          id: document.id,
          title: document.title,
          category: document.category,
          currentVersion: document.currentVersion,
          byteSize: document.currentByteSize,
          mimeType: document.currentMimeType,
          createdAt: document.createdAt,
        },
      });
    } catch (error) {
      console.error('Document upload error:', error);
      return res.status(500).json({ error: 'Failed to commit document to vault.' });
    }
  }

  /**
   * Lists all documents accessible to the current user (owned + explicitly shared).
   * ZERO METADATA LEAKAGE: Never discloses unshared files, even to Administrators.
   */
  static async listDocuments(req: AuthenticatedRequest, res: Response) {
    if (!req.user) return res.status(401).json({ error: 'Authentication required' });

    const search = req.query.search ? String(req.query.search).trim() : '';
    const category = req.query.category ? String(req.query.category).trim() : '';
    const showTrash = req.query.trash === 'true';

    try {
      // 1. Fetch documents where current user is Owner
      const ownedDocs = await prisma.document.findMany({
        where: {
          ownerId: req.user.id,
          isDeleted: showTrash,
          ...(search ? { title: { contains: search } } : {}),
          ...(category ? { category } : {}),
        },
        include: {
          owner: { select: { id: true, name: true, email: true } },
          permissions: { include: { user: { select: { id: true, name: true, email: true } } } },
        },
        orderBy: { updatedAt: 'desc' },
      });

      // 2. Fetch documents explicitly shared with current user (only active, non-trash)
      let sharedDocs: any[] = [];
      if (!showTrash) {
        const sharedPermissions = await prisma.documentPermission.findMany({
          where: {
            userId: req.user.id,
            document: {
              isDeleted: false,
              ...(search ? { title: { contains: search } } : {}),
              ...(category ? { category } : {}),
            },
          },
          include: {
            document: {
              include: {
                owner: { select: { id: true, name: true, email: true } },
              },
            },
          },
          orderBy: { updatedAt: 'desc' },
        });

        sharedDocs = sharedPermissions.map((p) => ({
          ...p.document,
          userAccessLevel: p.accessLevel,
        }));
      }

      // Format response with explicit access level
      const formattedOwned = ownedDocs.map((d) => ({
        ...d,
        userAccessLevel: 'OWNER',
      }));

      return res.status(200).json({
        documents: [...formattedOwned, ...sharedDocs],
      });
    } catch (error) {
      console.error('List documents error:', error);
      return res.status(500).json({ error: 'Failed to retrieve documents.' });
    }
  }

  /**
   * Retrieves document metadata after verifying permissions at PDP.
   */
  static async getDocument(req: AuthenticatedRequest, res: Response) {
    if (!req.user) return res.status(401).json({ error: 'Authentication required' });
    const { id } = req.params;

    const authResult = await PolicyDecisionPoint.authorize(req.user, id, 'READ', {
      clientIp: req.clientIp,
    });

    if (!authResult.authorized) {
      return res.status(authResult.statusCode || 403).json({ error: authResult.reason });
    }

    const doc = await prisma.document.findUnique({
      where: { id },
      include: {
        owner: { select: { id: true, name: true, email: true } },
        versions: {
          select: {
            id: true,
            versionNumber: true,
            byteSize: true,
            mimeType: true,
            changeSummary: true,
            createdAt: true,
            uploadedBy: { select: { id: true, name: true, email: true } },
          },
          orderBy: { versionNumber: 'desc' },
        },
        permissions: {
          include: { user: { select: { id: true, name: true, email: true } } },
        },
      },
    });

    await AuditService.recordEvent({
      userId: req.user.id,
      userEmail: req.user.email,
      action: 'DOC_VIEW',
      resourceType: 'DOCUMENT',
      resourceId: id,
      outcome: 'SUCCESS',
      reason: `Viewed metadata for document '${doc?.title}'`,
      clientIp: req.clientIp,
    });

    return res.status(200).json({
      document: doc,
      userAccessLevel: authResult.accessLevel,
    });
  }

  /**
   * Streams the document binary file from disk.
   */
  static async downloadDocument(req: AuthenticatedRequest, res: Response) {
    if (!req.user) return res.status(401).json({ error: 'Authentication required' });
    const { id } = req.params;

    const authResult = await PolicyDecisionPoint.authorize(req.user, id, 'DOWNLOAD', {
      clientIp: req.clientIp,
    });

    if (!authResult.authorized) {
      return res.status(authResult.statusCode || 403).json({ error: authResult.reason });
    }

    const doc = authResult.document;

    try {
      const stream = FileService.getBlobStream(doc.currentStorageKey);

      res.setHeader('Content-Type', doc.currentMimeType);
      res.setHeader('Content-Disposition', `attachment; filename="${doc.title}"`);
      res.setHeader('X-Content-Type-Options', 'nosniff');

      await AuditService.recordEvent({
        userId: req.user.id,
        userEmail: req.user.email,
        action: 'DOC_DOWNLOAD',
        resourceType: 'DOCUMENT',
        resourceId: id,
        outcome: 'SUCCESS',
        reason: `Downloaded current version (v${doc.currentVersion}) of '${doc.title}'`,
        clientIp: req.clientIp,
      });

      stream.pipe(res);
    } catch (error) {
      console.error('Download error:', error);
      return res.status(500).json({ error: 'Failed to stream document file.' });
    }
  }

  /**
   * Uploads a new version of an existing document.
   * Only Document Owner or users with EDIT permission are authorized.
   */
  static async uploadNewVersion(req: AuthenticatedRequest, res: Response) {
    if (!req.user) return res.status(401).json({ error: 'Authentication required' });
    const { id } = req.params;

    const authResult = await PolicyDecisionPoint.authorize(req.user, id, 'EDIT', {
      clientIp: req.clientIp,
    });

    if (!authResult.authorized) {
      return res.status(authResult.statusCode || 403).json({ error: authResult.reason });
    }

    const file = req.file;
    if (!file) {
      return res.status(400).json({ error: 'No file uploaded for new version.' });
    }

    // Magic-byte check
    const validation = FileService.validateMagicBytes(file.buffer);
    if (!validation.valid || !validation.detectedMimeType) {
      return res.status(400).json({ error: validation.error });
    }

    const changeSummary = req.body.changeSummary ? String(req.body.changeSummary).slice(0, 200) : 'Updated version';

    try {
      const storageKey = await FileService.saveBlob(file.buffer);
      const doc = authResult.document;
      const nextVersion = doc.currentVersion + 1;

      await prisma.$transaction(async (tx) => {
        await tx.documentVersion.create({
          data: {
            documentId: doc.id,
            versionNumber: nextVersion,
            storageKey,
            mimeType: validation.detectedMimeType!,
            byteSize: file.size,
            changeSummary,
            uploadedById: req.user!.id,
          },
        });

        await tx.document.update({
          where: { id: doc.id },
          data: {
            currentVersion: nextVersion,
            currentStorageKey: storageKey,
            currentMimeType: validation.detectedMimeType!,
            currentByteSize: file.size,
          },
        });
      });

      await AuditService.recordEvent({
        userId: req.user.id,
        userEmail: req.user.email,
        action: 'DOC_VERSION_UPLOAD',
        resourceType: 'DOCUMENT',
        resourceId: doc.id,
        outcome: 'SUCCESS',
        reason: `Uploaded version ${nextVersion}: ${changeSummary}`,
        clientIp: req.clientIp,
      });

      return res.status(200).json({
        message: `Version ${nextVersion} uploaded successfully`,
        currentVersion: nextVersion,
      });
    } catch (error) {
      console.error('Upload version error:', error);
      return res.status(500).json({ error: 'Failed to commit new version.' });
    }
  }

  /**
   * Downloads a specific historical version of a document.
   */
  static async downloadVersion(req: AuthenticatedRequest, res: Response) {
    if (!req.user) return res.status(401).json({ error: 'Authentication required' });
    const { id, versionNumber } = req.params;
    const vNum = parseInt(versionNumber, 10);

    const authResult = await PolicyDecisionPoint.authorize(req.user, id, 'DOWNLOAD', {
      clientIp: req.clientIp,
    });

    if (!authResult.authorized) {
      return res.status(authResult.statusCode || 403).json({ error: authResult.reason });
    }

    const version = await prisma.documentVersion.findUnique({
      where: {
        documentId_versionNumber: {
          documentId: id,
          versionNumber: vNum,
        },
      },
    });

    if (!version) {
      return res.status(404).json({ error: 'Requested version not found.' });
    }

    try {
      const stream = FileService.getBlobStream(version.storageKey);

      res.setHeader('Content-Type', version.mimeType);
      res.setHeader('Content-Disposition', `attachment; filename="${authResult.document.title}_v${vNum}"`);
      res.setHeader('X-Content-Type-Options', 'nosniff');

      await AuditService.recordEvent({
        userId: req.user.id,
        userEmail: req.user.email,
        action: 'DOC_VERSION_DOWNLOAD',
        resourceType: 'DOCUMENT',
        resourceId: id,
        outcome: 'SUCCESS',
        reason: `Downloaded historical version v${vNum}`,
        clientIp: req.clientIp,
      });

      stream.pipe(res);
    } catch (error) {
      console.error('Version download error:', error);
      return res.status(500).json({ error: 'Failed to download version.' });
    }
  }

  /**
   * Grants or updates document permissions for a named collaborator.
   * Only the Document Owner has permission to share.
   */
  static async shareDocument(req: AuthenticatedRequest, res: Response) {
    if (!req.user) return res.status(401).json({ error: 'Authentication required' });
    const { id } = req.params;

    const authResult = await PolicyDecisionPoint.authorize(req.user, id, 'SHARE', {
      clientIp: req.clientIp,
    });

    if (!authResult.authorized) {
      return res.status(authResult.statusCode || 403).json({ error: authResult.reason });
    }

    const parse = ShareSchema.safeParse(req.body);
    if (!parse.success) {
      return res.status(400).json({ error: 'Invalid share parameters', details: parse.error.format() });
    }

    const targetEmail = parse.data.email.toLowerCase().trim();
    const { accessLevel } = parse.data;

    try {
      const targetUser = await prisma.user.findUnique({ where: { email: targetEmail } });
      if (!targetUser) {
        return res.status(404).json({ error: 'Target user not found in the vault.' });
      }

      if (targetUser.id === req.user.id) {
        return res.status(400).json({ error: 'Cannot share document with yourself.' });
      }

      const permission = await prisma.documentPermission.upsert({
        where: {
          documentId_userId: {
            documentId: id,
            userId: targetUser.id,
          },
        },
        create: {
          documentId: id,
          userId: targetUser.id,
          accessLevel,
          grantedById: req.user.id,
        },
        update: {
          accessLevel,
          grantedById: req.user.id,
        },
      });

      await AuditService.recordEvent({
        userId: req.user.id,
        userEmail: req.user.email,
        action: 'PERM_GRANT',
        resourceType: 'DOCUMENT',
        resourceId: id,
        outcome: 'SUCCESS',
        reason: `Granted '${accessLevel}' access to user ${targetEmail}`,
        clientIp: req.clientIp,
      });

      return res.status(200).json({
        message: `Granted ${accessLevel} access to ${targetEmail}`,
        permission,
      });
    } catch (error) {
      console.error('Share document error:', error);
      return res.status(500).json({ error: 'Failed to update permissions.' });
    }
  }

  /**
   * Instantly revokes a collaborator's access to a document.
   * Zero-Delay Revocation: Deletes DocumentPermission row, immediately blocking
   * access to this document at T=0 via live PDP evaluation, while preserving
   * the collaborator's session across other documents they still hold access to.
   */
  static async revokePermission(req: AuthenticatedRequest, res: Response) {
    if (!req.user) return res.status(401).json({ error: 'Authentication required' });
    const { id, userId } = req.params;

    const authResult = await PolicyDecisionPoint.authorize(req.user, id, 'SHARE', {
      clientIp: req.clientIp,
    });

    if (!authResult.authorized) {
      return res.status(authResult.statusCode || 403).json({ error: authResult.reason });
    }

    try {
      const existing = await prisma.documentPermission.findUnique({
        where: {
          documentId_userId: {
            documentId: id,
            userId,
          },
        },
      });

      if (!existing) {
        return res.status(404).json({ error: 'No permission record found for this user.' });
      }

      // Zero-Delay Revocation: Instantly delete permission row.
      // PDP checks DocumentPermission live on every request, blocking access to this doc at T=0 (403 Forbidden).
      // Collaborator session remains valid for any other documents they still have access to.
      await prisma.documentPermission.delete({
        where: {
          documentId_userId: {
            documentId: id,
            userId,
          },
        },
      });

      await AuditService.recordEvent({
        userId: req.user.id,
        userEmail: req.user.email,
        action: 'PERM_REVOKE',
        resourceType: 'DOCUMENT',
        resourceId: id,
        outcome: 'SUCCESS',
        reason: `Instantly revoked access from user ID ${userId}`,
        clientIp: req.clientIp,
      });

      return res.status(200).json({ message: 'Access revoked successfully.' });
    } catch (error) {
      console.error('Revoke permission error:', error);
      return res.status(500).json({ error: 'Failed to revoke permissions.' });
    }
  }

  /**
   * Moves document to trash (Soft-delete).
   * Only the Document Owner has permission.
   */
  static async softDeleteDocument(req: AuthenticatedRequest, res: Response) {
    if (!req.user) return res.status(401).json({ error: 'Authentication required' });
    const { id } = req.params;

    const authResult = await PolicyDecisionPoint.authorize(req.user, id, 'DELETE', {
      clientIp: req.clientIp,
    });

    if (!authResult.authorized) {
      return res.status(authResult.statusCode || 403).json({ error: authResult.reason });
    }

    try {
      await prisma.document.update({
        where: { id },
        data: {
          isDeleted: true,
          deletedAt: new Date(),
        },
      });

      await AuditService.recordEvent({
        userId: req.user.id,
        userEmail: req.user.email,
        action: 'DOC_DELETE',
        resourceType: 'DOCUMENT',
        resourceId: id,
        outcome: 'SUCCESS',
        reason: `Moved document '${authResult.document.title}' to Trash`,
        clientIp: req.clientIp,
      });

      return res.status(200).json({ message: 'Document moved to trash.' });
    } catch (error) {
      console.error('Delete document error:', error);
      return res.status(500).json({ error: 'Failed to delete document.' });
    }
  }

  /**
   * Restores a soft-deleted document from trash.
   * STRUCTURAL PRIVILEGE: Strictly restricted to Document Owner.
   */
  static async restoreDocument(req: AuthenticatedRequest, res: Response) {
    if (!req.user) return res.status(401).json({ error: 'Authentication required' });
    const { id } = req.params;

    const authResult = await PolicyDecisionPoint.authorize(req.user, id, 'RESTORE', {
      clientIp: req.clientIp,
    });

    if (!authResult.authorized) {
      return res.status(authResult.statusCode || 403).json({ error: authResult.reason });
    }

    try {
      await prisma.document.update({
        where: { id },
        data: {
          isDeleted: false,
          deletedAt: null,
        },
      });

      await AuditService.recordEvent({
        userId: req.user.id,
        userEmail: req.user.email,
        action: 'DOC_RESTORE',
        resourceType: 'DOCUMENT',
        resourceId: id,
        outcome: 'SUCCESS',
        reason: `Restored document '${authResult.document.title}' from Trash`,
        clientIp: req.clientIp,
      });

      return res.status(200).json({ message: 'Document restored from trash.' });
    } catch (error) {
      console.error('Restore document error:', error);
      return res.status(500).json({ error: 'Failed to restore document.' });
    }
  }

  /**
   * Updates document metadata (Rename, Category, Description).
   * Authorized for Document Owner and users with EDIT permission.
   */
  static async updateDocument(req: AuthenticatedRequest, res: Response) {
    if (!req.user) return res.status(401).json({ error: 'Authentication required' });
    const { id } = req.params;

    const authResult = await PolicyDecisionPoint.authorize(req.user, id, 'EDIT', {
      clientIp: req.clientIp,
    });

    if (!authResult.authorized) {
      return res.status(authResult.statusCode || 403).json({ error: authResult.reason });
    }

    const { title, description, category } = req.body;
    const sanitizedTitle = title ? FileService.sanitizeFilename(String(title)) : undefined;

    try {
      const updated = await prisma.document.update({
        where: { id },
        data: {
          ...(sanitizedTitle ? { title: sanitizedTitle } : {}),
          ...(description !== undefined ? { description: String(description).slice(0, 500) } : {}),
          ...(category ? { category: String(category).slice(0, 50) } : {}),
        },
      });

      await AuditService.recordEvent({
        userId: req.user.id,
        userEmail: req.user.email,
        action: 'DOC_UPDATE',
        resourceType: 'DOCUMENT',
        resourceId: id,
        outcome: 'SUCCESS',
        reason: `Updated document metadata (Title: '${updated.title}', Category: '${updated.category}')`,
        clientIp: req.clientIp,
      });

      return res.status(200).json({
        message: 'Document metadata updated successfully',
        document: updated,
      });
    } catch (error) {
      console.error('Update document error:', error);
      return res.status(500).json({ error: 'Failed to update document metadata.' });
    }
  }

  /**
   * Permanently purges a document and all version file blobs from storage.
   * STRUCTURAL PRIVILEGE: Strictly restricted to Document Owner.
   */
  static async purgeDocument(req: AuthenticatedRequest, res: Response) {
    if (!req.user) return res.status(401).json({ error: 'Authentication required' });
    const { id } = req.params;

    const authResult = await PolicyDecisionPoint.authorize(req.user, id, 'PURGE', {
      clientIp: req.clientIp,
    });

    if (!authResult.authorized) {
      return res.status(authResult.statusCode || 403).json({ error: authResult.reason });
    }

    try {
      // 1. Fetch all versions to collect storage keys
      const versions = await prisma.documentVersion.findMany({
        where: { documentId: id },
        select: { storageKey: true },
      });

      // 2. Delete all physical blobs from disk
      for (const v of versions) {
        await FileService.deleteBlob(v.storageKey).catch(() => {});
      }
      if (authResult.document.currentStorageKey) {
        await FileService.deleteBlob(authResult.document.currentStorageKey).catch(() => {});
      }

      // 3. Delete database record (cascades versions and permissions)
      await prisma.document.delete({ where: { id } });

      await AuditService.recordEvent({
        userId: req.user.id,
        userEmail: req.user.email,
        action: 'DOC_PURGE',
        resourceType: 'DOCUMENT',
        resourceId: id,
        outcome: 'SUCCESS',
        reason: `Permanently purged document '${authResult.document.title}' and all associated version blobs`,
        clientIp: req.clientIp,
      });

      return res.status(200).json({ message: 'Document and all versions permanently purged.' });
    } catch (error) {
      console.error('Purge document error:', error);
      return res.status(500).json({ error: 'Failed to permanently purge document.' });
    }
  }
}
