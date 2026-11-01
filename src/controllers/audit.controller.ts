import { Response } from 'express';
import { prisma } from '../lib/prisma.js';
import { AuditService } from '../services/audit.service.js';
import { PolicyDecisionPoint } from '../services/pdp.service.js';
import { AuthenticatedRequest } from '../types/index.js';

export class AuditController {
  /**
   * Retrieves cryptographic audit trail.
   * - System Administrators: Full system-wide visibility.
   * - Document Owners: Scoped strictly to documents they own (zero unauthorized leakage).
   * - Viewers / Collaborators: Strictly forbidden (403).
   */
  static async getSystemAuditLogs(req: AuthenticatedRequest, res: Response) {
    if (!req.user) return res.status(401).json({ error: 'Authentication required' });

    if (req.user.role === 'VIEWER') {
      await AuditService.recordEvent({
        userId: req.user.id,
        userEmail: req.user.email,
        action: 'UNAUTHORIZED_ACCESS_ATTEMPT',
        resourceType: 'SYSTEM',
        resourceId: 'AUDIT_LEDGER',
        outcome: 'DENIED',
        reason: 'VIEWER_ATTEMPTED_AUDIT_LOG_READ',
        clientIp: req.clientIp,
      });
      return res.status(403).json({ error: 'Access denied: Viewers cannot inspect audit records.' });
    }

    const page = Math.max(1, parseInt(String(req.query.page || '1'), 10));
    const limit = Math.min(100, Math.max(1, parseInt(String(req.query.limit || '50'), 10)));
    const action = req.query.action ? String(req.query.action).trim() : undefined;
    const outcome = req.query.outcome ? String(req.query.outcome).trim() : undefined;
    const search = req.query.search ? String(req.query.search).trim() : undefined;

    try {
      const where: any = {};
      if (action) where.action = action;
      if (outcome) where.outcome = outcome;
      if (search) {
        where.OR = [
          { userEmail: { contains: search } },
          { reason: { contains: search } },
          { resourceId: { contains: search } },
        ];
      }

      // If actor is OWNER (not ADMIN), scope logs strictly to documents they own
      if (req.user.role === 'OWNER') {
        const ownedDocs = await prisma.document.findMany({
          where: { ownerId: req.user.id },
          select: { id: true },
        });
        const ownedIds = ownedDocs.map((d) => d.id);
        where.resourceId = { in: ownedIds };
      }

      const [total, entries] = await Promise.all([
        prisma.auditLog.count({ where }),
        prisma.auditLog.findMany({
          where,
          orderBy: { id: 'desc' },
          skip: (page - 1) * limit,
          take: limit,
        }),
      ]);

      return res.status(200).json({
        total,
        page,
        totalPages: Math.ceil(total / limit),
        entries,
        scopedToOwner: req.user.role === 'OWNER',
      });
    } catch (error) {
      console.error('Audit retrieval error:', error);
      return res.status(500).json({ error: 'Failed to retrieve audit trail.' });
    }
  }

  /**
   * Retrieves document-specific audit trail for Document Owners.
   * Answers the critical security question: "Who opened this file, and when?"
   */
  static async getDocumentAuditLogs(req: AuthenticatedRequest, res: Response) {
    if (!req.user) return res.status(401).json({ error: 'Authentication required' });
    const { id } = req.params;

    const doc = await prisma.document.findUnique({
      where: { id },
      select: { id: true, title: true, ownerId: true },
    });

    if (!doc) {
      return res.status(404).json({ error: 'Document not found.' });
    }

    if (doc.ownerId !== req.user.id && req.user.role !== 'ADMIN') {
      await AuditService.recordEvent({
        userId: req.user.id,
        userEmail: req.user.email,
        action: 'UNAUTHORIZED_ACCESS_ATTEMPT',
        resourceType: 'DOCUMENT',
        resourceId: id,
        outcome: 'DENIED',
        reason: 'NON_OWNER_ATTEMPTED_DOC_AUDIT_READ',
        clientIp: req.clientIp,
      });
      return res.status(403).json({
        error: 'Forbidden: Only the document owner can inspect the document audit trail.',
      });
    }

    try {
      const logs = await prisma.auditLog.findMany({
        where: {
          resourceType: 'DOCUMENT',
          resourceId: id,
        },
        orderBy: { id: 'desc' },
      });

      return res.status(200).json({
        documentId: id,
        documentTitle: doc.title,
        totalEvents: logs.length,
        logs,
      });
    } catch (error) {
      console.error('Document audit retrieval error:', error);
      return res.status(500).json({ error: 'Failed to retrieve document audit trail.' });
    }
  }

  /**
   * Real-time cryptographic chain integrity verification endpoint.
   * Mathematically proves that zero database rows have been altered or deleted.
   */
  static async verifyAuditChain(req: AuthenticatedRequest, res: Response) {
    try {
      const result = await AuditService.verifyChainIntegrity();

      const latest = await prisma.auditLog.findFirst({
        orderBy: { id: 'desc' },
        select: { entryHash: true, timestamp: true },
      });

      return res.status(200).json({
        valid: result.valid,
        totalEntries: result.totalEntries,
        brokenRowId: result.brokenRowId,
        reason: result.reason,
        latestEntryHash: latest?.entryHash || 'GENESIS',
        verifiedAt: new Date().toISOString(),
      });
    } catch (error) {
      console.error('Chain verification error:', error);
      return res.status(500).json({ error: 'Chain verification failed.' });
    }
  }
}
