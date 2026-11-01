import { Response } from 'express';
import { prisma } from '../lib/prisma.js';
import { AuditService } from '../services/audit.service.js';
import { PolicyDecisionPoint } from '../services/pdp.service.js';
import { AuthenticatedRequest } from '../types/index.js';

export class AuditController {
  /**
   * Retrieves system-wide cryptographic audit trail.
   * Access strictly restricted to System Administrators.
   */
  static async getSystemAuditLogs(req: AuthenticatedRequest, res: Response) {
    if (!req.user || req.user.role !== 'ADMIN') {
      await AuditService.recordEvent({
        userId: req.user?.id,
        userEmail: req.user?.email,
        action: 'UNAUTHORIZED_ACCESS_ATTEMPT',
        resourceType: 'SYSTEM',
        resourceId: 'AUDIT_LEDGER',
        outcome: 'DENIED',
        reason: 'NON_ADMIN_ATTEMPTED_AUDIT_LOG_READ',
        clientIp: req.clientIp,
      });
      return res.status(403).json({ error: 'Access denied: Administrator privileges required.' });
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
      });
    } catch (error) {
      console.error('System audit retrieval error:', error);
      return res.status(500).json({ error: 'Failed to retrieve audit trail.' });
    }
  }

  /**
   * Retrieves document-specific audit trail for Document Owners.
   * Allows owners to see: "Who accessed this document, and when?"
   */
  static async getDocumentAuditLogs(req: AuthenticatedRequest, res: Response) {
    if (!req.user) return res.status(401).json({ error: 'Authentication required' });
    const { id } = req.params;

    // Check ownership: Only Document Owner can inspect document-specific audit history
    const authResult = await PolicyDecisionPoint.authorize(req.user, id, 'READ', {
      clientIp: req.clientIp,
    });

    if (!authResult.authorized) {
      return res.status(authResult.statusCode || 403).json({ error: authResult.reason });
    }

    if (authResult.accessLevel !== 'OWNER' && req.user.role !== 'ADMIN') {
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
        documentTitle: authResult.document.title,
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
