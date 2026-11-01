import crypto from 'crypto';
import { prisma } from '../lib/prisma.js';
import { AuditOutcome } from '../types/index.js';

const GENESIS_HASH = '0000000000000000000000000000000000000000000000000000000000000000';
const AUDIT_SECRET = process.env.AUDIT_SECRET || 'trustvault_audit_chain_hmac_secret_2026_top1';

export interface LogAuditParams {
  userId?: string | null;
  userEmail?: string | null;
  action: string;
  resourceType: 'DOCUMENT' | 'USER' | 'SYSTEM';
  resourceId: string;
  outcome: AuditOutcome;
  reason?: string;
  clientIp?: string;
  userAgent?: string;
}

export class AuditService {
  /**
   * Generates canonical payload representation for HMAC hashing.
   * Includes all critical fields to prevent any partial row modification.
   */
  static formatCanonicalPayload(
    timestamp: Date,
    userId: string | null | undefined,
    userEmail: string | null | undefined,
    action: string,
    resourceType: string,
    resourceId: string,
    outcome: string,
    reason: string | null | undefined,
    clientIp: string | null | undefined
  ): string {
    return [
      timestamp.toISOString(),
      userId || 'ANONYMOUS',
      userEmail || 'NONE',
      action,
      resourceType,
      resourceId,
      outcome,
      reason || 'NONE',
      clientIp || 'UNKNOWN',
    ].join('|');
  }

  /**
   * Appends an event to the cryptographic audit chain.
   * Enforces database transaction atomicity to ensure linear hash sequencing across all threads/processes.
   */
  static async recordEvent(params: LogAuditParams) {
    try {
      return await prisma.$transaction(async (tx) => {
        // 1. Fetch latest entry atomically
        const latest = await tx.auditLog.findFirst({
          orderBy: { id: 'desc' },
          select: { entryHash: true },
        });

        const previousHash = latest ? latest.entryHash : GENESIS_HASH;
        const timestamp = new Date();

        // 2. Canonical payload with all security fields
        const canonicalPayload = AuditService.formatCanonicalPayload(
          timestamp,
          params.userId,
          params.userEmail,
          params.action,
          params.resourceType,
          params.resourceId,
          params.outcome,
          params.reason,
          params.clientIp
        );

        // 3. Compute HMAC-SHA256 signature
        const entryHash = crypto
          .createHmac('sha256', AUDIT_SECRET)
          .update(previousHash + canonicalPayload)
          .digest('hex');

        // 4. Commit to database within the same atomic transaction
        return await tx.auditLog.create({
          data: {
            timestamp,
            userId: params.userId,
            userEmail: params.userEmail,
            action: params.action,
            resourceType: params.resourceType,
            resourceId: params.resourceId,
            outcome: params.outcome,
            reason: params.reason,
            clientIp: params.clientIp,
            userAgent: params.userAgent,
            previousHash,
            entryHash,
          },
        });
      });
    } catch (error) {
      console.error('Critical failure in AuditService:', error);
      throw error;
    }
  }

  /**
   * Verifies the cryptographic chain integrity across all records in the database.
   */
  static async verifyChainIntegrity() {
    const entries = await prisma.auditLog.findMany({
      orderBy: { id: 'asc' },
    });

    let prevHash = GENESIS_HASH;

    for (let i = 0; i < entries.length; i++) {
      const entry = entries[i];

      // Check linkage
      if (entry.previousHash !== prevHash) {
        return {
          valid: false,
          brokenRowId: entry.id,
          reason: `Broken chain link at ID ${entry.id}. Expected ${prevHash}, got ${entry.previousHash}`,
        };
      }

      // Recompute hash
      const canonicalPayload = AuditService.formatCanonicalPayload(
        entry.timestamp,
        entry.userId,
        entry.userEmail,
        entry.action,
        entry.resourceType,
        entry.resourceId,
        entry.outcome,
        entry.reason,
        entry.clientIp
      );

      const expectedHash = crypto
        .createHmac('sha256', AUDIT_SECRET)
        .update(entry.previousHash + canonicalPayload)
        .digest('hex');

      if (entry.entryHash !== expectedHash) {
        return {
          valid: false,
          brokenRowId: entry.id,
          reason: `Signature mismatch at ID ${entry.id}. Data was modified directly!`,
        };
      }

      prevHash = entry.entryHash;
    }

    return {
      valid: true,
      totalEntries: entries.length,
    };
  }
}
