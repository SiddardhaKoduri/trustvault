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
   * Appends an event to the cryptographic audit chain.
   * Every record mathematically commits to the state of the previous record.
   */
  static async recordEvent(params: LogAuditParams) {
    try {
      // 1. Fetch the latest entry to retrieve its entryHash
      const latest = await prisma.auditLog.findFirst({
        orderBy: { id: 'desc' },
        select: { entryHash: true },
      });

      const previousHash = latest ? latest.entryHash : GENESIS_HASH;
      const timestamp = new Date();

      // 2. Compute canonical payload representation
      const canonicalPayload = `${timestamp.toISOString()}|${params.userId || 'ANONYMOUS'}|${params.action}|${params.resourceType}|${params.resourceId}|${params.outcome}|${params.clientIp || 'UNKNOWN'}`;

      // 3. Compute HMAC-SHA256 signature
      const entryHash = crypto
        .createHmac('sha256', AUDIT_SECRET)
        .update(previousHash + canonicalPayload)
        .digest('hex');

      // 4. Commit to database
      return await prisma.auditLog.create({
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
    } catch (error) {
      console.error('Critical failure in AuditService:', error);
      // Fail closed: in zero-trust, if audit logging fails, you log to stderr
      throw new Error('Audit record creation failed');
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
      const canonicalPayload = `${entry.timestamp.toISOString()}|${entry.userId || 'ANONYMOUS'}|${entry.action}|${entry.resourceType}|${entry.resourceId}|${entry.outcome}|${entry.clientIp || 'UNKNOWN'}`;
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
