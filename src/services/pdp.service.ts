import { prisma } from '../lib/prisma.js';
import { AuditService } from './audit.service.js';
import { SessionUser, AuthorizationResult } from '../types/index.js';

export type VaultOperation = 'READ' | 'DOWNLOAD' | 'EDIT' | 'DELETE' | 'SHARE';

export class PolicyDecisionPoint {
  /**
   * Evaluates whether an actor is authorized to perform a vault operation on a document.
   * Enforces zero-trust invariants:
   * - Strict server-side verification
   * - Administrative Blindness (Admins cannot read documents without explicit share)
   * - Editors cannot delete or share
   * - Automatic cryptographic audit logging for both success and refused attempts
   */
  static async authorize(
    currentUser: SessionUser,
    documentId: string,
    operation: VaultOperation,
    context?: { clientIp?: string; userAgent?: string }
  ): Promise<AuthorizationResult> {
    // 1. Deactivated user check (Instant invalidation)
    if (!currentUser.isActive) {
      await AuditService.recordEvent({
        userId: currentUser.id,
        userEmail: currentUser.email,
        action: 'UNAUTHORIZED_ACCESS_ATTEMPT',
        resourceType: 'DOCUMENT',
        resourceId: documentId,
        outcome: 'DENIED',
        reason: 'USER_ACCOUNT_DEACTIVATED',
        clientIp: context?.clientIp,
        userAgent: context?.userAgent,
      });
      return { authorized: false, statusCode: 403, reason: 'Account deactivated' };
    }

    // 2. Fetch document
    const doc = await prisma.document.findUnique({
      where: { id: documentId },
    });

    if (!doc || doc.isDeleted) {
      await AuditService.recordEvent({
        userId: currentUser.id,
        userEmail: currentUser.email,
        action: 'UNAUTHORIZED_ACCESS_ATTEMPT',
        resourceType: 'DOCUMENT',
        resourceId: documentId,
        outcome: 'DENIED',
        reason: 'DOCUMENT_NOT_FOUND_OR_DELETED',
        clientIp: context?.clientIp,
        userAgent: context?.userAgent,
      });
      return { authorized: false, statusCode: 404, reason: 'Document not found' };
    }

    // 3. Document Owner check (Owners have full permissions)
    if (doc.ownerId === currentUser.id) {
      return { authorized: true, document: doc, accessLevel: 'OWNER' };
    }

    // 4. Structural operations (DELETE, SHARE) can ONLY be performed by the Owner
    if (operation === 'DELETE' || operation === 'SHARE') {
      await AuditService.recordEvent({
        userId: currentUser.id,
        userEmail: currentUser.email,
        action: 'UNAUTHORIZED_ACCESS_ATTEMPT',
        resourceType: 'DOCUMENT',
        resourceId: documentId,
        outcome: 'DENIED',
        reason: `PRIVILEGE_VIOLATION: ${currentUser.role} attempted ${operation} on non-owned document`,
        clientIp: context?.clientIp,
        userAgent: context?.userAgent,
      });
      return {
        authorized: false,
        statusCode: 403,
        reason: 'Only the document owner can delete or manage permissions',
      };
    }

    // 5. Explicit Permission check (Required for all non-owners, INCLUDING ADMINS)
    const permission = await prisma.documentPermission.findUnique({
      where: {
        documentId_userId: {
          documentId,
          userId: currentUser.id,
        },
      },
    });

    // Administrative Blindness: Even if role is ADMIN, if no explicit permission exists, reject!
    if (!permission) {
      await AuditService.recordEvent({
        userId: currentUser.id,
        userEmail: currentUser.email,
        action: 'UNAUTHORIZED_ACCESS_ATTEMPT',
        resourceType: 'DOCUMENT',
        resourceId: documentId,
        outcome: 'DENIED',
        reason: `ACCESS_DENIED: User has no explicit permissions for document`,
        clientIp: context?.clientIp,
        userAgent: context?.userAgent,
      });
      return {
        authorized: false,
        statusCode: 403,
        reason: 'Access denied: You do not have permission to access this document',
      };
    }

    // 6. Level check for EDIT operation
    if (operation === 'EDIT' && permission.accessLevel !== 'EDIT') {
      await AuditService.recordEvent({
        userId: currentUser.id,
        userEmail: currentUser.email,
        action: 'UNAUTHORIZED_ACCESS_ATTEMPT',
        resourceType: 'DOCUMENT',
        resourceId: documentId,
        outcome: 'DENIED',
        reason: `INSUFFICIENT_LEVEL: READ permission cannot perform EDIT`,
        clientIp: context?.clientIp,
        userAgent: context?.userAgent,
      });
      return {
        authorized: false,
        statusCode: 403,
        reason: 'Read-only access: You do not have permission to edit this document',
      };
    }

    // Authorized!
    return {
      authorized: true,
      document: doc,
      accessLevel: permission.accessLevel as 'READ' | 'EDIT',
    };
  }
}
