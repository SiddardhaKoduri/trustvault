import { PrismaClient } from '@prisma/client';

const globalForPrisma = global as unknown as { prisma: PrismaClient };

export const prisma =
  globalForPrisma.prisma ||
  new PrismaClient({
    log: process.env.NODE_ENV === 'development' ? ['warn', 'error'] : ['error'],
  });

if (process.env.NODE_ENV !== 'production') globalForPrisma.prisma = prisma;

/**
 * Enforces immutable, append-only constraints on the AuditLog ledger at the database level.
 * Installs BEFORE UPDATE and BEFORE DELETE triggers that abort any attempted modification or deletion.
 */
export async function ensureAuditLedgerTriggers(): Promise<void> {
  try {
    // 1. Prevent updates to existing audit entries
    await prisma.$executeRawUnsafe(`
      CREATE TRIGGER IF NOT EXISTS prevent_audit_log_update
      BEFORE UPDATE ON AuditLog
      BEGIN
          SELECT RAISE(ABORT, 'Audit ledger is strictly append-only: updates are prohibited');
      END;
    `);

    // 2. Prevent deletions of existing audit entries
    await prisma.$executeRawUnsafe(`
      CREATE TRIGGER IF NOT EXISTS prevent_audit_log_delete
      BEFORE DELETE ON AuditLog
      BEGIN
          SELECT RAISE(ABORT, 'Audit ledger is strictly append-only: deletions are prohibited');
      END;
    `);
  } catch (error) {
    // Gracefully handle engines with different trigger syntax (e.g., PostgreSQL)
    console.warn('AuditLog database trigger initialization note:', (error as Error).message);
  }
}
