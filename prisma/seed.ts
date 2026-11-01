import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import { AuditService } from '../src/services/audit.service.js';

const prisma = new PrismaClient();
const AUDIT_SECRET = process.env.AUDIT_SECRET || 'trustvault_audit_chain_hmac_secret_2026_top1';
const GENESIS_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

async function main() {
  console.log('Seeding TrustVault Zero-Trust benchmark accounts...');

  const defaultPassword = 'VaultPassword2026!';
  const passwordHash = await bcrypt.hash(defaultPassword, 12);

  // 1. Ensure System Administrator exists
  const admin = await prisma.user.upsert({
    where: { email: 'admin@vault.local' },
    update: { isActive: true },
    create: {
      name: 'System Administrator',
      email: 'admin@vault.local',
      passwordHash,
      role: 'ADMIN',
      isActive: true,
      permissionEpoch: 1,
    },
  });

  // 2. Ensure Document Owner exists
  const owner = await prisma.user.upsert({
    where: { email: 'owner@vault.local' },
    update: { isActive: true },
    create: {
      name: 'Alice (Document Owner)',
      email: 'owner@vault.local',
      passwordHash,
      role: 'OWNER',
      isActive: true,
      permissionEpoch: 1,
    },
  });

  // 3. Ensure Viewer exists
  const viewer = await prisma.user.upsert({
    where: { email: 'viewer@vault.local' },
    update: { isActive: true },
    create: {
      name: 'Bob (Viewer Collaborator)',
      email: 'viewer@vault.local',
      passwordHash,
      role: 'VIEWER',
      isActive: true,
      permissionEpoch: 1,
    },
  });

  // 4. Create Genesis block in cryptographic audit chain ONLY if audit ledger is empty
  const logCount = await prisma.auditLog.count();
  let entryHash = 'EXISTING_CHAIN';

  if (logCount === 0) {
    const timestamp = new Date();
    const reason = 'TrustVault Genesis block initialized with benchmark accounts.';
    const canonicalPayload = AuditService.formatCanonicalPayload(
      timestamp,
      admin.id,
      admin.email,
      'SYSTEM_GENESIS_INITIALIZE',
      'SYSTEM',
      'sys_root',
      'SUCCESS',
      reason,
      '127.0.0.1'
    );

    entryHash = crypto
      .createHmac('sha256', AUDIT_SECRET)
      .update(GENESIS_HASH + canonicalPayload)
      .digest('hex');

    await prisma.auditLog.create({
      data: {
        timestamp,
        userId: admin.id,
        userEmail: admin.email,
        action: 'SYSTEM_GENESIS_INITIALIZE',
        resourceType: 'SYSTEM',
        resourceId: 'sys_root',
        outcome: 'SUCCESS',
        reason,
        clientIp: '127.0.0.1',
        userAgent: 'TrustVault Seed Harness 1.0',
        previousHash: GENESIS_HASH,
        entryHash,
      },
    });
  }

  console.log('✅ Seed completed successfully:');
  console.log(`   - Admin:  ${admin.email}  (Role: ADMIN,  Password: ${defaultPassword})`);
  console.log(`   - Owner:  ${owner.email}  (Role: OWNER,  Password: ${defaultPassword})`);
  console.log(`   - Viewer: ${viewer.email} (Role: VIEWER, Password: ${defaultPassword})`);
  console.log(`   - Genesis Audit Hash: ${entryHash}`);
}

main()
  .catch((e) => {
    console.error('Seed failed:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
