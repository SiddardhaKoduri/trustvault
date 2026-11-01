#!/usr/bin/env node

/**
 * TrustVault - Cryptographic Audit Chain Integrity Verifier
 * 
 * Verifies that the audit log chain has not been tampered with, deleted, or forged.
 * Mathematical proof: Every block must satisfy:
 *   EntryHash[k] === HMAC_SHA256(Secret, PreviousHash[k-1] + Payload[k])
 */

const crypto = require('crypto');

function computePayloadHash(entry, prevHash, secret) {
  const payload = `${entry.timestamp}|${entry.userId || 'ANONYMOUS'}|${entry.action}|${entry.resourceType}|${entry.resourceId}|${entry.outcome}|${entry.clientIp || 'UNKNOWN'}`;
  return crypto
    .createHmac('sha256', secret)
    .update(prevHash + payload)
    .digest('hex');
}

function verifyAuditChain(entries, secret) {
  console.log(`\n======================================================`);
  console.log(`   TRUSTVAULT CRYPTOGRAPHIC AUDIT CHAIN VERIFIER     `);
  console.log(`======================================================\n`);
  console.log(`Total Entries to Verify: ${entries.length}`);

  let prevHash = "0000000000000000000000000000000000000000000000000000000000000000";
  let verifiedCount = 0;

  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i];

    // 1. Verify previousHash link
    if (entry.previousHash !== prevHash) {
      console.error(`❌ [TAMPERING DETECTED] Broken chain linkage at Row ${entry.id}!`);
      console.error(`   Expected PreviousHash: ${prevHash}`);
      console.error(`   Found PreviousHash:    ${entry.previousHash}`);
      return {
        valid: false,
        brokenRow: entry.id,
        reason: 'BROKEN_PREVIOUS_HASH_POINTER'
      };
    }

    // 2. Recompute cryptographic signature
    const expectedHash = computePayloadHash(entry, prevHash, secret);
    if (entry.entryHash !== expectedHash) {
      console.error(`❌ [DATA CORRUPTION/TAMPERING DETECTED] Hash mismatch at Row ${entry.id}!`);
      console.error(`   Action: ${entry.action} | Resource: ${entry.resourceId} | Outcome: ${entry.outcome}`);
      console.error(`   Stored EntryHash:   ${entry.entryHash}`);
      console.error(`   Recomputed Hash:    ${expectedHash}`);
      return {
        valid: false,
        brokenRow: entry.id,
        reason: 'SIGNATURE_MISMATCH'
      };
    }

    prevHash = entry.entryHash;
    verifiedCount++;
  }

  console.log(`\n✅ ALL ${verifiedCount} AUDIT LOG ENTRIES CRYPTOGRAPHICALLY VERIFIED!`);
  console.log(`   Chain Status: 100% Intact. Zero Tampering Detected.\n`);
  return { valid: true, totalVerified: verifiedCount };
}

module.exports = { verifyAuditChain, computePayloadHash };

// If executed directly as CLI
if (require.main === module) {
  const secret = process.env.AUDIT_SECRET || 'trustvault_audit_master_secret_2026';
  // Example dummy chain demonstration
  const dummyChain = [
    {
      id: 1,
      timestamp: '2026-11-01T09:00:00.000Z',
      userId: 'usr_admin_1',
      action: 'SYSTEM_BOOT',
      resourceType: 'SYSTEM',
      resourceId: 'sys_0',
      outcome: 'SUCCESS',
      clientIp: '127.0.0.1',
      previousHash: '0000000000000000000000000000000000000000000000000000000000000000',
      entryHash: ''
    }
  ];
  dummyChain[0].entryHash = computePayloadHash(dummyChain[0], dummyChain[0].previousHash, secret);
  verifyAuditChain(dummyChain, secret);
}
