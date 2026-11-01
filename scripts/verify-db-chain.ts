import { AuditService } from '../src/services/audit.service.js';

async function verify() {
  console.log('\n======================================================');
  console.log('   TRUSTVAULT DATABASE AUDIT CHAIN VERIFICATION      ');
  console.log('======================================================\n');
  const result = await AuditService.verifyChainIntegrity();
  console.log('Verification Result:', result);
  if (result.valid) {
    console.log(`\n✅ MATHEMATICAL PROOF CONFIRMED: ${result.totalEntries} block(s) cryptographically intact.\n`);
  } else {
    console.error(`\n❌ CHAIN BROKEN:`, result);
    process.exit(1);
  }
}

verify().catch((e) => {
  console.error(e);
  process.exit(1);
});
