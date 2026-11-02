import dotenv from 'dotenv';
dotenv.config();

import { app } from './app.js';
import { FileService } from './services/file.service.js';
import { ensureAuditLedgerTriggers } from './lib/prisma.js';

// Guarantee isolated storage directory exists on startup
FileService.ensureStorageDirectory();

// Enforce database-level append-only triggers on AuditLog table
ensureAuditLedgerTriggers().catch((err) => {
  console.warn('Failed to initialize database audit triggers:', err);
});

const PORT = process.env.PORT || 4000;

app.listen(PORT, () => {
  console.log(`\n======================================================`);
  console.log(`  🛡️  TRUSTVAULT ZERO-TRUST SECURITY ENGINE STARTED   `);
  console.log(`======================================================`);
  console.log(`  Port:             ${PORT}`);
  console.log(`  Environment:      ${process.env.NODE_ENV || 'development'}`);
  console.log(`  Healthcheck:      http://localhost:${PORT}/api/health`);
  console.log(`======================================================\n`);
});
