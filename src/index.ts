import dotenv from 'dotenv';
dotenv.config();

import { app } from './app.js';

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
