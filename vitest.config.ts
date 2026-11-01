import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    fileParallelism: false, // Ensures sequential execution for shared database tests
    testTimeout: 10000,
  },
});
