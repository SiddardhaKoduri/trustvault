import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import request from 'supertest';
import { app } from '../app.js';
import { prisma } from '../lib/prisma.js';

describe('Day 3: Snovasys Evaluator Mutation Immunity & Negative Security Harness', () => {
  let adminToken: string;
  let ownerToken: string;
  let viewerToken: string;
  let viewerUserId: string;
  let targetDocId: string;

  beforeAll(async () => {
    await prisma.$connect();

    // Authenticate baseline accounts
    const adminRes = await request(app)
      .post('/api/auth/login')
      .send({ email: 'admin@vault.local', password: 'VaultPassword2026!' });
    adminToken = adminRes.body.token;

    const ownerRes = await request(app)
      .post('/api/auth/login')
      .send({ email: 'owner@vault.local', password: 'VaultPassword2026!' });
    ownerToken = ownerRes.body.token;

    const viewerRes = await request(app)
      .post('/api/auth/login')
      .send({ email: 'viewer@vault.local', password: 'VaultPassword2026!' });
    viewerToken = viewerRes.body.token;
    viewerUserId = viewerRes.body.user.id;

    // Create benchmark confidential document owned by Owner
    const docRes = await request(app)
      .post('/api/documents')
      .set('Cookie', `token=${ownerToken}`)
      .field('title', 'Evaluator Confidential Benchmark')
      .field('category', 'Top Secret')
      .attach('file', Buffer.from('%PDF-1.4\nConfidential Root Data\n%%EOF'), 'benchmark.pdf');

    targetDocId = docRes.body.document.id;
  });

  afterAll(async () => {
    await prisma.$disconnect();
  });

  it('MUTATION-INV-01: Anonymous requests to document vault MUST be rejected with 401', async () => {
    const res = await request(app).get(`/api/documents/${targetDocId}`);
    expect(res.status).toBe(401);
  });

  it('MUTATION-INV-02: IDOR Immunity: Viewer cannot access unshared document (MUST return 403 or 404)', async () => {
    const res = await request(app)
      .get(`/api/documents/${targetDocId}`)
      .set('Cookie', `token=${viewerToken}`);

    expect([403, 404]).toContain(res.status);
    expect(res.body.document).toBeUndefined();
  });

  it('MUTATION-INV-03: Administrative Blindness: Admin CANNOT download private document contents (MUST return 403)', async () => {
    const res = await request(app)
      .get(`/api/documents/${targetDocId}/download`)
      .set('Cookie', `token=${adminToken}`);

    expect(res.status).toBe(403);
    expect(res.body.error).toMatch(/access denied/i);
  });

  it('MUTATION-INV-04: Privilege Boundary: Viewer with READ access CANNOT edit or upload new versions (MUST return 403)', async () => {
    // 1. Grant READ
    await request(app)
      .post(`/api/documents/${targetDocId}/permissions`)
      .set('Cookie', `token=${ownerToken}`)
      .send({ email: 'viewer@vault.local', accessLevel: 'READ' })
      .expect(200);

    // 2. Viewer attempts version upload
    const res = await request(app)
      .post(`/api/documents/${targetDocId}/versions`)
      .set('Cookie', `token=${viewerToken}`)
      .field('changeSummary', 'Illegal version push')
      .attach('file', Buffer.from('%PDF-1.4\nIllegal version\n%%EOF'), 'v2.pdf');

    expect(res.status).toBe(403);
    expect(res.body.error).toMatch(/read-only access/i);
  });

  it('MUTATION-INV-05: Structural Privilege: Editor CANNOT delete document (MUST return 403)', async () => {
    // 1. Promote Viewer to EDIT
    await request(app)
      .post(`/api/documents/${targetDocId}/permissions`)
      .set('Cookie', `token=${ownerToken}`)
      .send({ email: 'viewer@vault.local', accessLevel: 'EDIT' })
      .expect(200);

    // 2. Editor attempts deletion
    const res = await request(app)
      .delete(`/api/documents/${targetDocId}`)
      .set('Cookie', `token=${viewerToken}`);

    expect(res.status).toBe(403);
    expect(res.body.error).toMatch(/owner/i);
  });

  it('MUTATION-INV-06: Lateral Movement Defense: Editor CANNOT re-share or grant permissions to third parties (MUST return 403)', async () => {
    const res = await request(app)
      .post(`/api/documents/${targetDocId}/permissions`)
      .set('Cookie', `token=${viewerToken}`)
      .send({ email: 'admin@vault.local', accessLevel: 'READ' });

    expect(res.status).toBe(403);
    expect(res.body.error).toMatch(/owner/i);
  });

  it('MUTATION-INV-07: Governance Defense: Non-admin CANNOT access Admin User Management directory (MUST return 403)', async () => {
    const res = await request(app)
      .get('/api/admin/users')
      .set('Cookie', `token=${ownerToken}`);

    expect(res.status).toBe(403);
  });

  it('MUTATION-INV-08: Audit Privacy: Non-admin CANNOT inspect system-wide audit ledger (MUST return 403)', async () => {
    const res = await request(app)
      .get('/api/audit')
      .set('Cookie', `token=${viewerToken}`);

    expect(res.status).toBe(403);
  });

  it('MUTATION-INV-09: Binary Sniffing: Server rejects fake PDF containing binary executable header (MUST return 400)', async () => {
    const exeBuffer = Buffer.from([0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00]); // MZ executable signature
    const res = await request(app)
      .post('/api/documents')
      .set('Cookie', `token=${ownerToken}`)
      .field('title', 'Spoofed Executable')
      .attach('file', exeBuffer, 'malware.pdf');

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/signature rejected/i);
  });

  it('MUTATION-INV-10: Instant Revocation Invariant: Access terminates at T=0 immediately upon revocation', async () => {
    // 1. Verify Viewer has access
    await request(app)
      .get(`/api/documents/${targetDocId}/download`)
      .set('Cookie', `token=${viewerToken}`)
      .expect(200);

    // 2. Owner revokes access
    await request(app)
      .delete(`/api/documents/${targetDocId}/permissions/${viewerUserId}`)
      .set('Cookie', `token=${ownerToken}`)
      .expect(200);

    // 3. Very next packet MUST BE REJECTED with 401 or 403
    const revokedRes = await request(app)
      .get(`/api/documents/${targetDocId}/download`)
      .set('Cookie', `token=${viewerToken}`);

    expect([401, 403]).toContain(revokedRes.status);
  });

  it('MUTATION-INV-11: Verifiable Audit Invariant: Refused attempts produce DENIED records in database', async () => {
    const deniedEntries = await prisma.auditLog.findMany({
      where: { outcome: 'DENIED' },
    });
    expect(deniedEntries.length).toBeGreaterThan(0);
  });

  it('MUTATION-INV-12: Cryptographic Head Verification: GET /api/audit/verify returns valid: true', async () => {
    const res = await request(app)
      .get('/api/audit/verify')
      .set('Cookie', `token=${adminToken}`);

    expect(res.status).toBe(200);
    expect(res.body.valid).toBe(true);
    expect(res.body.latestEntryHash).toBeDefined();
    expect(res.body.totalEntries).toBeGreaterThan(0);
  });
});
