import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import request from 'supertest';
import { app } from '../app.js';
import { prisma } from '../lib/prisma.js';
import { AuditService } from '../services/audit.service.js';

describe('Day 2: Defensive File Uploads, Versioning & Instant Revocation', () => {
  let adminToken: string;
  let ownerToken: string;
  let viewerToken: string;
  let viewerUserId: string;
  let uploadedDocId: string;

  beforeAll(async () => {
    await prisma.$connect();

    // Authenticate benchmark accounts
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
  });

  afterAll(async () => {
    await prisma.$disconnect();
  });

  it('SEC-DAY2-01: Owner should successfully upload a valid PDF document with %PDF- header', async () => {
    const validPdfBuffer = Buffer.from('%PDF-1.4\n%âãÏÓ\n1 0 obj\n<<\n/Title (Financial Report)\n>>\nendobj\ntrailer\n<<\n>>\n%%EOF');

    const res = await request(app)
      .post('/api/documents')
      .set('Cookie', `token=${ownerToken}`)
      .field('title', 'Quarterly Financials 2026')
      .field('category', 'Financial')
      .attach('file', validPdfBuffer, 'financials.pdf');

    expect(res.status).toBe(201);
    expect(res.body.document.id).toBeDefined();
    expect(res.body.document.currentVersion).toBe(1);
    expect(res.body.document.mimeType).toBe('application/pdf');

    uploadedDocId = res.body.document.id;
  });

  it('SEC-DAY2-02: Should REJECT disguised file upload (fake PDF extension containing binary shellcode)', async () => {
    // Binary buffer starting with executable null bytes / shellcode
    const maliciousBuffer = Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x00, 0x00, 0x00]); // ELF binary header

    const res = await request(app)
      .post('/api/documents')
      .set('Cookie', `token=${ownerToken}`)
      .field('title', 'Injected Payload')
      .attach('file', maliciousBuffer, 'fake.pdf');

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/signature rejected/i);

    // Verify refused attempt is logged
    const lastAudit = await prisma.auditLog.findFirst({
      where: { action: 'MALICIOUS_UPLOAD_ATTEMPT' },
      orderBy: { id: 'desc' },
    });
    expect(lastAudit).toBeDefined();
    expect(lastAudit?.outcome).toBe('DENIED');
  });

  it('SEC-DAY2-03: Should sanitize path traversal sequences in uploaded filename', async () => {
    const textBuffer = Buffer.from('Confidential strategic plan contents...');

    const res = await request(app)
      .post('/api/documents')
      .set('Cookie', `token=${ownerToken}`)
      .field('title', '../../../../etc/shadow_leak')
      .attach('file', textBuffer, 'report.txt');

    expect(res.status).toBe(201);
    expect(res.body.document.title).not.toContain('..');
    expect(res.body.document.title).toBe('shadow_leak');
  });

  it('SEC-DAY2-04: Non-shared Viewer attempting to access document receives 403/404 (Zero IDOR)', async () => {
    const res = await request(app)
      .get(`/api/documents/${uploadedDocId}`)
      .set('Cookie', `token=${viewerToken}`);

    expect([403, 404]).toContain(res.status);
    expect(res.body.document).toBeUndefined();
  });

  it('SEC-DAY2-05: System Admin cannot download private document (Administrative Blindness Invariant)', async () => {
    const res = await request(app)
      .get(`/api/documents/${uploadedDocId}/download`)
      .set('Cookie', `token=${adminToken}`);

    expect(res.status).toBe(403);
    expect(res.body.error).toMatch(/access denied/i);
  });

  it('SEC-DAY2-06: Owner grants READ access to Viewer', async () => {
    const res = await request(app)
      .post(`/api/documents/${uploadedDocId}/permissions`)
      .set('Cookie', `token=${ownerToken}`)
      .send({
        email: 'viewer@vault.local',
        accessLevel: 'READ',
      });

    expect(res.status).toBe(200);
    expect(res.body.permission.accessLevel).toBe('READ');
  });

  it('SEC-DAY2-07: Viewer can now download the shared document', async () => {
    const res = await request(app)
      .get(`/api/documents/${uploadedDocId}/download`)
      .set('Cookie', `token=${viewerToken}`);

    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toBe('application/pdf');
    expect(res.headers['content-disposition']).toMatch(/attachment/);
  });

  it('SEC-DAY2-08: Viewer with READ access CANNOT upload a new version (403 Forbidden)', async () => {
    const v2Buffer = Buffer.from('%PDF-1.4\n%Version 2 updated content\n%%EOF');

    const res = await request(app)
      .post(`/api/documents/${uploadedDocId}/versions`)
      .set('Cookie', `token=${viewerToken}`)
      .field('changeSummary', 'Illegal version attempt')
      .attach('file', v2Buffer, 'v2.pdf');

    expect(res.status).toBe(403);
    expect(res.body.error).toMatch(/read-only access/i);
  });

  it('SEC-DAY2-09: Owner promotes Viewer to EDIT access, and Viewer uploads Version 2', async () => {
    // 1. Promote to EDIT
    await request(app)
      .post(`/api/documents/${uploadedDocId}/permissions`)
      .set('Cookie', `token=${ownerToken}`)
      .send({
        email: 'viewer@vault.local',
        accessLevel: 'EDIT',
      })
      .expect(200);

    // 2. Viewer uploads v2
    const v2Buffer = Buffer.from('%PDF-1.4\n%Version 2 legitimate updated content\n%%EOF');
    const res = await request(app)
      .post(`/api/documents/${uploadedDocId}/versions`)
      .set('Cookie', `token=${viewerToken}`)
      .field('changeSummary', 'Quarterly figures updated by collaborator')
      .attach('file', v2Buffer, 'v2.pdf');

    expect(res.status).toBe(200);
    expect(res.body.currentVersion).toBe(2);
  });

  it('SEC-DAY2-10: Instant Revocation cuts off Viewer immediately on the very next request', async () => {
    // 1. Owner revokes access
    const revokeRes = await request(app)
      .delete(`/api/documents/${uploadedDocId}/permissions/${viewerUserId}`)
      .set('Cookie', `token=${ownerToken}`);

    expect(revokeRes.status).toBe(200);

    // 2. Viewer immediately attempts to download: MUST FAIL with 401 or 403 at T=0
    const downloadRes = await request(app)
      .get(`/api/documents/${uploadedDocId}/download`)
      .set('Cookie', `token=${viewerToken}`);

    expect([401, 403]).toContain(downloadRes.status);
  });

  it('SEC-DAY2-11: Cryptographic audit chain remains 100% verified across all Day 2 operations', async () => {
    const verification = await AuditService.verifyChainIntegrity();
    expect(verification.valid).toBe(true);
    expect(verification.totalEntries).toBeGreaterThan(10);
  });
});
