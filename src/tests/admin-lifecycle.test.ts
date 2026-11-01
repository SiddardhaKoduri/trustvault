import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import request from 'supertest';
import { app } from '../app.js';
import { prisma } from '../lib/prisma.js';
import { AuditService } from '../services/audit.service.js';

describe('Day 2 Additions: Document Metadata, Purge & Admin User Management', () => {
  let adminToken: string;
  let ownerToken: string;
  let viewerToken: string;
  let viewerUserId: string;
  let testDocId: string;

  beforeAll(async () => {
    await prisma.$connect();

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

    // Upload a test document for update & purge
    const docRes = await request(app)
      .post('/api/documents')
      .set('Cookie', `token=${ownerToken}`)
      .field('title', 'Lifecycle Test Doc')
      .field('category', 'Legal')
      .attach('file', Buffer.from('%PDF-1.4\nTest PDF content\n%%EOF'), 'test.pdf');
    testDocId = docRes.body.document.id;
  });

  afterAll(async () => {
    await prisma.$disconnect();
  });

  it('SEC-LIFECYCLE-01: Owner and Editor can update/rename document metadata', async () => {
    // 1. Owner renames document
    const res = await request(app)
      .put(`/api/documents/${testDocId}`)
      .set('Cookie', `token=${ownerToken}`)
      .send({
        title: 'Renamed Legal Contract 2026',
        category: 'Legal Agreements',
        description: 'Updated description for legal contract',
      });

    expect(res.status).toBe(200);
    expect(res.body.document.title).toBe('Renamed_Legal_Contract_2026');
    expect(res.body.document.category).toBe('Legal Agreements');
  });

  it('SEC-LIFECYCLE-02: Viewer CANNOT rename document (403 Forbidden)', async () => {
    // 1. Grant READ to Viewer
    await request(app)
      .post(`/api/documents/${testDocId}/permissions`)
      .set('Cookie', `token=${ownerToken}`)
      .send({ email: 'viewer@vault.local', accessLevel: 'READ' })
      .expect(200);

    // 2. Viewer tries to rename
    const res = await request(app)
      .put(`/api/documents/${testDocId}`)
      .set('Cookie', `token=${viewerToken}`)
      .send({ title: 'Malicious Rename' });

    expect(res.status).toBe(403);
    expect(res.body.error).toMatch(/read-only access/i);
  });

  it('SEC-LIFECYCLE-03: Admin User Directory access control', async () => {
    // Admin can list users
    const adminRes = await request(app)
      .get('/api/admin/users')
      .set('Cookie', `token=${adminToken}`);

    expect(adminRes.status).toBe(200);
    expect(Array.isArray(adminRes.body.users)).toBe(true);
    expect(adminRes.body.users.length).toBeGreaterThanOrEqual(3);

    // Non-Admin (Owner) is strictly blocked from Admin API
    const ownerRes = await request(app)
      .get('/api/admin/users')
      .set('Cookie', `token=${ownerToken}`);

    expect(ownerRes.status).toBe(403);
  });

  it('SEC-LIFECYCLE-04: Admin deactivates user, resulting in instant session termination', async () => {
    // 1. Admin deactivates Viewer
    const deactivateRes = await request(app)
      .patch(`/api/admin/users/${viewerUserId}/status`)
      .set('Cookie', `token=${adminToken}`)
      .send({ isActive: false });

    expect(deactivateRes.status).toBe(200);
    expect(deactivateRes.body.user.isActive).toBe(false);

    // 2. Viewer immediately tries to access /api/documents -> MUST FAIL at T=0
    const accessRes = await request(app)
      .get('/api/documents')
      .set('Cookie', `token=${viewerToken}`);

    expect([401, 403]).toContain(accessRes.status);

    // 3. Admin re-activates Viewer for subsequent clean state
    await request(app)
      .patch(`/api/admin/users/${viewerUserId}/status`)
      .set('Cookie', `token=${adminToken}`)
      .send({ isActive: true })
      .expect(200);

    // 4. Viewer re-authenticates to acquire updated token reflecting new epoch
    const reauthRes = await request(app)
      .post('/api/auth/login')
      .send({ email: 'viewer@vault.local', password: 'VaultPassword2026!' });
    viewerToken = reauthRes.body.token;
  });

  it('SEC-LIFECYCLE-05: Non-owner CANNOT purge document; Owner can permanently purge', async () => {
    // Viewer tries to purge
    const failRes = await request(app)
      .delete(`/api/documents/${testDocId}/purge`)
      .set('Cookie', `token=${viewerToken}`);
    expect([401, 403]).toContain(failRes.status);

    // Owner purges document
    const purgeRes = await request(app)
      .delete(`/api/documents/${testDocId}/purge`)
      .set('Cookie', `token=${ownerToken}`);

    expect(purgeRes.status).toBe(200);
    expect(purgeRes.body.message).toMatch(/permanently purged/i);

    // Verify document no longer exists in DB
    const docCheck = await prisma.document.findUnique({ where: { id: testDocId } });
    expect(docCheck).toBeNull();
  });

  it('SEC-LIFECYCLE-07: Soft-delete to Trash, then Permanent Purge from Trash by Owner', async () => {
    // 1. Upload a document to test trash-to-purge cycle
    const uploadRes = await request(app)
      .post('/api/documents')
      .set('Cookie', `token=${ownerToken}`)
      .field('title', 'Trash To Purge Doc')
      .attach('file', Buffer.from('%PDF-1.4\nTrash and purge\n%%EOF'), 'trash.pdf');
    const trashDocId = uploadRes.body.document.id;

    // 2. Soft delete to Trash
    await request(app)
      .delete(`/api/documents/${trashDocId}`)
      .set('Cookie', `token=${ownerToken}`)
      .expect(200);

    // 3. Verify it is marked isDeleted in DB
    const inTrash = await prisma.document.findUnique({ where: { id: trashDocId } });
    expect(inTrash?.isDeleted).toBe(true);

    // 4. Non-owner cannot purge even while in trash
    await request(app)
      .delete(`/api/documents/${trashDocId}/purge`)
      .set('Cookie', `token=${viewerToken}`)
      .expect(403);

    // 5. Owner permanently purges from trash
    const purgeTrashRes = await request(app)
      .delete(`/api/documents/${trashDocId}/purge`)
      .set('Cookie', `token=${ownerToken}`);

    expect(purgeTrashRes.status).toBe(200);
    expect(purgeTrashRes.body.message).toMatch(/permanently purged/i);

    // 6. Confirm purged from DB
    const deletedCheck = await prisma.document.findUnique({ where: { id: trashDocId } });
    expect(deletedCheck).toBeNull();
  });

  it('SEC-LIFECYCLE-08: Document-specific access audit trail access control', async () => {
    // 1. Create a doc
    const uploadRes = await request(app)
      .post('/api/documents')
      .set('Cookie', `token=${ownerToken}`)
      .field('title', 'Audit Access Doc')
      .attach('file', Buffer.from('%PDF-1.4\nAudit access\n%%EOF'), 'audit.pdf');
    const docId = uploadRes.body.document.id;

    // 2. Viewer tries to inspect document audit ledger -> 403 Forbidden
    const viewerRes = await request(app)
      .get(`/api/audit/document/${docId}`)
      .set('Cookie', `token=${viewerToken}`);
    expect(viewerRes.status).toBe(403);
    expect(viewerRes.body.error).toMatch(/Forbidden/i);

    // 3. Owner inspects document audit ledger -> 200 with events
    const ownerRes = await request(app)
      .get(`/api/audit/document/${docId}`)
      .set('Cookie', `token=${ownerToken}`);
    expect(ownerRes.status).toBe(200);
    expect(ownerRes.body.documentId).toBe(docId);
    expect(Array.isArray(ownerRes.body.logs)).toBe(true);
    expect(ownerRes.body.logs.length).toBeGreaterThanOrEqual(1);

    // Cleanup doc
    await request(app)
      .delete(`/api/documents/${docId}/purge`)
      .set('Cookie', `token=${ownerToken}`);
  });

  it('SEC-LIFECYCLE-09: Rejects active script, HTML, or SVG markup in document uploads', async () => {
    const maliciousHtml = '<!DOCTYPE html><html><body><script>alert(document.cookie)</script></body></html>';
    const res = await request(app)
      .post('/api/documents')
      .set('Cookie', `token=${ownerToken}`)
      .field('title', 'Malicious Document')
      .attach('file', Buffer.from(maliciousHtml), 'exploit.txt');

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/prohibited/i);
  });

  it('SEC-LIFECYCLE-06: Cryptographic audit chain remains intact after all lifecycle actions', async () => {
    const verification = await AuditService.verifyChainIntegrity();
    expect(verification.valid).toBe(true);
  });
});
