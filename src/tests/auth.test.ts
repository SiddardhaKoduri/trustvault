import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import request from 'supertest';
import { app } from '../app.js';
import { prisma } from '../lib/prisma.js';
import { AuditService } from '../services/audit.service.js';

describe('Day 1: Zero-Trust Authentication, RBAC & Chained Audit Verification', () => {
  beforeAll(async () => {
    await prisma.$connect();
  });

  afterAll(async () => {
    await prisma.$disconnect();
  });

  it('GET /api/health should return 200 and healthy status', async () => {
    const res = await request(app).get('/api/health');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('HEALTHY');
  });

  it('POST /api/auth/login should authenticate Admin successfully and set HTTP-only cookie', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({
        email: 'ADMIN@VAULT.LOCAL', // test case-insensitivity
        password: 'VaultPassword2026!',
      });

    expect(res.status).toBe(200);
    expect(res.body.user.role).toBe('ADMIN');
    expect(res.body.token).toBeDefined();

    const cookies = res.headers['set-cookie'];
    expect(cookies).toBeDefined();
    expect(cookies[0]).toMatch(/token=/);
    expect(cookies[0]).toMatch(/HttpOnly/i);
  });

  it('POST /api/auth/login with wrong password should return 401 and log refused attempt', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({
        email: 'admin@vault.local',
        password: 'WrongPassword!',
      });

    expect(res.status).toBe(401);
    expect(res.body.error).toMatch(/invalid/i);

    const lastAudit = await prisma.auditLog.findFirst({
      orderBy: { id: 'desc' },
    });

    expect(lastAudit).toBeDefined();
    expect(lastAudit?.action).toBe('AUTH_LOGIN_FAILED');
    expect(lastAudit?.outcome).toBe('DENIED');
  });

  it('POST /api/auth/register should REJECT self-assignment of ADMIN role (Privilege Escalation)', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({
        name: 'Attacker Rogue Admin',
        email: 'attacker@vault.local',
        password: 'AttackerPassword123!',
        role: 'ADMIN',
      });

    expect(res.status).toBe(403);
    expect(res.body.error).toMatch(/forbidden|prohibited/i);

    // Assert that the privilege escalation was captured in audit trail
    const auditRecord = await prisma.auditLog.findFirst({
      where: { action: 'PRIVILEGE_ESCALATION_ATTEMPT' },
      orderBy: { id: 'desc' },
    });
    expect(auditRecord).toBeDefined();
    expect(auditRecord?.outcome).toBe('DENIED');
  });

  it('POST /api/auth/register should allow valid registration as OWNER or VIEWER', async () => {
    const uniqueEmail = `charlie_${Date.now()}@vault.local`;
    const res = await request(app)
      .post('/api/auth/register')
      .send({
        name: 'Charlie New Owner',
        email: uniqueEmail,
        password: 'CharliePassword123!',
        role: 'OWNER',
      });

    expect(res.status).toBe(201);
    expect(res.body.user.role).toBe('OWNER');
    expect(res.body.user.email).toBe(uniqueEmail);
  });

  it('GET /api/auth/me without token should return 401 unauthorized', async () => {
    const res = await request(app).get('/api/auth/me');
    expect(res.status).toBe(401);
  });

  it('GET /api/auth/me with valid cookie should return current user', async () => {
    const loginRes = await request(app)
      .post('/api/auth/login')
      .send({
        email: 'owner@vault.local',
        password: 'VaultPassword2026!',
      });

    const token = loginRes.body.token;

    const meRes = await request(app)
      .get('/api/auth/me')
      .set('Cookie', `token=${token}`);

    expect(meRes.status).toBe(200);
    expect(meRes.body.user.email).toBe('owner@vault.local');
    expect(meRes.body.user.role).toBe('OWNER');
  });

  it('Audit chain remains 100% cryptographically intact after all events and attacks', async () => {
    const verification = await AuditService.verifyChainIntegrity();
    expect(verification.valid).toBe(true);
    expect(verification.totalEntries).toBeGreaterThan(4);
  });
});
