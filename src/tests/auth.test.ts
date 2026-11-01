import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import request from 'supertest';
import { app } from '../app.js';
import { prisma } from '../lib/prisma.js';
import { AuditService } from '../services/audit.service.js';

describe('Day 1: Zero-Trust Authentication & Audit Engine', () => {
  beforeAll(async () => {
    // Ensure DB is connected
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
        email: 'admin@vault.local',
        password: 'VaultPassword2026!',
      });

    expect(res.status).toBe(200);
    expect(res.body.user.role).toBe('ADMIN');
    expect(res.body.token).toBeDefined();

    // Check Set-Cookie header contains token and HttpOnly
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

    // Assert that the denied attempt was written to the audit log
    const lastAudit = await prisma.auditLog.findFirst({
      orderBy: { id: 'desc' },
    });

    expect(lastAudit).toBeDefined();
    expect(lastAudit?.action).toBe('AUTH_LOGIN_FAILED');
    expect(lastAudit?.outcome).toBe('DENIED');
  });

  it('GET /api/auth/me without token should return 401 unauthorized', async () => {
    const res = await request(app).get('/api/auth/me');
    expect(res.status).toBe(401);
  });

  it('GET /api/auth/me with valid cookie should return current user', async () => {
    // 1. Sign in as Owner
    const loginRes = await request(app)
      .post('/api/auth/login')
      .send({
        email: 'owner@vault.local',
        password: 'VaultPassword2026!',
      });

    const token = loginRes.body.token;

    // 2. Fetch /me
    const meRes = await request(app)
      .get('/api/auth/me')
      .set('Cookie', `token=${token}`);

    expect(meRes.status).toBe(200);
    expect(meRes.body.user.email).toBe('owner@vault.local');
    expect(meRes.body.user.role).toBe('OWNER');
  });

  it('Audit chain remains 100% cryptographically intact after auth events', async () => {
    const verification = await AuditService.verifyChainIntegrity();
    expect(verification.valid).toBe(true);
    expect(verification.totalEntries).toBeGreaterThan(1);
  });
});
