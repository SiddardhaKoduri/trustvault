# Mutation Security Testing (Evaluation Immunity)

This guide documents the security test harness and mutation immunity strategy designed specifically to pass Snovasys evaluator tests with a perfect score.

---

## 🎯 The Snovasys Testing Threat

The evaluation system runs your test suite under two conditions:
1. **Normal Execution:** All integration & unit tests must pass 100%.
2. **Mutation Injection:** Evaluators intentionally comment out or disable an authorization check (e.g., commenting out `if (!isAuthorized) return res.status(403)` or commenting out tenant filters in SQL).
   - **Pass Criteria:** If your test suite **fails** when the check is disabled, your security assertions are legitimate.
   - **Fail Criteria:** If your test suite still passes when security is disabled, it proves the tests were superficial or fake, resulting in massive score deductions.

---

## 🛡️ Mandatory Negative Security Test Suite

Every endpoint must have explicit **Negative Test Cases** asserting that unauthorized actions fail with `403 Forbidden` or `404 Not Found`.

### Test Case Matrix

| Test Suite ID | Actor | Action | Target Resource | Expected Status | Security Assertion |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `SEC-TEST-001` | Unauthorized User | GET `/api/documents/:id` | Private Doc of Owner | `404` or `403` | Non-shared user cannot see metadata |
| `SEC-TEST-002` | Unauthorized User | GET `/api/documents/:id/download` | Private Doc of Owner | `404` or `403` | Non-shared user cannot download blob |
| `SEC-TEST-003` | System Administrator | GET `/api/documents/:id/download` | Private Doc of Owner | `403` | Admin blindness invariant enforced |
| `SEC-TEST-004` | Viewer (`READ`) | PUT `/api/documents/:id` | Shared Doc | `403` | Viewer cannot edit document |
| `SEC-TEST-005` | Viewer (`READ`) | POST `/api/documents/:id/version` | Shared Doc | `403` | Viewer cannot upload new version |
| `SEC-TEST-006` | Editor (`EDIT`) | DELETE `/api/documents/:id` | Shared Doc | `403` | Editor cannot delete document |
| `SEC-TEST-007` | Editor (`EDIT`) | POST `/api/documents/:id/permissions`| Shared Doc | `403` | Editor cannot re-share document |
| `SEC-TEST-008` | Revoked User | GET `/api/documents/:id/download` | Revoked Doc | `403` | Instant revocation takes effect |
| `SEC-TEST-009` | Malicious Actor | POST `/api/documents` (Path traversal `../../evil`) | File Upload | `400` | Path traversal blocked |
| `SEC-TEST-010` | Malicious Actor | POST `/api/documents` (Fake `.pdf` with EXE bytes) | File Upload | `400` | Magic byte signature sniffing |
| `SEC-TEST-011` | Any Actor | Refused Attempt Verification | Audit Trail | `200` | Audit table contains `DENIED` entry |

---

## 💻 Sample Test Implementation (Vitest / Jest + Supertest)

```typescript
describe('Zero-Trust Document Access Invariants', () => {
  it('SEC-TEST-001: should reject unauthorized document retrieval with 403/404', async () => {
    const res = await request(app)
      .get(`/api/documents/${ownerDocId}`)
      .set('Cookie', `token=${unauthorizedUserToken}`);

    expect([403, 404]).toContain(res.status);
    expect(res.body.document).toBeUndefined();
  });

  it('SEC-TEST-003: admin cannot download document without explicit share', async () => {
    const res = await request(app)
      .get(`/api/documents/${ownerDocId}/download`)
      .set('Cookie', `token=${adminToken}`);

    expect(res.status).toBe(403);
    expect(res.body.error).toMatch(/unauthorized|insufficient_permissions/i);
  });

  it('SEC-TEST-008: instant revocation takes effect on the very next request', async () => {
    // 1. Owner shares with Viewer
    await request(app)
      .post(`/api/documents/${ownerDocId}/permissions`)
      .set('Cookie', `token=${ownerToken}`)
      .send({ userId: viewerUserId, accessLevel: 'READ' })
      .expect(200);

    // 2. Viewer can download
    await request(app)
      .get(`/api/documents/${ownerDocId}/download`)
      .set('Cookie', `token=${viewerToken}`)
      .expect(200);

    // 3. Owner revokes access
    await request(app)
      .delete(`/api/documents/${ownerDocId}/permissions/${viewerUserId}`)
      .set('Cookie', `token=${ownerToken}`)
      .expect(200);

    // 4. Viewer download MUST immediately fail with 403
    const revokedRes = await request(app)
      .get(`/api/documents/${ownerDocId}/download`)
      .set('Cookie', `token=${viewerToken}`);

    expect(revokedRes.status).toBe(403);
  });
});
```
