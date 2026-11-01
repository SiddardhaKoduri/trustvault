import { describe, it, expect } from 'vitest';

const BASE_URL = 'https://trustvault-zero-trust.onrender.com';

async function request(path: string, options: RequestInit = {}) {
  const url = `${BASE_URL}${path}`;
  const res = await fetch(url, {
    ...options,
    headers: {
      ...options.headers,
    },
  });
  const text = await res.text();
  let json: any = null;
  try {
    json = JSON.parse(text);
  } catch {}
  return {
    status: res.status,
    headers: res.headers,
    json,
    text,
  };
}

function getCookie(headers: Headers): string {
  const setCookie = headers.get('set-cookie');
  if (!setCookie) return '';
  const match = setCookie.match(/token=([^;]+)/);
  return match ? `token=${match[1]}` : '';
}

async function runLiveAudit() {
  console.log(`\n======================================================`);
  console.log(`  🕵️  TRUSTVAULT LIVE CLOUD PENETRATION & AUDIT TEST `);
  console.log(`  Target: ${BASE_URL}`);
  console.log(`======================================================\n`);

  let passed = 0;
  let failed = 0;

  function assert(condition: boolean, name: string, detail?: string) {
    if (condition) {
      console.log(`  ✅ PASS: ${name}`);
      passed++;
    } else {
      console.error(`  ❌ FAIL: ${name} ${detail ? `(${detail})` : ''}`);
      failed++;
    }
  }

  // 1. Healthcheck & Perimeter Headers
  console.log(`\n[Stage 1: Perimeter Security & HTTP Headers]`);
  const healthRes = await request('/api/health');
  assert(healthRes.status === 200 && healthRes.json?.status === 'HEALTHY', 'GET /api/health responds with 200 HEALTHY');
  assert(healthRes.headers.get('content-security-policy') !== null, 'Content-Security-Policy header present');
  assert(healthRes.headers.get('x-content-type-options') === 'nosniff', 'X-Content-Type-Options: nosniff enforced');
  assert(healthRes.headers.get('x-frame-options') !== null, 'X-Frame-Options clickjacking defense present');

  // 2. Authentication & Cookie Flags
  console.log(`\n[Stage 2: Zero-Trust Authentication & Session Integrity]`);
  const adminLogin = await request('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'admin@vault.local', password: 'VaultPassword2026!' }),
  });
  assert(adminLogin.status === 200 && adminLogin.json?.user?.role === 'ADMIN', 'Admin authentication succeeded');
  const adminCookie = getCookie(adminLogin.headers);
  assert(adminCookie.length > 0, 'Session token cookie issued');
  const setCookieHeader = adminLogin.headers.get('set-cookie') || '';
  assert(setCookieHeader.toLowerCase().includes('httponly'), 'Cookie has HttpOnly flag');
  assert(setCookieHeader.toLowerCase().includes('samesite=lax'), 'Cookie has SameSite=Lax flag');

  const ownerLogin = await request('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'owner@vault.local', password: 'VaultPassword2026!' }),
  });
  const ownerCookie = getCookie(ownerLogin.headers);
  assert(ownerLogin.status === 200 && ownerLogin.json?.user?.role === 'OWNER', 'Owner authentication succeeded');

  const viewerLogin = await request('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'viewer@vault.local', password: 'VaultPassword2026!' }),
  });
  let viewerCookie = getCookie(viewerLogin.headers);
  const viewerUserId = viewerLogin.json?.user?.id;
  assert(viewerLogin.status === 200 && viewerLogin.json?.user?.role === 'VIEWER', 'Viewer authentication succeeded');

  // 3. Privilege Escalation Prevention
  console.log(`\n[Stage 3: Privilege Escalation & Ingestion Protections]`);
  const rogueAdminRegister = await request('/api/auth/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      name: 'Rogue Hacker',
      email: `hacker_${Date.now()}@exploit.com`,
      password: 'HackerPassword123!',
      role: 'ADMIN',
    }),
  });
  assert(rogueAdminRegister.status === 403, 'Public registration blocks ADMIN role assignment with 403 Forbidden');

  // 4. In-Memory Magic-Byte Validation & Spoofing Defense
  const formDataShellcode = new FormData();
  formDataShellcode.append('title', 'exploit_shellcode.pdf');
  formDataShellcode.append('file', new Blob([Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x02])]), 'exploit_shellcode.pdf');
  const shellcodeRes = await fetch(`${BASE_URL}/api/documents`, {
    method: 'POST',
    headers: { Cookie: ownerCookie },
    body: formDataShellcode,
  });
  const shellcodeText = await shellcodeRes.text();
  assert(
    shellcodeRes.status === 400,
    'Rejects fake PDF with Linux ELF shellcode magic bytes with 400 Bad Request',
    `Status was ${shellcodeRes.status}: ${shellcodeText}`
  );

  const formDataScript = new FormData();
  formDataScript.append('title', 'xss_payload.txt');
  formDataScript.append('file', new Blob([Buffer.from('<script>alert(document.cookie)</script>')]), 'xss.txt');
  const scriptRes = await fetch(`${BASE_URL}/api/documents`, {
    method: 'POST',
    headers: { Cookie: ownerCookie },
    body: formDataScript,
  });
  const scriptText = await scriptRes.text();
  assert(
    scriptRes.status === 400,
    'Rejects text file containing <script> markup with 400 Bad Request',
    `Status was ${scriptRes.status}: ${scriptText}`
  );

  // 5. Valid Upload & Administrative Blindness
  console.log(`\n[Stage 4: Document Ingestion & Administrative Blindness]`);
  const validPdfBuffer = Buffer.from('%PDF-1.7\nTop Secret Project Document\n%%EOF');
  const formDataValid = new FormData();
  formDataValid.append('title', 'Live Cloud Confidential Vault Doc.pdf');
  formDataValid.append('category', 'Executive');
  formDataValid.append('description', 'High-assurance test document in production cloud.');
  formDataValid.append('file', new Blob([validPdfBuffer]), 'document.pdf');

  const uploadRes = await fetch(`${BASE_URL}/api/documents`, {
    method: 'POST',
    headers: { Cookie: ownerCookie },
    body: formDataValid,
  });
  const uploadJson = await uploadRes.json();
  const testDocId = uploadJson.document?.id;
  assert(uploadRes.status === 201 && !!testDocId, 'Owner successfully uploaded valid PDF to vault');

  // Administrative Blindness Checks
  const adminViewRes = await request(`/api/documents/${testDocId}`, {
    headers: { Cookie: adminCookie },
  });
  assert(adminViewRes.status === 403, 'Administrative Blindness: Admin CANNOT view document metadata (403 Forbidden)');

  const adminDownloadRes = await request(`/api/documents/${testDocId}/download`, {
    headers: { Cookie: adminCookie },
  });
  assert(adminDownloadRes.status === 403, 'Administrative Blindness: Admin CANNOT stream document binary (403 Forbidden)');

  // 6. Granular Sharing, Versioning & Instant Revocation
  console.log(`\n[Stage 5: Access Grants, Versioning & Instant Revocation (T=0)]`);
  const viewerBeforeShare = await request(`/api/documents/${testDocId}`, {
    headers: { Cookie: viewerCookie },
  });
  assert(viewerBeforeShare.status === 403, 'Unshared viewer CANNOT access document (403 Forbidden)');

  const shareRes = await request(`/api/documents/${testDocId}/permissions`, {
    method: 'POST',
    headers: { Cookie: ownerCookie, 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'viewer@vault.local', accessLevel: 'READ' }),
  });
  assert(shareRes.status === 200, 'Owner granted READ permission to viewer@vault.local');

  const viewerAfterShare = await request(`/api/documents/${testDocId}`, {
    headers: { Cookie: viewerCookie },
  });
  assert(viewerAfterShare.status === 200, 'Viewer can now access document metadata after share');

  const viewerDownload = await request(`/api/documents/${testDocId}/download`, {
    headers: { Cookie: viewerCookie },
  });
  assert(viewerDownload.status === 200 && viewerDownload.text.includes('Top Secret'), 'Viewer can stream authorized document content');

  // Instant Revocation (T=0)
  const revokeRes = await request(`/api/documents/${testDocId}/permissions/${viewerUserId}`, {
    method: 'DELETE',
    headers: { Cookie: ownerCookie },
  });
  assert(revokeRes.status === 200, 'Owner revoked viewer access');

  const viewerImmediateAttempt = await request(`/api/documents/${testDocId}/download`, {
    headers: { Cookie: viewerCookie },
  });
  assert([401, 403].includes(viewerImmediateAttempt.status), 'Instant Revocation: Viewer access terminated at T=0 (401/403)');

  // 7. Trash, Restore & Permanent Purge Lifecycle
  console.log(`\n[Stage 6: Trash, Restore & Permanent Purge Lifecycle]`);
  const trashRes = await request(`/api/documents/${testDocId}`, {
    method: 'DELETE',
    headers: { Cookie: ownerCookie },
  });
  assert(trashRes.status === 200, 'Owner moved document to Trash');

  const restoreRes = await request(`/api/documents/${testDocId}/restore`, {
    method: 'POST',
    headers: { Cookie: ownerCookie },
  });
  assert(restoreRes.status === 200, 'Owner restored document from Trash');

  // Trash again and permanently purge
  await request(`/api/documents/${testDocId}`, {
    method: 'DELETE',
    headers: { Cookie: ownerCookie },
  });
  const purgeRes = await request(`/api/documents/${testDocId}/purge`, {
    method: 'DELETE',
    headers: { Cookie: ownerCookie },
  });
  assert(purgeRes.status === 200, 'Owner permanently purged document and disk blobs from vault');

  const checkPurged = await request(`/api/documents/${testDocId}`, {
    headers: { Cookie: ownerCookie },
  });
  assert(checkPurged.status === 404, 'Purged document no longer exists in vault');

  // 8. Cryptographic Audit Chain Verification
  console.log(`\n[Stage 7: Live Cryptographic Audit Chain Integrity]`);
  const verifyChainRes = await request('/api/audit/verify', {
    headers: { Cookie: adminCookie },
  });
  assert(
    verifyChainRes.status === 200 && verifyChainRes.json?.valid === true,
    `Cryptographic chain mathematically verified: ${verifyChainRes.json?.totalEntries} blocks intact`
  );

  // Re-login viewer to get an active session token with their updated epoch
  const viewerRelogin = await request('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'viewer@vault.local', password: 'VaultPassword2026!' }),
  });
  const freshViewerCookie = getCookie(viewerRelogin.headers);

  const viewerAuditRes = await request('/api/audit', {
    headers: { Cookie: freshViewerCookie },
  });
  assert(viewerAuditRes.status === 403, 'Viewers are strictly forbidden from inspecting system audit logs (403)');

  console.log(`\n======================================================`);
  console.log(`  AUDIT SCORECARD: ${passed} PASSED | ${failed} FAILED`);
  console.log(`======================================================\n`);
}

runLiveAudit().catch(console.error);
