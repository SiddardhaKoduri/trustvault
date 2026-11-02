# TrustVault — AI Collaboration & Technical Oversight Ledger (PROMPTS.md)

This document is maintained chronologically throughout the Snovasys Fresher Hiring Challenge 2026. It records the prompts issued to AI assistants, the raw output received, the critical security and architectural flaws caught during human review, the corrections applied, the test verifications performed, and the exact Git commit references.

---

## 📅 Phase 1 — Sunday, 1 November 2026

### Entry 001: Architecture & Threat Model Inception
- **Commit Reference:** `b04d49e`
- **Date & Time:** 2026-11-01 13:00 IST
- **Target Area:** Architecture, Project Invariants & Skill Setup
- **Prompt Given to AI:**
  > "You can skip all the traditional ways to build this thing. Act like you have much experience giving your skill sets. Your task is to create a skill set that can be used for this project, which only the top 1% of people can use to build this entire thing. It should be flawless, and the most important thing is security, so it should be our first priority. Come up with a skill set that only the top 1% of the people can use, and you can skip all the traditional ways to build this thing. Install that skill set and use it for this entire project."
- **AI Initial Output / Recommendation:**
  The AI proposed a high-level secure document vault architecture, including RBAC with an Admin superuser that could manage all files, a standard JWT token stored in `localStorage`, and an audit log table written directly to the database.
- **Flaws & Security Risks Caught During Human Review:**
  1. **Administrative Overprivilege (Admin Peeking):** The AI gave the `ADMIN` role blanket read access to all documents. *Flaw:* In high-assurance zero-trust document sharing, Admins manage users and inspect system audit trails, but must have **zero intrinsic visibility into confidential document contents** unless an owner explicitly shares it with them.
  2. **Delayed Revocation via Stateless JWTs:** The AI suggested standard 24-hour JWTs. *Flaw:* Snovasys requires *immediate revocation*. If an owner revokes access or an admin deactivates a user, a stateless JWT would keep functioning until its expiration.
  3. **Mutable Audit Trail:** The AI proposed a normal SQLite/PostgreSQL audit table. *Flaw:* Any internal attacker or compromised SQL query could silently modify or delete rows. The audit log must be cryptographically chained via HMAC-SHA256 so tampering is provable.
- **Correction Applied & Final Architecture:**
  - Enforced the **Law of Administrative Blindness** in the Policy Decision Point (PDP).
  - Designed the **`permissionEpoch`** and active session validation to guarantee zero-millisecond revocation.
  - Implemented the **HMAC-SHA256 Cryptographic Hash Chain** (`EntryHash_k = HMAC_SHA256(secret, prevHash + payload)`).
  - Packaged these rules into the reusable project skill: `.agents/skills/top1-secure-vault-architect/`.
- **Verification:**
  - Successfully ran `scripts/audit_chain_verifier.js` verifying HMAC mathematical chain integrity.
  - Defined 9 invariant negative security test assertions in `scripts/mutation_test_runner.js`.

---

### Entry 002: Zero-Trust Auth Implementation, Benchmark Seed & Chained Audit Verification
- **Commit Reference:** `48a8502`
- **Date & Time:** 2026-11-01 13:13 IST
- **Target Component:** `src/controllers/auth.controller.ts`, `src/middleware/auth.middleware.ts`, `prisma/seed.ts`, `src/tests/auth.test.ts`
- **Initial Prompt Given to AI:**
  > "Scaffold the database schema and implement zero-trust authentication, benchmark seeds, and test the endpoints."
- **AI Initial Output / Recommendation:**
  The AI implemented basic login and registration controllers returning a JWT token in the JSON body, with no set-cookie header, and handled failed login attempts with a silent `401 Unauthorized` without logging.
- **Flaws & Security Risks Caught During Human Review:**
  1. **Token Insecurity (XSS vulnerability):** Returning JWT strictly in JSON response prompts frontend clients to store tokens in `localStorage`, exposing them to Cross-Site Scripting (XSS) extraction.
  2. **Audit Blindspot on Refused Attempts:** Failing to log failed authentication attempts violates Snovasys Core Standard 2 (*Verifiable Audit Trail: Every interaction, including refused attempts, must be logged*). Brute force attacks would go undetected.
  3. **Missing Epoch Invalidation:** The AI didn't include the `permissionEpoch` in the token signature, making instant token revocation impossible without database writes on every token decode.
- **Correction Applied & Final Code:**
  - Enforced `HttpOnly`, `SameSite=Lax`, and `Secure` cookie issuance for the session token.
  - Bound `AuditService.recordEvent({ action: 'AUTH_LOGIN_FAILED', outcome: 'DENIED', ... })` on any bad password or deactivated account attempt.
  - Embedded `permissionEpoch` in token payload and verified it against the database user record in `auth.middleware.ts`.
- **Verification & Test Result:**
  - Automated test suite `src/tests/auth.test.ts` passed 6/6 tests.
  - Verified `scripts/verify-db-chain.ts`: 4 cryptographic blocks verified 100% intact with zero tampering.

---

### Entry 003: Forensic Security Audit & Zero-Trust Hardening (Privilege Escalation Interception & Serialized Audit Mutex)
- **Commit Reference:** `595edd3`
- **Date & Time:** 2026-11-01 13:37 IST
- **Target Component:** `src/controllers/auth.controller.ts`, `src/services/audit.service.ts`, `src/app.ts`, `src/tests/auth.test.ts`
- **Initial Prompt Given to AI:**
  > "Before proceeding with Day 2, check thoroughly each and every corner and line of code to make sure it is 100% flawless."
- **Flaws & Security Risks Caught During Forensic Review:**
  1. **Privilege Escalation on Public Registration:** The registration endpoint allowed clients to pass `role: 'ADMIN'`. *Flaw:* Any anonymous attacker could self-register as a System Administrator. In zero-trust, public self-registration must never assign administrator privileges.
  2. **Audit Race Conditions under Concurrent Load:** `recordEvent` read the latest entry without serializing concurrent writes. *Flaw:* If two audit events occur simultaneously, both might read the same `previousHash`, causing a branch in the linear cryptographic chain.
  3. **Case-Sensitive Email Inconsistency:** Login and registration allowed mixed-case emails, risking credential spoofing or duplicate accounts.
  4. **Unauthenticated IP Resolution Gap:** Endpoints outside `auth.middleware.ts` lacked normalized IP resolution.
- **Correction Applied & Final Code:**
  - Blocked self-assignment of `ADMIN` in `auth.controller.ts`, returning `403 Forbidden` and logging a `PRIVILEGE_ESCALATION_ATTEMPT` audit event.
  - Built an in-memory asynchronous Promise Mutex in `AuditService` ensuring 100% linear, sequential cryptographic hash calculations.
  - Normalized all email inputs to `.toLowerCase().trim()`.
  - Added global client IP normalization middleware in `app.ts`.
- **Verification & Test Result:**
  - Expanded test suite to 8 tests in `src/tests/auth.test.ts`, verifying that attempting to register an `ADMIN` account fails with 403 and logs to the audit ledger.
  - All 8 tests passed in 1.54s.
  - Ran `scripts/verify-db-chain.ts`: All 6 blocks cryptographically verified with 0 defects.

---

## 📅 Phase 2 — Sunday, 1 November 2026

### Entry 004: Defensive Uploads, Magic-Byte Sniffing, Versioning & Instant Revocation
- **Commit Reference:** `571204c`
- **Date & Time:** 2026-11-01 13:43 IST
- **Target Component:** `src/services/file.service.ts`, `src/controllers/document.controller.ts`, `src/routes/document.routes.ts`, `src/tests/document.test.ts`
- **Initial Prompt Given to AI:**
  > "Proceed with Day 2: Build the defensive file upload pipeline, magic-byte inspection, isolated storage, versioning, granular sharing, and instant revocation."
- **AI Initial Output / Recommendation:**
  The AI suggested using Multer with `diskStorage` writing directly to `uploads/` based on client filename extensions (`file.originalname`), and checking permissions only at the route handler with `if (req.user.id !== doc.ownerId) return 403`.
- **Flaws & Security Risks Caught During Human Review:**
  1. **Arbitrary File Upload & Shellcode Injection:** Relying on filename extensions allows an attacker to upload an executable (`.exe` or `.elf`) disguised as `file.pdf`. The server would accept malicious binary executables.
  2. **Path Traversal Vulnerability:** Saving files using user-supplied names like `../../../../etc/shadow` risks writing files outside the storage sandbox.
  3. **Direct Disk Leakage:** Writing unvalidated uploads directly to disk leaves malicious payloads on the filesystem even if processing later errors out.
  4. **Audit Hash Forking in Multi-Worker Environments:** Concurrent test runners and worker threads forked the audit hash chain when reading `previousHash` outside an atomic database transaction.
- **Correction Applied & Final Code:**
  - Implemented **Memory-Buffered Magic-Byte Inspection** in `FileService.validateMagicBytes`: sniffs raw header bytes (`%PDF-`, PNG `0x89504E47`, JPEG `0xFFD8FF`, and non-null UTF-8 text) before any byte is written to storage.
  - Neutralized Path Traversal using `path.basename()` and regex sanitization.
  - Commits files to disk under non-deterministic UUID v4 keys (`crypto.randomUUID()`) in `storage/blobs/`, completely isolated from original filenames.
  - Enforced atomic database transactions (`prisma.$transaction`) in `AuditService.recordEvent` to ensure linear hash chain integrity across all concurrent threads.
  - Built **Instant Revocation Mechanism**: revoking a user deletes `DocumentPermission` and immediately cuts off access at $T=0$.
- **Verification & Test Result:**
  - Added 11 automated security tests in `src/tests/document.test.ts` covering magic bytes, shellcode rejection, path traversal sanitization, Administrative Blindness, and instant revocation.
  - All 19 tests across `auth.test.ts` and `document.test.ts` passed 100%.
  - Ran `scripts/verify-db-chain.ts`: All 20 cryptographic blocks verified intact with zero tampering.

---

### Entry 005: Full Day 2 Completeness & Security Hardening (Document Renaming, Purge, Admin User Directory & Rate Limiting)
- **Commit Reference:** `334bf80`
- **Date & Time:** 2026-11-01 13:52 IST
- **Target Component:** `src/controllers/document.controller.ts`, `src/controllers/admin.controller.ts`, `src/routes/admin.routes.ts`, `src/middleware/rate-limit.middleware.ts`, `src/tests/admin-lifecycle.test.ts`
- **Initial Prompt Given to AI:**
  > "Is there anything still left for Day 2 to reach that goal completely? Check Day 1 & Day 2 thoroughly for any vulnerabilities or gaps before moving to Day 3."
- **Flaws & Feature Gaps Caught During Comprehensive Audit:**
  1. **Missing Document Metadata Renaming:** The document controller had no endpoint for owners/editors to rename or update category/description metadata (`PUT /api/documents/:id`).
  2. **Missing Permanent Blob Purge:** Soft-delete moved documents to trash, but there was no permanent purge mechanism (`DELETE /api/documents/:id/purge`) to physically delete isolated file blobs from disk storage.
  3. **Admin User Lifecycle Gap:** While authentication verified `user.isActive`, the administrator lacked API endpoints to list users, create users, or toggle active/inactive status.
  4. **Unthrottled Endpoint Protection:** Endpoints were vulnerable to rapid brute-force without rate limiting (violating STRIDE Threat S-03 & D-02).
- **Correction Applied & Final Code:**
  - Implemented `updateDocument` (`PUT /api/documents/:id`) with title sanitization and PDP validation (only Owners and Editors can update; Viewers blocked).
  - Implemented `purgeDocument` (`DELETE /api/documents/:id/purge`) restricted to Document Owners; removes all physical storage blobs and database rows.
  - Built `AdminController` with `listUsers`, `updateUserStatus` (deactivation immediately bumps `permissionEpoch` cutting off active sessions at $T=0$), and `createUser`.
  - Built and mounted `createRateLimiter` middleware protecting login from brute-force attempts and logging violations to the audit trail.
- **Verification & Test Result:**
  - Added 6 new integration tests in `src/tests/admin-lifecycle.test.ts`.
  - Total test suite now runs **25 tests across 3 files**, with 100% passing.
  - Ran `scripts/verify-db-chain.ts`: All 31 cryptographic blocks verified intact with zero tampering.

---

## 📅 Phase 3 — Sunday, 1 November 2026

### Entry 006: Cryptographic Audit Explorer, Evaluator Mutation Immunity & Swiss Minimalist Frontend
- **Commit Reference:** `d747899`
- **Date & Time:** 2026-11-01 14:02 IST
- **Target Component:** `src/controllers/audit.controller.ts`, `src/routes/audit.routes.ts`, `src/tests/mutation-immunity.test.ts`, `public/index.html`, `public/css/style.css`, `public/js/app.js`
- **Initial Prompt Given to AI:**
  > "Build the UI using the refined Swiss Minimalist prompt. If Day 1 and Day 2 are verified, proceed with Day 3."
- **Flaws & Security Risks Caught During Human Review:**
  1. **Audit Ledger Privacy Boundary (Information Disclosure):** Initially, the audit controller would have exposed all events across all documents to any authenticated user. *Flaw:* Viewers must have zero visibility into system audit logs, and Document Owners should only see events concerning their own documents. Admins see system-wide logs but remain blind to file contents.
  2. **Evaluation Mutation Blindspot:** If an evaluator comments out an authorization check, tests that only test the "happy path" still pass. *Flaw:* Snovasys explicitly deducts marks if mutation testing passes with stripped authorization.
  3. **Visual Inconsistency:** Naive dashboards use rounded cards, blurry gradients, and floating dropshadows that undermine the perception of institutional security.
- **Correction Applied & Final Code:**
  - Built strict role-scoped audit retrieval in `audit.controller.ts` (`getSystemAuditLogs` for Admin; `getDocumentAuditLogs` for Owner; Viewers strictly blocked with 403).
  - Built dedicated `src/tests/mutation-immunity.test.ts` with 12 negative invariant test assertions proving that bypassing owner checks, admin blindness, permission levels, or magic byte sniffers immediately triggers test failure.
  - Implemented the complete **Swiss Minimalist** frontend in `public/`:
    - Strict 12-column grid with a 3-column persistent security rail and 9-column data matrix.
    - Authoritative design tokens (`#ffffff`, `#000000`, `#f0f0f0`, `#c90000`, 2px solid rules, 0px radius).
    - Interactive Cryptographic Audit Chain Explorer with block-by-block hash linkages and signal-red `[DENIED]` markers for failed attacks.
    - Real-time live Cryptographic Chain Integrity status indicator.
    - One-click benchmark persona switcher (`ADMIN`, `OWNER`, `VIEWER`) for evaluation walkthroughs.
- **Verification & Test Result:**
  - All 37 automated tests across 4 test suites passed with 100% success.
  - Verified `scripts/verify-db-chain.ts`: 91 blocks in the database audit chain verified 100% intact.

---

### Entry 007: Forensic Day 3 Security Audit, Trash Purge Bug Elimination & Full-Stack Hardening
- **Commit Reference:** `fae05f5`
- **Date & Time:** 2026-11-01 14:20 IST
- **Target Component:** `src/services/pdp.service.ts`, `src/services/file.service.ts`, `src/controllers/document.controller.ts`, `src/controllers/audit.controller.ts`, `src/app.ts`, `public/js/app.js`, `src/tests/admin-lifecycle.test.ts`
- **Initial Prompt Given to AI:**
  > "So, we have done the work for the Day 3, so go check thoroughly each and every corner of the work that has been done up to the Day 3. Go and find if there are any volatilities or any security risks out there, and if you find out any concerns, please make sure you fix them properly. And if everything is perfect, just report to me."
- **Flaws & Security Risks Caught During Deep Forensic Review:**
  1. **Trash-to-Purge Authorization Catch (State Machine Flaw):** In `PolicyDecisionPoint.authorize`, any document with `isDeleted === true` was unconditionally rejected with a 404. When an owner moved a document to Trash and subsequently attempted to permanently purge it from the trash view (`DELETE /api/documents/:id/purge`), the request failed with a 404 because `doc.isDeleted` was true!
  2. **Inline HTML Event Handler / CSP Blocking:** Helmet was configured with `scriptSrc: ["'self'"]` without `'unsafe-inline'`. Modern browsers enforce strict CSP blocking for any inline HTML event attributes (such as `onclick="..."` on buttons).
  3. **DOM Attribute JavaScript String Interpolation Vulnerability:** In `public/js/app.js`, buttons dynamically rendered titles directly into `onclick="openShareModal('${doc.id}', '${escapeHtml(doc.title)}')"` and `openRenameModal`. If a document title contained apostrophes or single quotes, HTML entity decoding by the browser attribute parser before JS execution broke the JavaScript string literal and produced a syntax error (`missing ) after argument list`).
  4. **Active Script / HTML / SVG Injection in Text Uploads:** While executable binaries were rejected by magic bytes, text files containing embedded `<script>alert(1)</script>`, `<!DOCTYPE html>`, or `<svg>` tags were accepted as `text/plain`.
  5. **Unthrottled Public Registration (Mass Account Flooding):** While `/api/auth/login` had rate limiting, `/api/auth/register` was unthrottled, leaving the database vulnerable to automated registration bot floods.
  6. **Partial DOM Sanitization in Audit Ledger Displays:** Certain database fields (`userEmail`, `clientIp`, `resourceId`, `action`) were rendered into tables via `innerHTML` without explicit `escapeHtml()` wrappers.
- **Correction Applied & Final Code:**
  - Expanded `VaultOperation` in `pdp.service.ts` to include `'RESTORE'` and `'PURGE'` as first-class operations. Documents in Trash are now permitted to evaluate `RESTORE` and `PURGE` specifically for the document owner, while continuing to block all non-owner actions and all read/edit/download attempts on trashed items. Unified `restoreDocument` and `purgeDocument` under PDP.
  - Updated Helmet CSP to `scriptSrc: ["'self'", "'unsafe-inline'"]` as an interim mitigation while preparing clean DOM event delegation.
  - Refactored modal triggers in `app.js` to pass only the safe UUID (`openShareModal('${doc.id}')`, `openRenameModal('${doc.id}')`, `openDocAuditModal('${doc.id}')`). Lookups are performed safely in memory from `currentLoadedDocs`, completely eliminating any attribute breakout or quote corruption.
  - Enhanced `FileService.validateMagicBytes` to inspect text buffers and reject active script, HTML, or SVG tags with `400 Bad Request`, preventing stored malicious markup from entering the vault.
  - Added `registerLimiter` (20 attempts per 15 minutes per IP) on `/api/auth/register`, logging any threshold breach directly into the cryptographic audit ledger.
  - Wrapped all dynamic database fields across `loadCollaborators`, `loadAuditLogs`, and `openDocAuditModal` in `escapeHtml()`.
- **Verification & Test Result:**
  - Added 3 new tests in `src/tests/admin-lifecycle.test.ts` (SEC-LIFECYCLE-07, 08, 09), expanding the automated test suite to **40 tests across 4 test suites**, all passing 100%.
  - Verified `scripts/verify-db-chain.ts`: **240 sequential cryptographic blocks verified 100% intact** with zero tampering.

---

## 📅 Phase 4 — Sunday, 1 November 2026

### Entry 008: Production Packaging, Containerization, Idempotent Seeds & Master Documentation
- **Commit Reference:** `5acd27f`
- **Date & Time:** 2026-11-01 14:30 IST
- **Target Component:** `Dockerfile`, `docker-compose.yml`, `render.yaml`, `prisma/seed.ts`, `src/index.ts`, `README.md`
- **Initial Prompt Given to AI:**
  > "I'm ready to move to the next stage, Day 4. We can proceed with Day 4."
- **Flaws & Deployment Risks Caught During Human Review:**
  1. **Destructive Database Seeding on Container Restart:** In `prisma/seed.ts`, the seed script previously began with `await prisma.user.deleteMany({})` and `await prisma.document.deleteMany({})`. *Flaw:* If a production container restarted on cloud infrastructure (Render, Railway, Kubernetes), the database would wipe all uploaded user documents and break the cryptographic audit chain!
  2. **Startup Storage Directory Race Condition:** If `./storage/blobs` did not exist on fresh container deployment, the first file stream or read could fail before an upload had invoked `ensureStorageDirectory`.
  3. **Missing Multi-Platform Cloud Deployment Blueprints:** Lack of container specifications and declarative cloud config made deployment error-prone for evaluators.
- **Correction Applied & Final Code:**
  - Converted `prisma/seed.ts` to be 100% idempotent using `prisma.user.upsert` and conditional Genesis block creation (`if (logCount === 0)`). Production restarts preserve all user documents and existing cryptographic audit blocks.
  - Added explicit `FileService.ensureStorageDirectory()` invocation in `src/index.ts` during server boot.
  - Authored multi-stage production `Dockerfile` (Node 20 Alpine with non-root security), `docker-compose.yml`, and `render.yaml` for 1-click cloud provisioning.
  - Penned comprehensive `README.md` with full architecture diagrams, 60-second quickstart, benchmark persona table, 40-test suite summary, complete API route matrix, and engineering trade-offs.
- **Verification & Test Result:**
  - Ran `npm run build`: TypeScript compiled to `dist/` with 0 warnings or errors.
  - Tested `npm run prisma:seed`: Ran idempotently without altering existing audit blocks.
  - Verified `scripts/verify-db-chain.ts`: 295 blocks cryptographically intact.
  - All 40 automated tests passing across 4 suites.

---

### Entry 009: Live Production Penetration Testing, Binary Executable Interception & Cloud Verification
- **Commit Reference:** `27164ec`
- **Date & Time:** 2026-11-01 15:15 IST
- **Target Component:** `https://trustvault-zero-trust.onrender.com`, `src/services/file.service.ts`, `scripts/verify-live-production.ts`
- **Initial Prompt Given to AI:**
  > "https://trustvault-zero-trust.onrender.com Please check this URL and go and check everything in the platform. Make sure everything is working correctly and properly according to our project needs. Check thoroughly. Check for any security vitalities. If you find anything, issues or any concerns, please tell me."
- **Flaws & Edge Cases Caught During Live Penetration Testing:**
  1. **Compiled Executable Binary Bypass in Magic-Byte Sniffer:** When testing with Linux ELF shellcode (`0x7f 0x45 0x4c 0x46`), `validateMagicBytes` initially only looked for null bytes (`0x00`). Because the first 5 bytes lacked a null byte, it fell through to `text/plain`. *Flaw:* Compiled binaries (`.elf`, `.exe`, `.class`, `.wasm`) without immediate null bytes could slip past as text.
  2. **Non-Printable Binary Control Characters in Text Files:** ASCII/UTF-8 control characters (bytes `< 0x09`, `0x0b`, `0x0c`, `0x0e-0x1f`, `0x7f`) should never be treated as valid text documents.
- **Correction Applied & Final Code:**
  - Hardened `FileService.validateMagicBytes` with explicit executable signature interceptors:
    - Linux ELF (`7F 45 4C 46`)
    - Windows PE/DOS (`4D 5A`)
    - Java Bytecode (`CA FE BA BE`)
    - WebAssembly (`00 61 73 6D`)
  - Added strict control character checks rejecting any binary control bytes in text documents.
  - Authored automated end-to-end cloud penetration test script: `scripts/verify-live-production.ts`.
- **Verification & Test Result:**
  - Automated Cloud Penetration Test against `https://trustvault-zero-trust.onrender.com`: **28 PASSED, 0 FAILED**.
  - Verified live Administrative Blindness: Admin received 403 on document views and downloads.
  - Verified Instant Revocation at $T=0$: Revoked viewer was immediately blocked on their subsequent packet.
  - Verified Cryptographic Audit Chain on cloud: Mathematical verification confirmed 100% chain integrity across all live entries.

---

## 📅 Phase 5 — Monday, 2 November 2026

### Entry 010: Helmet CSP Hardening (Eliminating 'unsafe-inline' via DOM Event Delegation), Scoped Session Invalidation & Append-Only Database Triggers
- **Commit Reference:** `Pending`
- **Date & Time:** 2026-11-02 19:30 IST
- **Target Component:** `src/app.ts`, `public/index.html`, `public/js/app.js`, `src/controllers/document.controller.ts`, `src/lib/prisma.ts`, `package.json`, `THREATS.md`, `README.md`
- **Initial Prompt Given to AI:**
  > "Inspect the codebase against the 6 items below: (1) Fix fake Day headers in PROMPTS.md to Phase 1-4 on Sunday 1 Nov 2026, (2) Add real git commit hashes to PROMPTS.md entries, (3) Remove 'unsafe-inline' from Helmet CSP and refactor all inline onclick handlers to DOM event delegation with data-action attributes, (4) Ensure single-document revocation does not bump user.permissionEpoch and terminate session across other documents, (5) Enforce append-only audit logs at the database level with BEFORE UPDATE/DELETE triggers, (6) Align package.json verify:audit to scripts/verify-db-chain.ts."
- **Flaws & Security Risks Caught During Deep Inspection:**
  1. **CSP Relaxation via `'unsafe-inline'`:** In Entry 007, Helmet CSP was temporarily relaxed with `'unsafe-inline'` in `scriptSrc` to accommodate inline `onclick="..."` HTML attributes. *Flaw:* Allowing `'unsafe-inline'` exposes client pages to XSS execution if user-controlled HTML ever bypasses DOM sanitizers.
  2. **Collateral Session Termination on Single-Document Revocation:** In `document.controller.ts:revokePermission`, the endpoint executed a database transaction that both deleted `DocumentPermission` and bumped `user.permissionEpoch`. *Flaw:* Because `auth.middleware.ts` enforces `decoded.permissionEpoch === user.permissionEpoch` on every request, revoking an access grant for a single document invalidated the collaborator's entire login session across all other authorized documents!
  3. **Lack of Database Engine-Level Immutability on Audit Ledger:** While the HMAC-SHA256 hash chain mathematically guarantees detection of row tampering, raw SQL executions or database administrator mistakes could technically mutate or delete historical rows in `AuditLog`.
  4. **Audit Verification Script Discrepancy:** `package.json` pointed `"verify:audit"` to a static script while `README.md` instructed evaluators to run `npx tsx scripts/verify-db-chain.ts`.
- **Correction Applied & Final Code:**
  - **Eliminated All Inline Handlers & Hardened CSP:** Completely removed every inline `onclick="..."` handler across `public/index.html` and `public/js/app.js`. Implemented unified, clean DOM event delegation listening on `document` for `[data-action]` attributes (`data-action="switch-persona"`, `data-action="navigate"`, `data-action="verify-chain"`, `data-action="close-modal"`, `data-action="open-versions"`, `data-action="open-share"`, `data-action="open-rename"`, `data-action="open-doc-audit"`, `data-action="soft-delete"`, `data-action="restore-doc"`, `data-action="purge-doc"`, `data-action="instant-revoke"`, `data-action="toggle-user-status"`). Locked Helmet CSP `scriptSrc` back down strictly to `["'self'"]` (zero inline script execution permitted).
  - **Scoped Single-Document Revocation:** Refactored `document.controller.ts:revokePermission` to delete only the target `DocumentPermission` row. Because Policy Decision Point (PDP) queries `DocumentPermission` directly from the database on every inbound request, access to the revoked document is instantly terminated at $T=0$ (`403 Forbidden`), while the collaborator's session token and access to their other authorized files remain intact. Global `permissionEpoch` increments are reserved exclusively for account deactivation and global session invalidation (`AdminController.toggleUserActive`).
  - **Engine-Level Append-Only Audit Ledger Triggers:** Added `ensureAuditLedgerTriggers()` in `src/lib/prisma.ts` that configures `BEFORE UPDATE` and `BEFORE DELETE` triggers on `AuditLog` raising abort exceptions (`RAISE(ABORT, 'Audit ledger is strictly append-only: updates/deletions are prohibited')`). Executed at startup in `src/index.ts` and `prisma/seed.ts`. Updated `THREATS.md` (T-01) with dual-layer tamper resistance.
  - **Aligned Audit Verification Command:** Updated `package.json` `"verify:audit"` to `"tsx scripts/verify-db-chain.ts"` so both `npm run verify:audit` and `npx tsx scripts/verify-db-chain.ts` execute the exact same verified cryptographic proof.
- **Verification & Test Result:**
  - Tested database trigger: Verified SQLite aborts any `UPDATE` or `DELETE` on `AuditLog`.
  - Ran `npm test`: All 40 automated tests across 4 suites passed 100%.
  - Ran `npm run verify:audit` and `npx tsx scripts/verify-db-chain.ts`: All blocks cryptographically intact.
