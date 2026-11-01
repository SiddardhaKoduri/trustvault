# TrustVault — AI Collaboration & Technical Oversight Ledger (PROMPTS.md)

This document is maintained chronologically throughout the Snovasys Fresher Hiring Challenge 2026. It records the prompts issued to AI assistants, the raw output received, the critical security and architectural flaws caught during human review, the corrections applied, and the test verifications performed.

---

## 📅 Day 1 — Sunday, 1 November 2026

### Entry 001: Architecture & Threat Model Inception
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

*(Entries continue chronologically as each milestone is built)*


### Entry 002: Zero-Trust Auth Implementation, Benchmark Seed & Chained Audit Verification
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
