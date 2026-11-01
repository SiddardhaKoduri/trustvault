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
