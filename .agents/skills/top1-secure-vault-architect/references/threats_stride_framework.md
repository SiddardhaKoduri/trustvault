# STRIDE Threat Model Reference (THREATS.md Blueprint)

This document provides the canonical STRIDE threat modeling blueprint required for `THREATS.md` to earn full marks in the Snovasys evaluation.

---

## 🛡️ STRIDE Threat Matrix for TrustVault

### 1. Spoofing (Identity Deception)
* **Threat S-01:** Attacker steals or replays an expired authentication token.
  * *Mitigation:* Cryptographically signed HTTP-only, SameSite=Strict cookies; database session invalidation; token expiration within short TTL.
* **Threat S-02:** Attacker spoofs client IP in audit logs using arbitrary `X-Forwarded-For` headers.
  * *Mitigation:* Extract client IP only from verified reverse proxy headers (e.g., trusted proxies only) and sanitize values before logging.

### 2. Tampering (Data Integrity Violation)
* **Threat T-01:** Database administrator or compromised server process modifies historical audit log entries to conceal unauthorized downloads.
  * *Mitigation:* Tamper-evident cryptographic hash chain (`entryHash = HMAC_SHA256(secret, prevHash + eventPayload)`). Verification script immediately identifies altered rows.
* **Threat T-02:** Attacker uploads malicious script disguised as a `.pdf` or image (MIME-confusion attack).
  * *Mitigation:* Strict binary magic-number byte signature verification before committing file to storage; stripping executable bits; serving files with `Content-Disposition: attachment; filename="..."` and `X-Content-Type-Options: nosniff`.
* **Threat T-03:** Path Traversal via malicious filename in upload (e.g. `../../etc/shadow`).
  * *Mitigation:* Absolute decoupling: files are saved with randomized UUID v4 names on disk/blob store. The original sanitized filename is kept only as metadata in the database.

### 3. Repudiation (Denial of Action)
* **Threat R-01:** User downloads confidential document and claims they never accessed it.
  * *Mitigation:* Every download event produces an un-deletable audit record containing user ID, timestamp, document version, IP, and cryptographic hash chain link.
* **Threat R-02:** User attempts to brute-force document IDs and denies malicious intent.
  * *Mitigation:* All failed/unauthorized (`401`/`403`/`404`) requests are logged under `UNAUTHORIZED_ACCESS_ATTEMPT` with full request context.

### 4. Information Disclosure (Unauthorized Data Leakage)
* **Threat I-01:** Insecure Direct Object Reference (IDOR) via predictable document IDs.
  * *Mitigation:* UUID v4 keys + mandatory centralized PDP authorization verification on every route.
* **Threat I-02:** Search endpoint leaks existence or metadata of unshared documents.
  * *Mitigation:* Database queries for search inject tenant/access filters at the SQL level (`WHERE ownerId = currentUserId OR id IN (SELECT documentId FROM permissions WHERE userId = currentUserId)`).
* **Threat I-03:** Information leakage via error stack traces in production.
  * *Mitigation:* Centralized error handler masks internal exceptions and returns generic user-facing JSON errors with correlation IDs.

### 5. Denial of Service (Availability Destruction)
* **Threat D-01:** Attacker floods server with gigantic file uploads to exhaust storage or RAM.
  * *Mitigation:* Strict payload limits (5 MB cap) enforced via streaming parser before buffering full file into memory.
* **Threat D-02:** Unauthenticated attacker floods login/upload endpoints to exhaust DB connections.
  * *Mitigation:* Rate limiting (token bucket / sliding window per IP).

### 6. Elevation of Privilege (Privilege Escalation)
* **Threat E-01:** Document Viewer sends crafted PUT request to edit document content.
  * *Mitigation:* Server PDP validates that user has `EDIT` or `OWNER` permission.
* **Threat E-02:** Document Editor attempts to add other collaborators or delete document.
  * *Mitigation:* Server PEP strictly restricts permission manipulation and deletion endpoints to Document Owners only.
* **Threat E-03:** System Administrator accesses confidential document contents.
  * *Mitigation:* Application-level PDP blocks admin access to document read/download unless explicit permission record exists.

---

## ⚖️ Documented Accepted Risks & Rationale

* **Local Disk Storage in Development:** In local dev mode, files reside on filesystem. Rationale: In production deployment, files are backed by cloud blob storage (S3/Supabase/Vercel Blob) with at-rest server-side encryption (AES-256).
* **Single Master Key for HMAC Audit Chain:** Audit chain secret is stored in server environment variable (`AUDIT_SECRET`). Rationale: Sufficient for application tier security; in enterprise tier, this secret would be anchored to AWS KMS or Google Cloud HSM.
