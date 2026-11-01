# TrustVault — Comprehensive STRIDE Threat Model (THREATS.md)

This threat model outlines trust boundaries, threat actors, attack vectors, and concrete technical mitigations implemented across TrustVault in alignment with the Snovasys Fresher Hiring Challenge 2026 rubric.

---

## 🎯 System Overview & Trust Boundaries

```
[ External / Unauthenticated Attacker ] 
                    │
                    ▼  (Perimeter: TLS 1.3, Rate Limit, Helmet CSP)
[ Authenticated Client (Browser / API) ]
                    │
                    ▼  (Boundary 1: Strict PEP / Session Verification)
[ Policy Decision Point (PDP Engine) ]
                    │
                    ▼  (Boundary 2: Isolated Data Plane & Hash Chain)
[ SQLite/Postgres DB ]  <──>  [ Isolated File Blob Store ]  <──>  [ Chained Audit Ledger ]
```

---

## 🛡️ STRIDE Threat Matrix & Mitigations

### 1. Spoofing (Identity & Session Forgery)
| ID | Threat Description | Severity | Concrete Mitigation Implemented in Code |
| :--- | :--- | :---: | :--- |
| **S-01** | Attacker uses stolen or expired session tokens | High | HTTP-only, `SameSite=Strict`, Secure cookies with database-validated session status and short TTL. |
| **S-02** | Attacker forges client IP via spoofed `X-Forwarded-For` | Medium | IP resolution only trusts configured reverse-proxy boundaries; invalid values are rejected. |
| **S-03** | Attacker attempts credential stuffing/brute force on login | High | Argon2/bcrypt password hashing with per-user salt + progressive IP rate limiting. |

### 2. Tampering (Unauthorized Modification)
| ID | Threat Description | Severity | Concrete Mitigation Implemented in Code |
| :--- | :--- | :---: | :--- |
| **T-01** | Rogue DB user modifies or deletes historical audit rows | Critical | **Cryptographic Hash Chain:** Every audit row includes `HMAC_SHA256(secret, prevHash + payload)`. `scripts/audit_chain_verifier.js` detects any modified or deleted row. |
| **T-02** | Malicious file disguised as PDF (MIME-type spoofing) | High | **Binary Magic-Byte Inspection:** The server validates the raw header bytes (`%PDF-`, PNG, JPEG) before saving. Files with mismatched headers are rejected with HTTP 400. |
| **T-03** | Path Traversal during file upload (e.g. `../../etc/passwd`) | Critical | Uploaded files are stored on disk under **randomized UUID v4 keys** detached from the original filename. Original names are stored only as sanitized metadata. |
| **T-04** | Stored XSS via uploaded HTML/SVG or malicious scripts in text files | High | **Active Script Sanitization:** `FileService.validateMagicBytes` actively parses text buffers and rejects `<script>`, `<html>`, `<!DOCTYPE>`, `<?php>`, and `<svg>` payloads with HTTP 400. |

### 3. Repudiation (Denial of Action)
| ID | Threat Description | Severity | Concrete Mitigation Implemented in Code |
| :--- | :--- | :---: | :--- |
| **R-01** | User downloads confidential file and denies having accessed it | High | Every download emits an immutable chained audit log entry with timestamp, user ID, IP, document ID, and cryptographic signature. |
| **R-02** | Attacker probes unauthorized document IDs and denies malicious activity | Medium | **Logging of Refused Attempts:** Failed/unauthorized requests (HTTP 401/403/404) are explicitly recorded in the audit trail with outcome `DENIED`. |

### 4. Information Disclosure (Data Leakage)
| ID | Threat Description | Severity | Concrete Mitigation Implemented in Code |
| :--- | :--- | :---: | :--- |
| **I-01** | Insecure Direct Object Reference (IDOR) via document UUIDs | Critical | Every document endpoint routes through the central Policy Decision Point (`authorizeDocumentAccess`). Unshared IDs return 404/403 with no metadata disclosure. |
| **I-02** | System Administrator reads confidential company files | High | **Administrative Blindness:** Admin role can manage users and inspect system audits, but has zero read/download rights to documents unless explicitly granted by the owner. |
| **I-03** | Search queries leak unauthorized file titles or categories | High | Database search queries inject strict tenant & permission filters directly into the SQL `WHERE` clause. |

### 5. Denial of Service (Availability Disruption)
| ID | Threat Description | Severity | Concrete Mitigation Implemented in Code |
| :--- | :--- | :---: | :--- |
| **D-01** | Attacker uploads multi-gigabyte files to exhaust disk space | High | Strict 5 MB file size limit enforced at the streaming middleware layer before files hit disk. |
| **D-02** | Rapid automated requests saturate database connections | Medium | Route-level rate limiting using in-memory token bucket. |
| **D-03** | Automated registration bots flood user database | High | Route-level rate limiting on `/api/auth/register` (max 20 requests per 15 min per IP) with audit logging on breach. |

### 6. Elevation of Privilege (Privilege Escalation)
| ID | Threat Description | Severity | Concrete Mitigation Implemented in Code |
| :--- | :--- | :---: | :--- |
| **E-01** | Viewer attempts to edit or upload a new version | High | Policy Decision Point enforces that only `OWNER` or `EDIT` permissions can submit updates. Viewers receive HTTP 403. |
| **E-02** | Editor attempts to delete document or alter permissions | High | Structural operations (deletion, permission grant/revoke) are strictly restricted to the Document Owner. |
| **E-03** | Revoked user continues accessing file via cached permissions | Critical | **Instant Revocation:** Permission checks perform live database queries. Revoking a user invalidates access immediately on their next packet. |

---

## ⚖️ Documented Accepted Risks & Rationale

1. **In-Memory Rate Limiting:** Single-instance rate limiting is used for local and single-container deployment. For horizontal multi-instance scaling, a shared Redis store would be introduced.
2. **Local Storage in Development:** Files reside in `./storage/blobs` during local testing. For cloud production, files are moved to encrypted cloud object storage (e.g., Supabase / S3) with server-side AES-256 encryption.
