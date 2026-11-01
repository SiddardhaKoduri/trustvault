# AI Oversight Ledger Guidelines (PROMPTS.md Blueprint)

This document establishes the structure and rules for maintaining `PROMPTS.md` throughout the hiring challenge to secure the full 15 marks in the AI Usage category.

---

## 🎯 What Evaluators Look For

The Snovasys evaluation criteria state:
> *"The evaluation is about how well you direct the tool, catch its errors, and thoroughly understand your submitted code. Heavy AI usage without proof of catching/correcting mistakes will negatively impact scoring."*

Therefore, a winning `PROMPTS.md` must not merely be a copy-paste of prompts. It must demonstrate **Active Technical Oversight, Architectural Leadership, and Insecurity Interception**.

---

## 📋 Ledger Entry Template

Every entry in `PROMPTS.md` must follow this 6-part schema:

```markdown
### Entry [ID]: [Feature or Milestone Description]
- **Date & Time:** YYYY-MM-DD HH:MM IST
- **Target Component:** e.g., `src/middleware/auth.ts`, `src/services/pdp.ts`
- **Initial Prompt Given to AI:**
  > "[Exact prompt text]"
- **AI Initial Output / Recommendation:**
  Brief summary of what the AI generated.
- **Flaws / Vulnerabilities Caught During Human Review:**
  Detailed explanation of the security flaw, architectural limitation, or hallucination in the AI output.
  *(Examples: AI checked permissions only in the UI; AI gave Admins blanket read permissions; AI relied on filename extension instead of magic bytes; AI omitted 403 denied logging in audit trail).*
- **Correction Applied & Final Code:**
  How the developer directed the AI or refactored the code to enforce top-tier zero-trust invariants.
- **Verification & Test Result:**
  Specific automated test run and output verifying the fix.
```

---

## 🏆 High-Scoring Examples of Caught AI Mistakes

1. **The "Admin Can Do Anything" Trap:**
   - *AI Mistake:* AI writes `if (user.role === 'ADMIN' || doc.ownerId === user.id) return next()`.
   - *Caught by Human:* Violation of Non-Negotiable Law 2 (Zero-Knowledge Admin). Admins should never have automatic read access to private confidential documents.
   - *Correction:* Removed `user.role === 'ADMIN'` bypass. Admin can only view metadata and audit logs, not document contents.

2. **The "Stateless JWT Revocation Delay" Trap:**
   - *AI Mistake:* AI generates a 24-hour signed JWT containing user roles and document permissions.
   - *Caught by Human:* Revocation is not instantaneous! If an owner revokes access, the JWT remains valid until expiration.
   - *Correction:* Converted to database-backed session token verification or introduced an indexed `permissionEpoch` checked on every request.

3. **The "MIME-Type Header Trust" Trap:**
   - *AI Mistake:* AI validates file type with `file.mimetype === 'application/pdf'`.
   - *Caught by Human:* Any attacker can send an executable `.exe` file with a fake `Content-Type: application/pdf` header.
   - *Correction:* Implemented binary magic-byte inspection (reading buffer header bytes `0x25, 0x50, 0x44, 0x46`) before processing.

4. **The "Silent Rejection" Trap:**
   - *AI Mistake:* AI handles unauthorized requests with `return res.status(403).json({ error: 'Forbidden' })` without logging.
   - *Caught by Human:* Violates the verifiable audit trail requirement: refused/unauthorized attempts MUST be captured in the audit ledger.
   - *Correction:* Injected audit logger call capturing the denied event with attacker IP, targeted resource, and timestamp.
