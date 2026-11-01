# Cryptographic Audit Chain (Tamper-Evident Ledger)

This specification defines the cryptographic hashing and verification protocol for the TrustVault audit log.

---

## 🔒 Architecture Overview

A traditional database audit log is vulnerable to:
1. SQL injection or rogue DB administrators modifying historical access logs.
2. Silent deletion of unauthorized access attempts to hide breach evidence.

TrustVault implements a **Cryptographic Hash Chain** (analogous to a blockchain blockheader or Merkle chain) where every log entry contains:
- `entryHash`: The SHA-256 HMAC of the current entry payload salted with the previous row's `entryHash`.
- `previousHash`: The `entryHash` of the immediately preceding record in the sequence.
- Genesis Hash: `0000000000000000000000000000000000000000000000000000000000000000` (for entry #1).

---

## 🧮 Hashing Formula

For any event record $k$:

$$\text{Payload} = \text{ISO_Timestamp} \parallel \text{UserId} \parallel \text{Action} \parallel \text{ResourceType} \parallel \text{ResourceId} \parallel \text{Outcome} \parallel \text{ClientIP}$$

$$\text{EntryHash}_k = \text{HMAC-SHA256}(\text{ServerSecret}, \text{PreviousHash}_{k-1} \parallel \text{Payload})$$

If an attacker modifies even a single character in the `Action`, `Outcome`, or `Timestamp` of record $k$, recomputing the hash at record $k+1$ produces a hash mismatch, mathematically proving tampering.

---

## 📝 Required Log Fields

Every audit entry must record:
1. `id`: Serial sequence or UUID v4.
2. `timestamp`: ISO-8601 UTC timestamp (`YYYY-MM-DDTHH:mm:ss.sssZ`).
3. `userId`: ID of actor (or `"ANONYMOUS"`).
4. `userEmail`: Email of actor at the time of action.
5. `action`: Standardized verb (`AUTH_LOGIN`, `AUTH_LOGOUT`, `DOC_UPLOAD`, `DOC_VIEW`, `DOC_DOWNLOAD`, `DOC_UPDATE`, `DOC_VERSION_UPLOAD`, `DOC_DELETE`, `DOC_RESTORE`, `PERM_GRANT`, `PERM_REVOKE`, `UNAUTHORIZED_ACCESS_ATTEMPT`).
6. `resourceType`: `DOCUMENT`, `USER`, `SYSTEM`.
7. `resourceId`: UUID of target resource.
8. `outcome`: `SUCCESS` or `DENIED`.
9. `reason`: Human/machine readable diagnostic (e.g., `READ_SUCCESS`, `INSUFFICIENT_PERMISSIONS`, `FILE_SIGNATURE_MISMATCH`).
10. `clientIp`: Remote IPv4/IPv6 address.
11. `userAgent`: Client user-agent string.
12. `previousHash`: Hash of record $k-1$.
13. `entryHash`: Computed hash of this record.

---

## 🔍 Chain Verification Algorithm

```typescript
import crypto from 'crypto';

export function verifyAuditChain(records: AuditLogEntry[], secret: string): VerificationReport {
  let prevHash = "0000000000000000000000000000000000000000000000000000000000000000";

  for (let i = 0; i < records.length; i++) {
    const entry = records[i];

    // Check link integrity
    if (entry.previousHash !== prevHash) {
      return {
        valid: false,
        brokenAtId: entry.id,
        reason: `Previous hash pointer mismatch at row ${entry.id}`
      };
    }

    // Recompute current hash
    const payload = `${entry.timestamp}|${entry.userId}|${entry.action}|${entry.resourceType}|${entry.resourceId}|${entry.outcome}|${entry.clientIp}`;
    const expectedHash = crypto
      .createHmac('sha256', secret)
      .update(entry.previousHash + payload)
      .digest('hex');

    if (entry.entryHash !== expectedHash) {
      return {
        valid: false,
        brokenAtId: entry.id,
        reason: `Cryptographic signature mismatch at row ${entry.id}. Data has been modified!`
      };
    }

    prevHash = entry.entryHash;
  }

  return { valid: true, totalVerified: records.length };
}
```
