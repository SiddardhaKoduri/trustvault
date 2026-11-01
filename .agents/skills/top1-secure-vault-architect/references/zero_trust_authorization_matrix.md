# Zero-Trust Authorization Matrix & Decision Protocol

This specification defines the granular Role-Based & Attribute-Based Access Control (RBAC/ABAC) matrix for TrustVault.

---

## 👥 Persona & Role Definitions

1. **System Administrator (`ADMIN`):**
   - Can manage user accounts (create, activate, deactivate, reset).
   - Can inspect system health and query the tamper-evident audit ledger.
   - **SECURITY INVARIANT:** The Administrator **CANNOT** read, download, or edit documents unless explicitly granted access by the Document Owner. Having root/admin database privileges does not grant application-level document read rights.

2. **Document Owner (`OWNER`):**
   - Has full control over documents they upload.
   - Can view, download, update metadata, upload new versions, soft-delete, and permanently purge their documents.
   - Can grant and revoke granular permissions (`READ` or `EDIT`) to specific named users.
   - Can inspect the document-specific audit trail.

3. **Document Editor (`EDIT` permission):**
   - Can view document details, download all version artifacts, and upload new versions.
   - **SECURITY INVARIANT:** An Editor **CANNOT** delete the document, alter the document owner, or share/revoke permissions with other users.

4. **Document Viewer (`READ` permission):**
   - Can view document details and download allowed versions.
   - **SECURITY INVARIANT:** A Viewer **CANNOT** edit, rename, upload new versions, delete, or share the document.

5. **Unauthorized User / Anonymous:**
   - Any request for a non-shared document must return `404 Not Found` (or `403 Forbidden` if authenticated but unauthorized, ensuring no resource enumeration leaks).
   - Automatically generates a `DENIED` entry in the cryptographic audit log.

---

## 📊 Comprehensive Matrix

| Action / Operation | Anonymous | Unshared User | Viewer (`READ`) | Editor (`EDIT`) | Document Owner | System Admin |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Authenticate / Sign In** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **List Own / Shared Docs** | ❌ (401) | ✅ (Empty) | ✅ (Shared only)| ✅ (Shared only)| ✅ (All Owned) | ✅ (Empty unless shared) |
| **Search Documents** | ❌ (401) | ❌ (No results) | ✅ (Filtered) | ✅ (Filtered) | ✅ (Filtered) | ❌ (No results) |
| **View Doc Metadata** | ❌ (401) | ❌ (404/403) | ✅ | ✅ | ✅ | ❌ (404/403) |
| **Download Current File** | ❌ (401) | ❌ (404/403) | ✅ | ✅ | ✅ | ❌ (404/403) |
| **Download Old Versions** | ❌ (401) | ❌ (404/403) | ✅ | ✅ | ✅ | ❌ (404/403) |
| **Upload New Version** | ❌ (401) | ❌ (403) | ❌ (403) | ✅ | ✅ | ❌ (403) |
| **Rename / Edit Metadata**| ❌ (401) | ❌ (403) | ❌ (403) | ✅ | ✅ | ❌ (403) |
| **Grant Access to User** | ❌ (401) | ❌ (403) | ❌ (403) | ❌ (403) | ✅ | ❌ (403) |
| **Revoke Access from User**| ❌ (401) | ❌ (403) | ❌ (403) | ❌ (403) | ✅ | ❌ (403) |
| **Soft Delete to Trash** | ❌ (401) | ❌ (403) | ❌ (403) | ❌ (403) | ✅ | ❌ (403) |
| **Restore from Trash** | ❌ (401) | ❌ (403) | ❌ (403) | ❌ (403) | ✅ | ❌ (403) |
| **Purge Permanently** | ❌ (401) | ❌ (403) | ❌ (403) | ❌ (403) | ✅ | ❌ (403) |
| **View Audit Trail (System)**| ❌ (401)| ❌ (403) | ❌ (403) | ❌ (403) | ❌ (403) | ✅ |
| **View Audit Trail (Doc)** | ❌ (401)| ❌ (403) | ❌ (403) | ❌ (403) | ✅ | ✅ |
| **Manage User Accounts** | ❌ (401) | ❌ (403) | ❌ (403) | ❌ (403) | ❌ (403) | ✅ |

---

## ⚡ Instantaneous Revocation Mechanics

To achieve zero-millisecond revocation without latency:
1. **Database Session Validation:** Every API call hitting a protected route reads the user's `isActive` flag and `permissionEpoch`.
2. **Permission Check at PEP:** Whenever a file download or document query occurs, the permission record is queried with a direct index lookup: `db.permission.findUnique({ documentId, userId })`.
3. When the owner clicks "Revoke", the record is removed immediately in a transaction. The very next packet from the revoked user receives `403 Forbidden`.
