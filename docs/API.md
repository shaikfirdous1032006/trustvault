# TrustVault — REST API Reference & Authorization Boundary Specification

Every endpoint in TrustVault strictly enforces the **default-deny** security principle. Application-level authorization operates in tandem with PostgreSQL Row Level Security (RLS) as defense in depth. Identity and roles are **never** trusted from client parameters; they are derived exclusively from the verified Supabase session token.

---

## Summary of Endpoints

| Method | Endpoint | Required Role | Required Doc Permission | Audit Event Emitted |
|---|---|---|---|---|
| `POST` | `/api/auth/login` | Public (Unauthenticated) | None | `login` (allowed) or `login_failure` (denied) |
| `POST` | `/api/auth/register` | Public (Unauthenticated) | None | `admin_action` (`account_registration`, role assigned) |
| `POST` | `/api/auth/logout` | Authenticated | None | `logout` (allowed) |
| `GET` | `/api/auth/me` | Authenticated | None | None |
| `GET` | `/api/documents` | Authenticated | RLS-scoped filter | `search` (allowed, if `?search=` present) |
| `POST` | `/api/documents` | `owner` only | None (Owner of new doc) | `upload` (allowed/denied) |
| `GET` | `/api/documents/:id` | Authenticated | `read` (or Owner) | `preview` (allowed/denied) |
| `PATCH` | `/api/documents/:id` | Authenticated | `edit` (or Owner) | `update` (allowed/denied) |
| `DELETE` | `/api/documents/:id` | Authenticated | Owner Only | `delete` (allowed/denied) |
| `POST` | `/api/documents/:id/versions` | Authenticated | `edit` (or Owner) | `version_upload` (allowed/denied) |
| `GET` | `/api/documents/:id/versions` | Authenticated | `read` (or Owner) | `preview` (resource: versions) |
| `GET` | `/api/documents/:id/download` | Authenticated | `read` (or Owner) | `download` (allowed/denied) |
| `GET` | `/api/documents/:id/permissions` | Authenticated | Owner or `admin` | None |
| `POST` | `/api/documents/:id/permissions` | Authenticated | Owner Only | `permission_grant` (allowed/denied) |
| `DELETE` | `/api/documents/:id/permissions/:permissionId` | Authenticated | Owner Only | `permission_revoke` (allowed/denied) |
| `GET` | `/api/documents/:id/audit` | Authenticated | Owner or `admin` | None |
| `GET` | `/api/admin/audit` | `admin` | None | Filterable by `?action=auth` for Login/Logout history |
| `POST` | `/api/admin/audit/verify` | `admin` | None | `admin_action` (allowed/denied) |
| `GET` | `/api/admin/users` | `admin` | None | None |

---

## Detailed Endpoint Specifications

### 1. `POST /api/auth/login`
- **Description:** Authenticates user credentials via Supabase Auth and establishes HTTP-only secure cookie session.
- **Required Role:** Public / Any.
- **Required Document Permission:** None.
- **Validation Rules:**
  - `email`: valid email format (RFC 5322), non-empty.
  - `password`: string, minimum 6 characters.
- **Possible Error Responses:**
  - `400 Bad Request`: `{"success": false, "error": "Invalid email or password format"}`
  - `401 Unauthorized`: `{"success": false, "error": "Invalid credentials"}`
  - `500 Internal Server Error`: `{"success": false, "error": "Internal server error"}`
- **Audit Events Emitted:**
  - On failure: `action="login_failure"`, `result="denied"`, `actor_email=<email>`, `ip_hash`, `user_agent_hash`.
  - On success: `action="login"`, `result="allowed"`, `actor_id=<uid>`, `actor_email=<email>`.

---

### 2. `POST /api/auth/logout`
- **Description:** Terminates current session, invalidates authentication cookies.
- **Required Role:** Authenticated.
- **Required Document Permission:** None.
- **Validation Rules:** Valid authenticated session.
- **Possible Error Responses:**
  - `500 Internal Server Error`: `{"success": false, "error": "Internal server error"}`
- **Audit Events Emitted:**
  - `action="logout"`, `result="allowed"`, `actor_id=<uid>`, `actor_email=<email>`.

---

### 3. `GET /api/documents`
- **Description:** Lists documents accessible to the caller. Automatically scoped by PostgreSQL RLS.
- **Required Role:** Any authenticated user (`admin`, `owner`, `viewer`).
- **Required Document Permission:** Explicit active permission or document ownership.
- **Query Parameters:**
  - `search` (optional): substring search against title and description.
  - `category` (optional): filter by category (`general`, `legal`, `financial`, `technical`, `hr`, etc.).
  - `page` (optional, default: 1): integer >= 1.
  - `pageSize` (optional, default: 20, max: 100): integer.
- **Possible Error Responses:**
  - `401 Unauthorized`: Authentication missing.
  - `403 Forbidden`: Account deactivated.
  - `500 Internal Server Error`: Query execution error.
- **Audit Events Emitted:**
  - When `search` is provided: `action="search"`, `result="allowed"`, details include query string and result count.

---

### 4. `POST /api/documents`
- **Description:** Uploads a document file and metadata. Computes SHA-256 content checksum and stores file in private storage bucket.
- **Required Role:** `owner` or `admin`. Viewers are rejected.
- **Required Document Permission:** None (caller becomes document owner).
- **Validation Rules (Multipart Form Data):**
  - `title`: string, 1–255 characters.
  - `description`: optional string, max 1000 characters.
  - `category`: string, 1–50 characters.
  - `file`: binary file required, max size 52,428,800 bytes (50MB), MIME type must match allowlist.
- **Possible Error Responses:**
  - `401 Unauthorized`: Not authenticated.
  - `403 Forbidden`: `{"success": false, "error": "Only owners can upload documents"}`
  - `400 Bad Request`: Missing file, metadata validation failure, file size > 50MB, or disallowed MIME type.
  - `500 Internal Server Error`: Storage upload or database insertion failure.
- **Audit Events Emitted:**
  - Denied: `action="upload"`, `result="denied"`, details: reason.
  - Allowed: `action="upload"`, `result="allowed"`, details include file name, size, checksum, and category.

---

### 5. `GET /api/documents/:id`
- **Description:** Retrieves document metadata and details.
- **Required Role:** Any authenticated user.
- **Required Document Permission:** `read` or `edit` permission (or Owner). **Admins cannot read documents without explicit permission.**
- **Possible Error Responses:**
  - `401 Unauthorized`: Not authenticated.
  - `403 Forbidden`: `{"success": false, "error": "Access denied"}`
  - `404 Not Found`: `{"success": false, "error": "Document not found"}`
  - `500 Internal Server Error`: Database error.
- **Audit Events Emitted:**
  - Denied: `action="preview"`, `result="denied"`, details: `{ reason: "..." }`.
  - Allowed: `action="preview"`, `result="allowed"`.

---

### 6. `PATCH /api/documents/:id`
- **Description:** Updates document metadata (title, description, category).
- **Required Role:** Any authenticated user with edit rights.
- **Required Document Permission:** `edit` permission or Owner.
- **Validation Rules (JSON):**
  - `title`: optional string, 1–255 characters.
  - `description`: optional string, max 1000 characters.
  - `category`: optional string, 1–50 characters.
- **Possible Error Responses:**
  - `401 Unauthorized`: Not authenticated.
  - `403 Forbidden`: `{"success": false, "error": "Access denied"}`
  - `400 Bad Request`: Invalid JSON payload.
  - `500 Internal Server Error`: Database update error.
- **Audit Events Emitted:**
  - Denied: `action="update"`, `result="denied"`.
  - Allowed: `action="update"`, `result="allowed"`, details: `{ changes: {...} }`.

---

### 7. `DELETE /api/documents/:id`
- **Description:** Soft-deletes a document. Sets `is_deleted = true`, `deleted_at = now()`, `deleted_by = session.user.id`.
- **Required Role:** Any authenticated user who owns the document.
- **Required Document Permission:** Document Owner only.
- **Possible Error Responses:**
  - `401 Unauthorized`: Not authenticated.
  - `403 Forbidden`: `{"success": false, "error": "Only the document owner can delete"}`
  - `500 Internal Server Error`: Update error.
- **Audit Events Emitted:**
  - Denied: `action="delete"`, `result="denied"`.
  - Allowed: `action="delete"`, `result="allowed"`.

---

### 8. `POST /api/documents/:id/versions`
- **Description:** Uploads a new version of an existing document. Increments version counter, stores checksum.
- **Required Role:** Any authenticated user with edit rights.
- **Required Document Permission:** `edit` permission or Owner.
- **Validation Rules:**
  - `file`: binary file required, max size 50MB.
  - `change_notes`: optional string.
- **Possible Error Responses:**
  - `401 Unauthorized`: Not authenticated.
  - `403 Forbidden`: `{"success": false, "error": "Access denied"}`
  - `400 Bad Request`: Missing file or size limit exceeded.
  - `404 Not Found`: Document not found.
  - `500 Internal Server Error`: Storage or version insert error.
- **Audit Events Emitted:**
  - Denied: `action="version_upload"`, `result="denied"`.
  - Allowed: `action="version_upload"`, `result="allowed"`, details include version number, file name, and checksum.

---

### 9. `GET /api/documents/:id/versions`
- **Description:** Lists all historical versions of a document with checksums and uploader details.
- **Required Role:** Any authenticated user.
- **Required Document Permission:** `read` or `edit` permission (or Owner).
- **Possible Error Responses:**
  - `401 Unauthorized`: Not authenticated.
  - `403 Forbidden`: `{"success": false, "error": "Access denied"}`
  - `500 Internal Server Error`: Database query error.
- **Audit Events Emitted:**
  - Denied: `action="preview"`, `result="denied"`, details: `{ resource: "versions" }`.

---

### 10. `GET /api/documents/:id/download`
- **Description:** Generates a short-lived (300-second TTL) signed storage URL for secure file download.
- **Required Role:** Any authenticated user.
- **Required Document Permission:** `read` or `edit` permission (or Owner). **Admins cannot download without explicit grant.**
- **Enforcement:** Fresh server-side permission check on every single invocation. No caching.
- **Possible Error Responses:**
  - `401 Unauthorized`: Not authenticated.
  - `403 Forbidden`: `{"success": false, "error": "Access denied"}`
  - `404 Not Found`: Document not found.
  - `500 Internal Server Error`: Storage signing error.
- **Audit Events Emitted:**
  - Denied: `action="download"`, `result="denied"`.
  - Allowed: `action="download"`, `result="allowed"`, details: `{ file_name: "..." }`.

---

### 11. `GET /api/documents/:id/permissions`
- **Description:** Lists current active and revoked permissions for a document.
- **Required Role:** Document Owner or platform `admin`.
- **Required Document Permission:** Document Owner or `admin` role.
- **Possible Error Responses:**
  - `401 Unauthorized`: Not authenticated.
  - `403 Forbidden`: `{"success": false, "error": "Only the document owner can view permissions"}`
  - `500 Internal Server Error`: Database error.
- **Audit Events Emitted:** None (read-only metadata).

---

### 12. `POST /api/documents/:id/permissions`
- **Description:** Grants explicit `read` or `edit` access to a named user by email. Supports optional expiration timestamp.
- **Required Role:** Document Owner only.
- **Required Document Permission:** Document Owner only.
- **Validation Rules (JSON):**
  - `user_email`: valid email string. Cannot be the caller's own email.
  - `permission_level`: must be exactly `'read'` or `'edit'`.
  - `expires_at`: optional ISO 8601 UTC timestamp.
- **Possible Error Responses:**
  - `401 Unauthorized`: Not authenticated.
  - `403 Forbidden`: `{"success": false, "error": "Only the document owner can grant permissions"}`
  - `400 Bad Request`: Invalid payload or attempting to grant permission to oneself.
  - `404 Not Found`: Target user email does not exist in system.
  - `409 Conflict`: Active permission already exists for target user.
  - `500 Internal Server Error`: Insert failure.
- **Audit Events Emitted:**
  - Denied: `action="permission_grant"`, `result="denied"`.
  - Allowed: `action="permission_grant"`, `result="allowed"`, details include target email and permission level.

---

### 13. `DELETE /api/documents/:id/permissions/:permissionId`
- **Description:** Immediately revokes a permission grant by setting `revoked_at = now()`. Takes effect immediately across all routes and RLS.
- **Required Role:** Document Owner only.
- **Required Document Permission:** Document Owner only.
- **Possible Error Responses:**
  - `401 Unauthorized`: Not authenticated.
  - `403 Forbidden`: `{"success": false, "error": "Only the document owner can revoke permissions"}`
  - `404 Not Found`: Permission record not found.
  - `500 Internal Server Error`: Update failure.
- **Audit Events Emitted:**
  - Denied: `action="permission_revoke"`, `result="denied"`.
  - Allowed: `action="permission_revoke"`, `result="allowed"`, details include target user email and revoked level.

---

### 14. `GET /api/documents/:id/audit`
- **Description:** Returns the complete tamper-evident audit history for a specific document.
- **Required Role:** Document Owner or platform `admin`.
- **Required Document Permission:** Document Owner or `admin` role.
- **Query Parameters:** `page`, `pageSize` (max 100).
- **Possible Error Responses:**
  - `401 Unauthorized`: Not authenticated.
  - `403 Forbidden`: `{"success": false, "error": "Only the document owner or admin can view the audit trail"}`
  - `500 Internal Server Error`: Query error.
- **Audit Events Emitted:** None.

---

### 15. `GET /api/admin/audit`
- **Description:** Returns platform-wide audit log events with cryptographic hash-chain metadata.
- **Required Role:** `admin` only.
- **Required Document Permission:** None.
- **Query Parameters:** `page`, `pageSize`, `action`, `result`, `startDate`, `endDate`.
- **Possible Error Responses:**
  - `401 Unauthorized`: Not authenticated.
  - `403 Forbidden`: `{"success": false, "error": "Insufficient role. Required: admin"}`
  - `500 Internal Server Error`: Query error.
- **Audit Events Emitted:** None.

---

### 16. `GET /api/admin/users`
- **Description:** Lists all registered platform users, roles, and active statuses.
- **Required Role:** `admin` only.
- **Required Document Permission:** None.
- **Possible Error Responses:**
  - `401 Unauthorized`: Not authenticated.
  - `403 Forbidden`: `{"success": false, "error": "Insufficient role. Required: admin"}`
  - `500 Internal Server Error`: Query error.
- **Audit Events Emitted:** None.

