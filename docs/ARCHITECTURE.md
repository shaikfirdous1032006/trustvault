# TrustVault — Architecture & Security Engineering Specification

TrustVault is a secure document-sharing platform engineered to satisfy stringent zero-trust requirements. This document outlines the core architectural pillars, authorization mechanisms, audit immutability guarantees, and deliberate design exclusions.

---

## 1. Dual-Layer Authorization & Permission Model

TrustVault enforces a **dual-layer defense-in-depth** authorization architecture. Application-level checks protect the entry points, while PostgreSQL Row Level Security (RLS) acts as the immutable final boundary.

```
                              ┌───────────────────────────────────┐
                              │     Client Request (HTTP/REST)     │
                              └─────────────────┬─────────────────┘
                                                │
                                                ▼
                              ┌───────────────────────────────────┐
                              │  Layer 1: Application-Level Auth  │
                              │  - Session token verification     │
                              │  - Zod payload validation         │
                              │  - requireAuth() / requireRole()  │
                              │  - checkDocumentPermission()      │
                              │  - Denial logged to audit trail   │
                              └─────────────────┬─────────────────┘
                                                │ (Pass)
                                                ▼
                              ┌───────────────────────────────────┐
                              │  Layer 2: PostgreSQL RLS Boundary │
                              │  - auth.uid() bound session       │
                              │  - Default-deny on all tables     │
                              │  - SELECT / INSERT / UPDATE / DEL │
                              │  - No implicit admin document read│
                              └─────────────────┬─────────────────┘
                                                │ (Pass)
                                                ▼
                              ┌───────────────────────────────────┐
                              │   Data / Storage Access Allowed   │
                              │   Short-lived Signed URL (300s)   │
                              └───────────────────────────────────┘
```

### Roles and Capability Matrix

| Role | User Administration | Platform Audit View | Upload Documents | Manage Permissions | Read / Download Documents |
|---|---|---|---|---|---|
| **Admin** (`admin@example.com`) | Yes (Full) | Yes (Platform metadata) | Yes | Only on owned docs | **Only with explicit grant** |
| **Owner** (`owner@example.com`) | No | Only on owned docs | Yes | Yes (on owned docs) | Full on owned docs + grants |
| **Viewer** (`viewer@example.com`) | No | No | No | No | **Only with explicit grant** |

### Principle of Default Deny
- No user can access, read, download, update, delete, or search a document unless an active explicit permission grant exists in `document_permissions` or the caller is the registered `owner_id`.
- Admins possess platform management privileges (viewing user registries and audit metadata) but **do not inherit implicit document read privileges**. If an admin requires access to a sensitive document, the document owner must explicitly grant them permission.

---

## 2. Real-Time Revocation Model (Zero Authorization Caching)

In distributed document sharing, stale permissions are a primary source of data breaches. TrustVault guarantees that revocation takes effect immediately across all system layers.

### Key Tenets:
1. **Zero Authorization Caching:**
   - Authorization decisions are never cached in Redis, memory, or JWT claims.
   - Every read, download, version access, or update queries the database directly with a fresh permission evaluation.
2. **Fresh Verification on Every Request:**
   - Evaluates:
     ```sql
     revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())
     ```
   - If an owner revokes access at $T_0$, the very next request at $T_0 + 1\text{ms}$ evaluates `revoked_at` as non-null and is immediately denied with HTTP 403.
3. **Short-Lived Signed URLs for Storage:**
   - Files are stored in a private bucket (`public = false`).
   - Signed download URLs are issued with a 300-second (5-minute) Time-To-Live (TTL).
   - Direct storage links are never stored or exposed; a signed URL is only generated after passing an on-demand permission check.

---

## 3. Tamper-Evident Audit Trail & Cryptographic Hash Chaining

The `audit_events` table maintains an append-only, cryptographically linked record of every sensitive operation, both allowed and denied.

### Database-Enforced Immutability
Application roles (`authenticated`, `anon`) are strictly denied `UPDATE`, `DELETE`, and `TRUNCATE` privileges on `audit_events`. To defend against compromised service keys or SQL injection:
- `BEFORE UPDATE` trigger raises an exception: `"Audit events are immutable."`
- `BEFORE DELETE` trigger raises an exception: `"Audit events are immutable."`
- `BEFORE TRUNCATE` trigger raises an exception: `"Audit events table cannot be truncated."`

### Cryptographic Hash Chaining (SHA-256)
Each audit event stores two cryptographic hashes:
1. `prev_hash`: The SHA-256 hash of the immediately preceding event ($H_{i-1}$).
2. `event_hash`: The SHA-256 hash of the current event ($H_i$), computed over canonical data:

$$\text{canonical} = \text{occurred\_at} \parallel \text{actor\_id} \parallel \text{document\_id} \parallel \text{action} \parallel \text{result} \parallel \text{details\_json} \parallel \text{prev\_hash}$$

$$H_i = \text{SHA-256}(\text{canonical})$$

If any row is modified, deleted, or inserted out of order, the chain of hashes is broken. The `verifyAuditChain()` utility traverses the log and detects any discrepancies.

### Privacy-Preserving Forensics
Client IP addresses and `User-Agent` strings are hashed using SHA-256 before insertion (`ip_hash`, `user_agent_hash`), allowing anomaly detection and rate-limit tracking without storing plaintext PII.

---

## 4. Deliberate Architectural Exclusions

To maximize security and eliminate attack vectors, the following architectural shortcuts were intentionally rejected:

1. **No Permanent Public URLs:**
   - Files are never hosted in a public bucket or served via permanent CDN links.
   - Rationale: Permanent URLs can be leaked, scraped, or retained long after a user's access has been revoked.
2. **No Client-Supplied Identity or Authorization:**
   - The API rejects client-supplied `user_id`, `role`, `owner_id`, or `granted_by` values.
   - Rationale: Prevents Insecure Direct Object Reference (IDOR) and role spoofing vulnerabilities.
3. **No Automatic Admin Document Access:**
   - Admins cannot browse or download document files without an explicit grant from the owner.
   - Rationale: Protects confidential documents against internal administrative compromise.
4. **No UI-Only Hiding:**
   - Hiding buttons in the frontend is treated purely as UX, never as security. Every API route independently verifies permissions.
5. **No AI Autonomous Permission Widening:**
   - AI permission suggestions are advisory only and require explicit manual confirmation by the document owner. Suggestions and grants are audited as distinct events.
