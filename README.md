# TrustVault — Secure Document Sharing with a Real Tamper-Evident Audit Trail

> **Build a document platform where the wrong person can never read the file, and you can prove who read it.**
> 
> 🌐 **Live Deployed Application:** [https://trustvault-smoky.vercel.app](https://trustvault-smoky.vercel.app)  
> 📦 **Public Repository:** [https://github.com/shaikfirdous1032006/trustvault](https://github.com/shaikfirdous1032006/trustvault)  
> 🧪 **Automated Test Coverage:** 271 tests passing across 19 test suites (`npm test`)  
> 🎬 **Video Demonstration Walkthrough:** [docs/DEMO_SCRIPT.md](file:///docs/DEMO_SCRIPT.md) *(Recordings can be viewed following this 5-minute walkthrough)*

---

## 🔑 Demo Accounts & Credentials

The live deployment comes pre-seeded with all three core roles:

| Role | Email | Password | Access Scope |
|------|-------|----------|--------------|
| **Admin** | `admin@example.com` | `TrustVault2024!` | Platform security monitoring, Real-time Login/Logout history, Threat alerts, Policy simulator, SHA-256 audit chain verification & HMAC-signed report export |
| **Document Owner** | `owner@example.com` | `TrustVault2024!` | Exclusive permission to upload documents, manage versions, grant/revoke per-document read/edit access, AI Privacy Shield redactions |
| **Viewer** | `viewer@example.com` | `TrustVault2024!` | Strictly read-only access to documents explicitly shared with them. Cannot upload, modify, or view unauthorized assets |

> **Self-Service Registration with Role Selection:** New users can register at `/login` and select their desired role (**Owner** or **Viewer**). Registered credentials and roles are securely persisted in MongoDB Atlas or Supabase PostgreSQL.

---

## 📋 The 10 Core Competition Requirements

| # | Requirement | Implementation in TrustVault | Verification / Test |
|---|-------------|------------------------------|---------------------|
| **1** | **Authentication with at least 3 roles** (admin, document owner, viewer) | Implemented in `src/lib/session.ts` and `src/app/api/auth/`. Enforces role-based boundaries on server. Supports public registration with role selection. | `tests/session.test.ts`, `tests/user-role-features.test.ts` |
| **2** | **Upload, organise, search and manage documents** | Stored in private bucket with server-generated UUID keys. SHA-256 checksum, MIME validation, categorized in financial, legal, technical, etc. | `tests/competition-a-to-t.test.ts` (Req G–J) |
| **3** | **Permissions per document (read & edit) to named people** | `document_permissions` table assigns granular `read` or `edit` rights to specific user IDs with optional time-bound expiration (`expires_at`). | `tests/api-authorization.test.ts` |
| **4** | **Owners can grant access and take it back** | Document owners grant access via `POST /api/documents/:id/permissions` and revoke immediately via `DELETE /api/documents/:id/permissions/:permissionId`. | `tests/competition-a-to-t.test.ts` (Req E, F) |
| **5** | **Unpermitted users cannot read, download, change or delete** | Zero-trust default-deny on all routes. Downloads reject unpermitted users with `403 Forbidden` and never issue signed storage URLs. | `tests/api-authorization.test.ts` (59 tests) |
| **6** | **Audit trail of uploads, downloads, changes, deletions & grants** | Every operation emits an append-only audit event. Uses a cryptographic SHA-256 hash chain (`event_hash = SHA256(canonical_fields \| prev_hash)`). | `tests/standalone-audit-chain.test.ts`, `tests/audit.test.ts` |
| **7** | **Search by name, owner, category, and date** | Multi-attribute search supported in `GET /api/documents?search=...&owner=...&category=...&dateFrom=...&dateTo=...`. Every search is audited. | `tests/competition-a-to-t.test.ts` (Req K, L) |
| **8** | **Validation of what is uploaded** | Strict server-side magic-byte sniffing (PDF, docx, xlsx, pptx, images, text, csv) and 50MB file size limits in `src/lib/permission.ts`. Executables and disguised files rejected. | `tests/competition-a-to-t.test.ts` (Req H, I) |
| **9** | **Administrative view of document activity & permissions** | Admin dashboard (`/dashboard/admin/audit`) with live Real-Time Login/Logout activity, IST timestamping (`Asia/Kolkata`), multi-filter search, and chain verification. | `tests/admin-login-logout-activity.test.ts`, `tests/user-role-features.test.ts` |
| **10** | **Automated tests showing one user cannot reach another's documents** | 271 automated security tests testing IDOR, direct storage URL manipulation, revoked permissions, cross-origin CSRF, and role boundaries. | `tests/api-authorization.test.ts`, `tests/competition-a-to-t.test.ts` |

---

## 🛡️ The Three Non-Negotiable Standards

### 1. The Server Decides Every Time (Zero UI Reliance)
* UI hiding is treated purely as a convenience, never as security. Every API endpoint (`GET`, `POST`, `PATCH`, `DELETE`) re-evaluates the authenticated user's session against the exact document grant before touching disk or database.
* Even if an attacker uses `curl` or Postman with a forged document ID, the server checks `evaluateDocumentPermission()` or PostgreSQL RLS and returns `403 Forbidden`.

### 2. Proof After the Fact (Cryptographic Hash-Chained Audit Trail)
* Audit records are append-only. Each audit record hashes its canonical fields together with the previous block's SHA-256 hash:
  $$\text{event\_hash} = \text{SHA256}(\text{occurred\_at} \mid \text{actor\_id} \mid \text{document\_id} \mid \text{action} \mid \text{result} \mid \text{details\_json} \mid \text{prev\_hash})$$
* **Tamper Evident:** If an attacker modifies an old audit log row in storage, the hash chain breaks from that block onwards. Administrators can click **Verify Hash Chain** or run `POST /api/admin/audit/verify` to detect the exact corrupted block.
* Refused attempts are logged as `result: "denied"`, providing an indisputable forensic trail of intrusion attempts.

### 3. Taking Access Away Works Immediately
* No caching of authorization decisions. Every document read or download evaluates the database `revoked_at` column in real time.
* The moment an owner revokes a grant, `revoked_at` is stamped. Any subsequent request—even 10 milliseconds later—is denied.
* Files are stored under opaque UUID storage paths in private storage. Downloads use short-lived signed URLs with a 5-minute TTL issued only after authorization passes.

---

## 🏗️ Architecture & Write-Up

### Permission Model in Our Own Words
TrustVault implements a **Zero-Trust, Per-Document Capability Model** with Defense in Depth:
1. **Ownership Boundary:** The user who uploads a document is its permanent owner. Only owners can upload documents, delete documents, and grant or revoke access.
2. **Explicit Grants:** Non-owners have **zero access by default**. Access requires an explicit grant in `document_permissions` (`read` or `edit`).
3. **Time-Bound Grants:** Grants can specify an optional `expires_at` timestamp. Expired grants are treated as invalid immediately.
4. **Administrative Oversight:** Admins have audit and compliance visibility, but do **not** automatically bypass private document read permissions, preventing rogue administrator data exfiltration.

### What We Built Beyond the Floor
1. **AI Privacy Shield (`/dashboard/privacy`):** Detects SSNs, credit cards (with Luhn validation), API keys, and passwords. Allows owners to review and generate separate redacted documents without altering the originals.
2. **Explainable Threat Detection Engine (`/dashboard/admin/alerts`):** Real-time pattern detection for repeated denied accesses (IDOR probing), brute-force login attempts, and mass download bursts with automated actor throttling.
3. **Policy Simulator (`/dashboard/admin/simulator`):** What-If simulation engine allowing administrators to project access consequences before modifying policies.
4. **Exportable Signed Checkpoint Reports (`/api/admin/audit/export`):** Generates HMAC-SHA256 signed audit reports for external auditors.

### What We Deliberately Chose Not to Build (And Why)
* **No Folder-Level Inheritance:** Folder hierarchies introduce subtle permission leaks (e.g. adding a user to a parent folder inadvertently grants access to all nested confidential files). TrustVault intentionally mandates explicit per-document permissions.
* **No Public Share Links Without Token Hashes:** We avoided guessable URLs. Any external sharing requires cryptographically random 256-bit tokens whose raw values are never stored in plaintext (stored only as SHA-256 hashes).

---

## 💻 Running the Project Locally

### 1. Clone & Install Dependencies
```bash
git clone https://github.com/shaikfirdous1032006/trustvault.git
cd trustvault
npm install
```

### 2. Run Automated Security Tests
```bash
npm test
```
*Executes all 271 tests across the 19 security and integration test suites in seconds.*

### 3. Start the Local Server
```bash
npm run dev
```
Open **[http://localhost:3000](http://localhost:3000)** in your browser.

---

## 🗄️ Production Database Configuration

TrustVault supports dual enterprise database configurations:

### Option A: MongoDB Atlas (Document & Credential Store)
1. In your [MongoDB Atlas Dashboard](https://cloud.mongodb.com):
   - Navigate to **Security -> Network Access**.
   - Click **Add IP Address** and select **Allow Access from Anywhere** (`0.0.0.0/0`) so that cloud serverless environments (e.g. Vercel) can establish TLS connections without TLS Alert 80.
2. In your Vercel project environment variables:
   - `MONGODB_URI`: `mongodb+srv://<username>:<password>@cluster0.xxx.mongodb.net/trustvault?retryWrites=true&w=majority`
   - `MONGODB_DB`: `trustvault`

### Option B: Supabase PostgreSQL (Row-Level Security & Realtime)
1. Run the versioned SQL migrations in the Supabase SQL Editor:
   - `supabase/migrations/001_initial_schema.sql` (Creates users, documents, permissions, versions, audit_events)
   - `supabase/migrations/002_share_links.sql` (External share tokens and access limits)
   - `supabase/migrations/003_audit_realtime_and_security.sql` (Enables Supabase Realtime publication on `audit_events` and RLS trigger)
2. In your Vercel environment variables:
   - `NEXT_PUBLIC_SUPABASE_URL`: `https://<your-project-id>.supabase.co`
   - `NEXT_PUBLIC_SUPABASE_ANON_KEY`: `<anon-key>`
   - `SUPABASE_SERVICE_ROLE_KEY`: `<service-role-key>` (Server-side only)

---

## 📑 Required Competition Deliverables Index

* 🛡️ **[THREATS.md](file:///THREATS.md):** 30 threat scenarios (STRIDE methodology), mitigations, residual risks, accepted risks, and automated test cross-references.
* 🤖 **[PROMPTS.md](file:///PROMPTS.md):** Detailed log of AI interactions across the development cycle, including catching AI errors in RLS policies, audit immutability, and storage boundaries.
* 📖 **[docs/API.md](file:///docs/API.md):** Complete REST API specification with role and permission matrices.
* 🏛️ **[docs/ARCHITECTURE.md](file:///docs/ARCHITECTURE.md):** Technical design guide and security boundaries.
* 🎬 **[docs/DEMO_SCRIPT.md](file:///docs/DEMO_SCRIPT.md):** 5-minute video demonstration walkthrough script.
* 📊 **[docs/EVALUATION_REPORT.md](file:///docs/EVALUATION_REPORT.md):** Threat detection and AI Privacy Shield benchmarks (100% precision/recall).
