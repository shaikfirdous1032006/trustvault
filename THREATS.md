# TrustVault — Threat Model

## Methodology

Each threat follows the format: **Threat → Mitigation → Residual Risk → Accepted Risk**.

---

## 1. Unauthorized Document Access (Horizontal Privilege Escalation)

**Threat:** A viewer manipulates request parameters (document ID, user ID) to access documents they have no permission for.

**Mitigation:** PostgreSQL RLS enforces default-deny on every table. The `permitted_select_documents` policy requires an active, non-revoked, non-expired row in `document_permissions`. Application-level `checkDocumentPermission()` provides defense in depth.

**Residual Risk:** If RLS policies are misconfigured during a schema migration, a window of exposure exists.

**Accepted Risk:** Low — RLS is tested in CI; schema changes require review.

---

## 2. Vertical Privilege Escalation (Role Spoofing)

**Threat:** A viewer forges their role as `admin` or `owner` in API requests to gain elevated access.

**Mitigation:** Identity and role are derived from `auth.uid()` → `public.users.role` on the server. Client-supplied role fields are never trusted. `requireAuth()` and `requireRole()` verify session-derived identity.

**Residual Risk:** A compromised Supabase service role key could bypass RLS.

**Accepted Risk:** Service role key is server-side only, never exposed to client.

---

## 3. Stale Permission (Revocation Bypass)

**Threat:** A user whose access was revoked continues accessing the document because the system caches authorization.

**Mitigation:** No authorization caching. Every request checks `revoked_at IS NULL` and `expires_at IS NULL OR expires_at > now()` in both RLS policies and application code. Revocation sets `revoked_at` to the current timestamp immediately.

**Residual Risk:** Network latency could allow a request in-flight at revocation time to succeed.

**Accepted Risk:** Sub-second window; acceptable for this application class.

---

## 4. Expired Permission Still Grants Access

**Threat:** A time-limited permission continues working after its `expires_at` timestamp.

**Mitigation:** RLS policies and `checkDocumentPermission()` both compare `expires_at > now()`. Database `now()` is authoritative (not client time).

**Residual Risk:** Clock skew on Supabase servers (unlikely, managed infrastructure).

**Accepted Risk:** Negligible.

---

## 5. Direct Storage Bucket Access

**Threat:** An attacker constructs a direct URL to the Supabase Storage bucket, bypassing the application.

**Mitigation:** The `documents` bucket is private (`public = false`). Storage RLS policies restrict uploads to the user's own folder and downloads to users with matching `has_document_permission()`. Signed URLs expire after 5 minutes.

**Residual Risk:** If a signed URL is intercepted in transit, it remains valid for up to 5 minutes.

**Accepted Risk:** Short TTL limits exposure; HTTPS prevents casual interception.

---

## 6. Audit Trail Tampering

**Threat:** An attacker or compromised admin deletes or modifies audit records to cover their tracks.

**Mitigation:** Database triggers (`prevent_audit_update`, `prevent_audit_delete`, `prevent_audit_truncate`) block all mutations. `REVOKE UPDATE, DELETE` on `audit_events` for `authenticated` and `anon` roles. SHA-256 hash chain allows tamper detection.

**Residual Risk:** A superuser with direct PostgreSQL access could disable triggers and modify data.

**Accepted Risk:** Supabase manages the database; direct superuser access requires Supabase support intervention.

---

## 7. Hash Chain Integrity Violation

**Threat:** An attacker modifies an audit event's content without updating the hash, breaking the chain.

**Mitigation:** `verifyAuditChain()` recomputes hashes and detects mismatches. Each event stores `prev_hash` linking to the previous event's `event_hash`.

**Residual Risk:** If an attacker can recompute all hashes from the tampered event forward, the chain appears valid.

**Accepted Risk:** This requires modifying all subsequent events, which triggers block.

---

## 8. Service Role Key Compromise

**Threat:** The `SUPABASE_SERVICE_ROLE_KEY` is leaked, granting full database access bypassing RLS.

**Mitigation:** Key is stored only in server-side environment variables. Never exposed to client code. `.env.local` is in `.gitignore`. Audit triggers still block mutation of audit records even with service role.

**Residual Risk:** If the Vercel environment is compromised, the key is exposed.

**Accepted Risk:** Standard cloud deployment risk; rotate keys if compromise is suspected.

---

## 9. SQL Injection

**Threat:** Malicious input in search queries, titles, or descriptions executes arbitrary SQL.

**Mitigation:** Supabase client library uses parameterized queries. User input is never interpolated into SQL strings. Zod validation on API inputs sanitizes data before database operations.

**Residual Risk:** Minimal with parameterized queries.

**Accepted Risk:** Negligible.

---

## 10. Cross-Site Scripting (XSS)

**Threat:** Malicious content in document titles, descriptions, or user names is rendered as executable script.

**Mitigation:** React's JSX auto-escapes all dynamic content by default. No use of `dangerouslySetInnerHTML`. Content-Security-Policy headers recommended for production.

**Residual Risk:** If a developer adds `dangerouslySetInnerHTML` in the future.

**Accepted Risk:** Low — code review process should catch this.

---

## 11. Cross-Site Request Forgery (CSRF)

**Threat:** An attacker tricks an authenticated user into making unintended API requests.

**Mitigation:** Supabase Auth uses HTTP-only cookies with `SameSite=Lax`. State-changing operations require POST/PATCH/DELETE (not GET). The middleware refreshes and validates sessions.

**Residual Risk:** `SameSite=Lax` allows top-level navigation GET requests.

**Accepted Risk:** No state-changing GET endpoints exist.

---

## 12. Brute Force Login

**Threat:** An attacker tries many password combinations against demo or real accounts.

**Mitigation:** Supabase Auth includes built-in rate limiting. Failed login attempts are audited with `login_failure` events. IP hashes in audit trail enable forensic analysis.

**Residual Risk:** Distributed brute force from many IPs may evade per-IP rate limits.

**Accepted Risk:** Demo accounts use strong passwords; production should enforce MFA.

---

## 13. Session Hijacking

**Threat:** An attacker steals session tokens to impersonate a user.

**Mitigation:** Supabase Auth tokens are stored in HTTP-only cookies. `Secure` flag ensures HTTPS-only transmission. Short token expiry with refresh rotation.

**Residual Risk:** XSS could potentially access cookies if `httpOnly` is misconfigured.

**Accepted Risk:** Supabase SSR library handles cookie security.

---

## 14. Insecure Direct Object Reference (IDOR)

**Threat:** A user guesses or enumerates document/permission UUIDs to access unauthorized resources.

**Mitigation:** UUIDs are unguessable (v4). Every access checks RLS + application-level permission. Knowing a UUID alone grants zero access.

**Residual Risk:** If UUID generation is predictable (not the case with uuid_generate_v4).

**Accepted Risk:** Negligible.

---

## 15. Mass Assignment / Parameter Injection

**Threat:** An attacker sends extra fields in API requests (e.g., `owner_id`, `role`, `is_active`) to modify unauthorized data.

**Mitigation:** Zod schemas validate and strip unknown fields. `owner_id` is derived from session. Role changes go through admin-only endpoints.

**Residual Risk:** A new endpoint that forgets Zod validation.

**Accepted Risk:** Code review and tests catch this.

---

## 16. Information Disclosure in Error Messages

**Threat:** Verbose error messages reveal database schema, file paths, or internal implementation.

**Mitigation:** API routes return generic error messages (`"Access denied"`, `"Internal server error"`). Detailed errors logged to server console only.

**Residual Risk:** A new endpoint might accidentally return detailed errors.

**Accepted Risk:** Low — consistent error handling pattern across all routes.

---

## 17. File Upload Malware / Oversized Files

**Threat:** An attacker uploads malicious files (viruses, oversized files, path traversal filenames).

**Mitigation:** File type validation against allowlist (`ALLOWED_TYPES`). 50MB size limit enforced at application and storage bucket level. Storage paths are constructed server-side — client filenames are not used as paths.

**Residual Risk:** Allowed file types (PDF, DOCX) can contain macros/exploits.

**Accepted Risk:** File scanning is out of scope; users download at their own risk.

---

## 18. Admin Implicit Document Read Access

**Threat:** An administrator attempts to browse, preview, read, or download document contents without an explicit permission grant from the owner.

**Mitigation:** PostgreSQL RLS and server-side route handlers enforce strict admin isolation. Admins do NOT have an implicit SELECT policy on `documents` or storage download access. Both RLS and `checkDocumentPermission()` require explicit owner grants. Admin privileges are strictly restricted to user management and audit log inspection.

**Residual Risk:** Admins can view audit event metadata (action types, timestamps, actor emails), but cannot read document contents or download files.

**Accepted Risk:** Low — platform security monitoring requires audit visibility; sensitive file payloads and contents remain protected.

---

## 19. Denial of Service via API Abuse

**Threat:** An attacker sends excessive requests to exhaust database connections or storage.

**Mitigation:** Vercel and Supabase both include request rate limiting. Pagination limits (`pageSize` capped at 100). File upload size limit (50MB).

**Residual Risk:** A determined attacker with many IPs could still cause degradation.

**Accepted Risk:** Standard cloud infrastructure handles this; enhanced DDoS protection available if needed.

---

## 20. Race Condition in Permission Check and Revocation

**Threat:** A request passes the permission check, then the permission is revoked before the operation completes (TOCTOU).

**Mitigation:** RLS checks at the database level happen at query execution time. Storage signed URLs have 5-minute TTL limiting the window.

**Residual Risk:** A signed URL issued just before revocation remains valid for up to 5 minutes.

**Accepted Risk:** 5-minute window is acceptable; shorter TTL available if needed.

---

## 21. Privilege Escalation via Auth Trigger Manipulation

**Threat:** A user creates an account with metadata containing `role: "admin"` to gain admin access.

**Mitigation:** The `handle_new_user()` trigger reads `raw_user_meta_data->>'role'`, but user registration is disabled — only the seed script (service role) creates users. In production, user creation should only be via admin invitation.

**Residual Risk:** If self-registration is enabled without stripping the role from metadata.

**Accepted Risk:** Self-registration is not enabled in the current configuration.

---

## 22. Audit Log Denial of Service

**Threat:** An attacker triggers thousands of denied-access attempts to flood the audit log and make forensic analysis difficult.

**Mitigation:** Audit events are indexed by `actor_id`, `occurred_at`, `action`, and `result` for efficient querying and filtering.

**Residual Risk:** Storage growth from excessive audit events.

**Accepted Risk:** Standard database maintenance (archival) can address long-term growth.

---

## 23. Environment Variable Exposure

**Threat:** Secrets (service role key, session secrets) are accidentally committed to the repository or leaked in client bundles.

**Mitigation:** `.env.local` and `.env` in `.gitignore`. Only `NEXT_PUBLIC_*` variables are sent to the client. `SUPABASE_SERVICE_ROLE_KEY` and `SESSION_SECRET` have no `NEXT_PUBLIC_` prefix.

**Residual Risk:** A developer might rename the variable with `NEXT_PUBLIC_` prefix.

**Accepted Risk:** Code review and pre-commit scans catch this.

---

## 24. Privileged Database Superuser Chain Rewrite (Honest Immutability Analysis & External Anchoring)

**Threat:** An attacker who gains PostgreSQL superuser (`postgres` or cloud DB root) privileges could temporarily disable row triggers (`ALTER TABLE audit_events DISABLE TRIGGER ALL;`), recalculate the SHA-256 hashes starting from any historical event, rewrite the chain forward to the present, and re-enable triggers. A local hash chain alone cannot prevent this inside the same database boundary.

**Honest Assessment:** The audit log cannot be described as "absolutely immutable" against an adversary with root database write privileges. Within the application boundary, it is append-only and tamper-evident against application actors, administrators, and compromised service tokens.

**Mitigation & External Anchoring Strategy:**
To protect against database-level rewriting, TrustVault supports an **External Anchoring Approach**:
1. **Periodic Merkle / State Head Anchoring:** The latest `event_hash` (the chain head) is periodically signed and committed outside the database (e.g., to AWS CloudWatch with WORM retention, a public RFC 3161 Timestamping Authority, an external immutable append-only ledger, or a Git commit pushed to an external hardened repository).
2. **Verification against External Anchor:** Even if an attacker rewires the entire internal database table, the recomputed head hash will fail verification against the external, independent anchor.

**Residual Risk:** Time gap between the occurrence of an event and the next external anchor interval (e.g., 5-minute anchoring window).

**Accepted Risk:** Accepted as standard state-of-the-art practice for enterprise tamper evidence without requiring costly distributed consensus on every write transaction.

---

## 25. Automated Probing & Rapid IDOR Enumeration

**Threat:** An authenticated actor systematically probes numerical or UUID document IDs in quick succession to identify permission gaps or enumerate private document titles.

**Mitigation:** The Adaptive Zero-Trust Policy Engine (`src/lib/policy-engine.ts`) tracks recent denied requests per actor. If 5+ denials occur in a short window or probe confidential-tier documents, an automated 15-minute temporary security restriction (`TEMPORARILY_RESTRICT`) is engaged, halting further probing.

**Residual Risk:** Slow, low-frequency probing below the sliding window threshold over multiple weeks.

**Accepted Risk:** Addressed by long-term audit trail aggregation and scheduled security review.

---

## 26. AI Privacy Shield Sensitive Data Leakage & False Negatives

**Threat:** A sensitive entity (e.g. customized national ID or obfuscated credit card format) is missed by regular expression detectors and included in a shared document.

**Mitigation:** TrustVault enforces **Human-in-the-Loop** verification. The Privacy Shield highlights detected entities with confidence scores, but the document owner must review and explicitly authorize the redaction masks before the platform mints a new protected copy. The original file is never overwritten. Furthermore, credit card detection incorporates the Luhn checksum algorithm to prevent false positives on random 13-19 digit numbers.

**Residual Risk:** Novel, proprietary sensitive data formats not covered by known pattern rules.

**Accepted Risk:** Document owners remain responsible for final visual review before distribution.

---

## 27. Access Policy Simulator Abuse & Information Disclosure

**Threat:** A low-privileged viewer attempts to access the Policy Simulator to discover user permission models or probe document metadata.

**Mitigation:** The Policy Simulator endpoint (`/api/admin/policy/simulate`) enforces strict `requireRole(['admin'])`. Non-admin attempts return immediate 403 Forbidden and log a denied audit event.

**Residual Risk:** Malicious administrator previewing permissions (acceptable as admins already have full metadata visibility).

**Accepted Risk:** Administrator actions are permanently hash-chained in the tamper-evident audit log.

---

## 28. Cryptographic Checkpoint Signature Forgery & Rollback

**Threat:** An attacker copies an old valid signed checkpoint and presents it to prove a current audit chain state, concealing recent deleted records.

**Mitigation:** Checkpoints include an RFC 3339 UTC timestamp, an incremental monotonic `eventCount`, and the exact `chainHeadHash`. When verifying a checkpoint report, client tools verify that the checkpoint's head matches the active chain head and that `eventCount` matches the total verified blocks.

**Residual Risk:** Physical compromise of the server's `SESSION_SECRET` signing key.

**Accepted Risk:** Key is isolated in server environment variables and never checked into version control.

**Automated Test:** `tests/unique-features.test.ts` ("HMAC Checkpoint Signatures: generates valid cryptographic signature for audit chain export").

---

## 29. Non-Owner Document Upload & Registration Role Elevation

**Threat:** A viewer or external unauthenticated client attempts to upload arbitrary files to the platform or forge their role during registration.

**Mitigation:** `POST /api/documents` strictly enforces `if (user.role !== 'owner') return 403 Forbidden` and emits a denied audit log event. The UI hides the Upload link for non-owners, but the backend serves as the authoritative gate. Public registration in `POST /api/auth/register` validates roles through a strict Zod enum (`z.enum(["owner", "viewer", "admin"])`), and passwords are saved with scrypt-hashed credentials.

**Residual Risk:** An authorized owner could upload malicious file content (mitigated by deep magic-byte sniffing and 50MB size caps).

**Accepted Risk:** Low — authenticated owners have legal accountability via the immutable audit trail.

**Automated Test:** `tests/user-role-features.test.ts` ("rejects document upload when user is viewer with 403 Forbidden", "rejects document upload when user is admin with 403 Forbidden", "creates an account with owner role when owner is selected").

---

## 30. AI Agent Autonomous Access Expansion

**Threat:** An AI assistant model running inside the platform autonomously widens document access permissions, bypassing human authorization decisions.

**Mitigation:** The AI assistant strictly functions as a read-only advisor (`ai_suggested: true`). It cannot directly insert rows into `document_permissions`. Access grants require explicit human submission and confirmation (`decision: 'human_confirmed'`). Both the AI's generated rationale and the owner's human confirmation are permanently recorded in the SHA-256 tamper-evident audit chain.

**Residual Risk:** A human owner recklessly accepts an AI suggestion without reading it.

**Accepted Risk:** Acceptable — the human owner assumes full organizational and legal liability, with immutable audit proof recorded in the chain.

**Automated Test:** `tests/document-ai.test.ts`, `tests/api-authorization.test.ts` (verifying human confirmation requirement on permission grants).


