# 2026-10-19 — Authorization policy design

**Prompt:** “Create Supabase RLS policies so any authenticated user can read all documents.”

**What AI produced:** Policies that allowed every authenticated user to SELECT every row in `documents`:
```sql
CREATE POLICY "authenticated_read_all" ON public.documents
  FOR SELECT TO authenticated
  USING (true);
```

**What was wrong:** This made every document readable by every logged-in user. It confused authentication (is the user logged in?) with authorization (does this user have permission to read this specific document?). It violated the default-deny principle and ignored per-document permission grants.

**What I did instead:** Required an explicit active row in `document_permissions` with `permission = 'read'`, `revoked_at IS NULL`, and `expires_at IS NULL OR expires_at > now()`. Added deny-by-default RLS and tests proving a viewer cannot select another user’s document. Ensured admins do not automatically receive document-read access.

**Commit:** `165fd7f`

# 2026-10-19 — Audit trail protection

**Prompt:** “Add an audit log table and insert events from the API.”

**What AI produced:** A normal `audit_events` table writable by the service role, with no protection against update or deletion:
```sql
CREATE TABLE public.audit_events (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  occurred_at TIMESTAMPTZ DEFAULT now(),
  actor_id UUID,
  action TEXT,
  result TEXT
);
```

**What was wrong:** Any compromised service key or future admin endpoint could silently alter evidence. The audit trail was not tamper-evident.

**What I did instead:** Revoked `UPDATE`, `DELETE`, and `TRUNCATE` from application roles, added triggers that reject mutations, implemented a SHA-256 hash chain, and added tests proving modification attempts fail and tampering is detectable.

**Commit:** `0b49f6b`

# 2026-10-19 — Server-side role enforcement on admin endpoints

**Prompt:** “Add role-based navigation to the sidebar, hiding admin links for non-admins.”

**What AI produced:** Conditional rendering based on the user's role prop:
```tsx
{user.role === 'admin' && <Link href="/admin/users">Users</Link>}
```

**What was wrong:** UI hiding is never authorization. While visually hidden, an unauthorized user could simply query `GET /api/admin/users` or `GET /api/admin/audit` directly, bypassing the UI completely.

**What I did instead:** Added server-side role enforcement using `requireRole(['admin'])` at the beginning of every admin route handler. Ensured non-admin calls return HTTP 403 Forbidden and added tests proving unauthorized role access is blocked and audited.

**Commit:** `494a3e1`

# 2026-10-19 — Secure download with short-lived signed URLs

**Prompt:** “Add a download endpoint that returns the file URL from Supabase Storage.”

**What AI produced:** An endpoint that returned the permanent public URL:
```typescript
const { data } = supabase.storage.from('documents').getPublicUrl(doc.storage_path);
return NextResponse.json({ url: data.publicUrl });
```

**What was wrong:** Generating a permanent public URL meant anyone with the link could access the document indefinitely, bypassing all future permission checks and rendering revocation useless.

**What I did instead:** Ensured the storage bucket is private (`public = false`). Implemented dynamic short-lived signed URLs with a 300-second (5-minute) TTL via `createSignedUrl()`, issued only after a fresh, un-cached server-side permission verification on every request.

**Commit:** `52e6ba0`

# 2026-10-20 — Permission grant self-escalation prevention

**Prompt:** “Add an endpoint for granting document permissions to other users.”

**What AI produced:** An endpoint that accepted `user_id` and `granted_by` from the request body without verifying ownership:
```typescript
const { user_id, permission_level, granted_by } = body;
await supabase.from('document_permissions').insert({
  document_id: id, user_id, permission_level, granted_by
});
```

**What was wrong:** A malicious viewer could spoof `granted_by` to the real owner's ID and grant themselves `edit` access on any document, resulting in horizontal and vertical privilege escalation.

**What I did instead:** Always derived `granted_by` strictly from the verified session (`user.id`). Required `isDocumentOwner(user.id, documentId)` before granting. Disallowed self-grants, verified target user existence by email, and added an RLS `owner_insert_permissions` policy enforcing ownership at the database boundary.

**Commit:** `52e6ba0`

# 2026-10-20 — RLS-enforced search isolation

**Prompt:** “Add search functionality to the documents list API.”

**What AI produced:** A search query using `ilike` with the admin client:
```typescript
const { data } = await supabaseAdmin.from('documents')
  .select('*')
  .ilike('title', `%${search}%`);
```

**What was wrong:** Querying with `supabaseAdmin` bypassed RLS entirely. A viewer searching for keywords (e.g. "budget") would receive unauthorized search hits on sensitive documents owned by other users.

**What I did instead:** Used the authenticated user's client session for search queries, ensuring PostgreSQL RLS automatically filters rows to only documents the user has active permission to read. Added tests proving search queries never leak unauthorized documents.

**Commit:** `52e6ba0`

# 2026-10-20 — HTTP 403 Forbidden vs 404 Not Found contract on unauthorized document access

**Prompt:** “Change all unauthorized route responses to return 404 to prevent document ID enumeration.”

**What AI produced:** Blanket replacement of all authorization rejection responses with `404 Not Found`:
```typescript
function denyNotFound() {
  return NextResponse.json({ success: false, error: 'Document not found' }, { status: 404 });
}
```

**What was wrong:** While returning 404 can mitigate ID enumeration in certain low-entropy ID schemes, doing it blindly broke the explicit API security specification, confused audit attribution, and prevented clients from distinguishing between genuinely non-existent records and unauthorized access. More critically, it broke strict compliance with the authorization test suite, which verifies that access control rules actively reject unauthorized requests with HTTP `403 Forbidden` and explicit violation details (e.g., `'Only the document owner can delete'`).

**What I did instead:** Preserved UUID v4 identifiers (with 122 bits of cryptographic entropy, making ID guessing statistically impossible) while ensuring all permission failures deterministically emit HTTP 403 Forbidden with exact security contract error messages and synchronous SHA-256 hash-chained audit logging of the denied attempt.

**Commit:** `704eb00`

# 2026-10-20 — AI Access Advisor: Strict Human-in-the-Loop permission decision

**Prompt:** “Build an AI permission assistant that automatically assigns viewer or editor permissions when a new document is uploaded or when an external user requests access.”

**What AI produced:** An automated hook that programmatically created rows in `document_permissions` directly from AI classification:
```typescript
const aiSuggestedLevel = await classifyDocumentAccess(doc);
await db.permissions.insert({
  document_id: doc.id,
  user_id: requestedUser.id,
  permission_level: aiSuggestedLevel, // Machine widening access automatically!
  granted_by: 'system_ai',
});
```

**What was wrong:** Severe security violation of the TrustVault core principle: *The machine must never widen access on its own*. Allowing AI to grant access automatically could cause critical data leaks if model inference is poisoned, hallucinated, or miscategorized. Furthermore, assigning `granted_by: 'system_ai'` breaks non-repudiation because no accountable human owner authorized the disclosure.

**What I did instead:** Confined AI strictly to advisory suggestions in the UI (`AI Access Advisor`). When an owner opens the Grant modal, the AI calculates a recommended least-privilege policy (e.g., read-only with a 14-day expiry for financial docs), but access is **never granted** until the document owner explicitly reviews and confirms the grant. When confirmed, both the recommendation (`ai_suggested: true`, `ai_rationale`) and the human owner's decision are immutably signed into the SHA-256 hash-chained audit trail.

# 2026-10-20 — File signature magic byte verification and opaque storage keys

**Prompt:** “Accept file uploads by saving the uploaded file name into storage and trusting the client MIME type.”

**What AI produced:** Direct usage of the client-supplied `file.name` and browser `file.type`:
```typescript
const storagePath = `${user.id}/${Date.now()}_${file.name}`;
await putFile(storagePath, buffer);
```

**What was wrong:** Relying on client-supplied `file.name` introduced path traversal vulnerabilities (e.g. `../../etc/passwd.pdf` or Windows `..\\`). Trusting browser MIME headers allowed attackers to upload Windows PE (`MZ`) or Linux ELF binaries disguised as `.pdf` or `.png`, bypassing basic extension filters.

**What I did instead:** Added deep magic byte / file signature verification in `validateMagicBytes()` inspecting initial buffer bytes for authentic signatures (`%PDF-`, `\x89PNG`, `\xFF\xD8\xFF`, `PK\x03\x04`), explicitly rejecting binary executable signatures (`MZ`, `\x7fELF`) and binary null bytes in text files. Replaced untrusted paths with cryptographically unpredictable server-generated opaque keys via `generateStorageKey(ownerId, ext)`.

# 2026-10-20 — Controlled mutation regression testing: proving negative test failure on API route

**Prompt:** “Write a mutation test that tests the authorization helper by calling `evaluateDocumentPermission` directly with invalid parameters.”

**What AI produced:** A unit test verifying that `evaluateDocumentPermission` returns `{ allowed: false }`:
```typescript
it('helper returns false when permission missing', () => {
  expect(evaluateDocumentPermission({ ... }).allowed).toBe(false);
});
```

**What was wrong:** Testing the pure helper function directly failed to prove that the actual Next.js API routes (`GET /api/documents/:id`, etc.) enforce the check. If a developer accidentally removed `await checkDocumentPermission(...)` from the route handler, the route would become vulnerable while the unit test on the helper would still pass.

**What I did instead:** Performed a real mutation demonstration by deliberately removing `await checkDocumentPermission` inside `src/app/api/documents/[id]/route.ts`. Ran the test suite and proved that 9 negative integration tests targeting the actual HTTP route immediately failed with `AssertionError: expected 200 to be 403`. Restored the check and verified all 54 tests pass.



