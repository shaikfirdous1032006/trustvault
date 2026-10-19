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
