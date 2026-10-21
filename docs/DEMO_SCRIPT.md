# TrustVault — 5-Minute Video Demonstration Script

**Title:** TrustVault: Secure Document Sharing with a Tamper-Evident Audit Trail  
**Duration:** Exactly 5:00 minutes  
**Presenter:** Senior Full-Stack Security Engineer  
**Seeded Demo Credentials:**
- `admin@example.com` / `TrustVault2024!` (Role: Admin)
- `owner@example.com` / `TrustVault2024!` (Role: Owner)
- `viewer@example.com` / `TrustVault2024!` (Role: Viewer)

---

### [0:00 – 0:45] Scene 1: Introduction & Security Architecture Overview

**Visual:**
- Screen opens on the TrustVault Landing Page (`/login`) showcasing the clean, accessible light-theme enterprise security aesthetic (warm sand `#FBF9F5`, coffee brown `#724B39`, and Chinese black `#0C1519`).
- Terminal window open side-by-side displaying `npm test` passing 54 automated security tests.

**Audio / Voiceover:**
> "Welcome to TrustVault, an enterprise-grade document sharing platform built with Next.js 15 App Router, TypeScript, Tailwind CSS, and Supabase PostgreSQL with Row Level Security.
> 
> In traditional document systems, authorization is often handled purely in application code or UI hiding. If an API check is forgotten, data leaks. In TrustVault, we enforce a strict **default-deny** architecture. PostgreSQL RLS serves as the final, immutable authorization boundary, paired with server-side validation on every single request.
> 
> Today, we'll demonstrate our three core personas: Owner, Viewer, and Admin, proving real-time access control, instant revocation, and our SHA-256 hash-chained audit trail."

---

### [0:45 – 1:30] Scene 2: Document Upload, Checksum & Versioning (Owner Flow)

**Visual:**
- Log in as `owner@example.com`.
- Dashboard loads showing recent documents and quick action cards.
- Navigate to `/dashboard/upload`.
- Drag and drop `Q3_Financial_Audit.pdf` (5.2 MB).
- Enter title: `"Q3 2026 Financial Audit & Forecast"`, Category: `"Financial"`, Description: `"Highly confidential corporate audit."`
- Click **Upload Document**.
- Redirects to `/dashboard/documents/:id`. Show the generated SHA-256 checksum, file size, version number (v1), and private storage path.

**Audio / Voiceover:**
> "Let's log in as our Document Owner. When the owner uploads a document, TrustVault computes the file's SHA-256 checksum client-and-server-side, validates the MIME type against a strict allowlist, and commits the file to a completely private storage bucket.
> 
> Notice that files never have permanent public URLs. Downloads only occur through short-lived signed URLs with a 5-minute TTL, generated dynamically only after a fresh authorization check."

---

### [1:30 – 2:30] Scene 3: Granular Permissions & Instant Access Verification

**Visual:**
- On document detail page, switch to the **Permissions** tab.
- Currently, only the owner has access.
- Click **Grant Access**.
- Enter `viewer@example.com`, select **Read** permission, and set an expiry date.
- Submit the modal. The active permission appears with a badge.
- Open an Incognito browser window. Log in as `viewer@example.com`.
- Viewer dashboard shows `"Q3 2026 Financial Audit & Forecast"`.
- Viewer opens the document and clicks **Download**. The file downloads successfully via a 300-second signed URL.

**Audio / Voiceover:**
> "Now let's share this document with `viewer@example.com`. The owner explicitly grants 'Read' access.
> 
> Switching over to our viewer's session in a private window: the document now appears in their library. The viewer can view metadata and download the file. Notice that the download endpoint freshly evaluated their permission before issuing a signed storage token. No authorization decisions are ever cached."

---

### [2:30 – 3:30] Scene 4: Immediate Revocation & Default-Deny Proof

**Visual:**
- Switch back to the **Owner** window.
- In the Permissions tab, click the **Revoke (X)** button on `viewer@example.com`.
- Status immediately transitions to 'Revoked'.
- Switch back to the **Viewer** window.
- Click **Download** again or refresh the page.
- Screen displays a clean, secure **Access Denied (403)** empty state.
- In DevTools Network tab, inspect the response: HTTP 403 Forbidden: `{"success": false, "error": "Access denied"}`.
- Viewer attempts to directly fetch `GET /api/documents/:id` via curl/Fetch — returns 403.

**Audio / Voiceover:**
> "Here is our non-negotiable security rule in action: **Immediate Revocation**. The moment the owner clicks 'Revoke', `revoked_at` is stamped in the database.
> 
> When the viewer tries to download or even view the document again one second later, access is denied immediately. Because we do not cache authorization in tokens or memory, there is zero revocation delay. PostgreSQL RLS and the server-side validator block the request at the perimeter."

---

### [3:30 – 4:15] Scene 5: Admin Isolation & Search Privacy

**Visual:**
- Open a third browser tab and log in as `admin@example.com`.
- Admin visits `/dashboard/admin/users` to view the user directory.
- Admin visits `/dashboard/documents`. The confidential document is **NOT readable** by the admin without explicit permission.
- Admin attempts to open `/api/documents/:id/download` — receives HTTP 403 Forbidden.
- Viewer attempts to use search bar (`?search=Financial`) — the search query returns 0 results for the revoked document.

**Audio / Voiceover:**
> "A critical requirement in zero-trust architecture is **Admin Isolation**. In TrustVault, administrators manage users and inspect platform health, but they **cannot implicitly read or download documents**. 
> 
> As you can see, when our admin attempts to access or download the owner's confidential financial document without an explicit grant, access is strictly forbidden by both RLS and our API layer. Furthermore, our search queries are scoped at the database level, ensuring search never leaks unauthorized document titles."

---

### [4:15 – 5:00] Scene 6: Tamper-Evident Audit Trail & Signed Checkpoints

**Visual:**
- While logged in as `admin@example.com`, navigate to `/dashboard/admin/audit`.
- Display the platform audit table showing `permission_grant`, `permission_revoke`, and the viewer's `denied` download attempt.
- Click **Verify Hash Chain**: green banner appears confirming 100% cryptographic soundness.
- Click **Export Signed Report**: downloads JSON report with HMAC-SHA256 checkpoint signature.
- Click **Simulate Storage Tampering**: a malicious payload alteration is injected into the database; verify chain re-runs and immediately catches the exact tampered record!

**Audio / Voiceover:**
> "Finally, let's examine TrustVault's **tamper-evident audit trail**. 
> 
> Every allowed action and, crucially, **every denied attempt** is logged with actor identity, hashed IP, and canonical details. Every single event is cryptographically linked to the previous event using a SHA-256 hash chain.
> 
> When our admin clicks 'Verify Hash Chain', the server recomputes every event from genesis to head. If an attacker attempts to alter any byte in an audit record, the cryptographic hash chain breaks and tampering is instantly exposed."

---

### [5:00 – 6:00] Scene 7: AI Privacy Shield & Redaction (Owner Flow)

**Visual:**
- Switch to Owner window, navigate to `/dashboard/privacy`.
- Select `Q3_Financial_Audit.txt`.
- Click **Scan for Sensitive Data**.
- UI highlights findings with confidence scores: SSN (`[REDACTED_SSN_••••6789]`), Payment Cards (`[REDACTED_CARD_••••0366]`), API keys, and passwords.
- Owner reviews the findings, keeps all selected, and clicks **Generate Redacted Copy**.
- TrustVault mints `[Redacted] Q3 2026 Financial Audit & Forecast`. Original file is 100% unaltered.

**Audio / Voiceover:**
> "Now let's examine the **AI Privacy Shield**. When an owner wants to share a document externally, they can scan it for sensitive data. 
> 
> The detector uses deterministic pattern recognizers and Luhn checksum validation to find SSNs, credit cards, API tokens, and plaintext passwords. 
> 
> Crucially, the system enforces **Human-in-the-Loop** verification: the owner reviews the proposed replacements, confirms the redaction, and TrustVault mints a separate, protected copy. The original document remains completely untouched in immutable storage."

---

### [6:00 – 7:00] Scene 8: Threat Alerts & Policy Simulator (Admin Flow)

**Visual:**
- Switch back to Admin window, navigate to `/dashboard/admin/alerts`.
- View real-time threat detection alerts: `Repeated Denied Document Access` and `Credential Stuffing`.
- Click **Restrict Actor Access** on the attacker: 15-minute temporary restriction is applied immediately.
- Navigate to `/dashboard/admin/simulator`.
- Select `viewer@example.com` and `Q3_Financial_Audit.txt`.
- Set proposed action: `Elevate to Edit Access`.
- Click **Simulate Policy Impact**.
- Visual diff shows access elevation, Zero-Trust decision outcome, and warning alerts: *"Viewer role elevated to edit privileges on confidential document"*.

**Audio / Voiceover:**
> "To close, let's look at **Threat Detection & Policy Simulation**.
> 
> Our detection pipeline constantly evaluates audit events for brute force, IDOR enumeration, and mass download bursts. When an attack is flagged, the administrator can investigate and temporarily restrict the actor with a single click.
> 
> And before making any permission change, administrators can use the **Access Policy Simulator** to run 'What-If' scenarios through our Zero-Trust engine, projecting access changes and risk consequences before deployment.
> 
> That is TrustVault — defense in depth, zero-trust authorization, explainable threat intelligence, and verifiable audit integrity. Thank you."

