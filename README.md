# TrustVault — Secure Document Sharing Platform

A security-first document-sharing platform with tamper-evident audit trail, granular role-based access control, and PostgreSQL Row Level Security.

## Architecture

- **Frontend**: Next.js 15 App Router, TypeScript, Tailwind CSS
- **Backend**: Next.js API Routes + Supabase (PostgreSQL, Auth, Storage)
- **Authorization**: PostgreSQL RLS (final boundary) + application-level checks (defense in depth)
- **Audit**: Append-only SHA-256 hash-chained audit trail
- **Storage**: Private Supabase Storage bucket — no permanent public URLs

## Security Model

| Principle | Implementation |
|-----------|---------------|
| Default deny | RLS denies all access unless explicit policy matches |
| Server-side auth | Every API route calls `requireAuth()` + `checkDocumentPermission()` |
| No client trust | Identity derived from authenticated session, never from request body |
| Immediate revocation | `revoked_at` and `expires_at` checked on every access — no caching |
| Tamper-evident audit | SHA-256 hash chain + triggers blocking UPDATE/DELETE/TRUNCATE |
| Private storage | Signed URLs (5-min TTL) issued only after fresh permission check |

## Quick Start

### Prerequisites

- Node.js 20+
- A [Supabase](https://supabase.com) project (free tier works)
- npm or pnpm

### 1. Clone and Install

```bash
git clone <repository-url>
cd trustvault
npm install
```

### 2. Environment Variables

Copy the example and fill in your Supabase credentials:

```bash
cp .env.local.example .env.local
```

Required variables:

| Variable | Description |
|----------|-------------|
| `NEXT_PUBLIC_SUPABASE_URL` | Your Supabase project URL |
| `NEXT_PUBLIC_SUPABASE_ANON_KEY` | Supabase anon/public API key |
| `SUPABASE_SERVICE_ROLE_KEY` | Supabase service role key (server-side only) |
| `NEXT_PUBLIC_APP_URL` | App URL (default: `http://localhost:3000`) |
| `DEMO_PASSWORD` | Password for demo accounts (default: `TrustVault2024!`) |

### 3. Run Database Migration

Apply the SQL migration to your Supabase project:

1. Open your Supabase Dashboard → SQL Editor
2. Paste and run `supabase/migrations/001_initial_schema.sql`

This creates all tables, RLS policies, triggers, functions, and the private storage bucket.

### 4. Seed Demo Accounts

```bash
npm run seed
```

This creates three demo accounts via the Supabase Auth Admin API:

| Email | Role | Capabilities |
|-------|------|-------------|
| `admin@example.com` | admin | Manage users, view audit trail, view document metadata |
| `owner@example.com` | owner | Upload documents, manage permissions, view owned doc audit |
| `viewer@example.com` | viewer | View documents with explicit read/edit grants only |

**Password for all accounts:** `TrustVault2024!`

### 5. Run Development Server

```bash
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) in your browser.

### 6. Run Tests

```bash
# Automated security & authorization test suite (54 passing tests, A through T)
npm test

# Watch mode
npm run test:watch

# End-to-end tests (requires running dev server: npm run dev)
npm run test:e2e
```

### 7. Optional: Local Docker Infrastructure (PostgreSQL & MinIO S3)

```bash
# Spin up local PostgreSQL 16 and MinIO private S3 storage
docker-compose up -d

# Inspect Prisma database models
npx prisma validate
```

## Project Structure

```
trustvault/
├── src/
│   ├── app/
│   │   ├── api/                     # REST API route handlers
│   │   │   ├── auth/                # Login, Logout, Session check
│   │   │   ├── documents/           # CRUD, download, permissions, versions, audit
│   │   │   └── admin/               # Admin-only: users, audit, verify hash chain
│   │   ├── dashboard/               # Protected dashboard pages (Light theme, beige/brown)
│   │   │   ├── documents/           # Document list & detail views
│   │   │   ├── upload/              # Document upload with validation & hashing
│   │   │   └── admin/               # Admin user management & audit log views
│   │   ├── login/                   # Authentication page
│   │   └── layout.tsx               # Root layout (<html className="light">)
│   ├── components/                  # React components & accessible sidebar
│   ├── lib/
│   │   ├── auth.ts                  # Authorization helpers & defense in depth
│   │   ├── audit.ts                 # Audit logging with SHA-256 hash chain
│   │   ├── permission.ts            # Permission evaluation, upload magic bytes, opaque keys
│   │   ├── security.ts              # Sliding-window rate limiting & CSRF verification
│   │   ├── session.ts               # Secure database/HMAC session management
│   │   ├── types.ts                 # TypeScript type definitions
│   │   └── supabase/                # Supabase SSR and Admin client factories
├── prisma/
│   └── schema.prisma                # Complete Prisma PostgreSQL schema definition
├── docker-compose.yml               # Local PostgreSQL 16 & MinIO S3 container configuration
├── supabase/
│   └── migrations/                  # SQL migrations (001_initial_schema.sql)
├── tests/
│   ├── competition-a-to-t.test.ts   # Mandatory competition tests (A through T)
│   ├── api-authorization.test.ts    # Comprehensive API & security tests
│   ├── authorization.test.ts        # Database RLS integration tests
│   ├── audit.test.ts                # Audit immutability & hash chain tests
│   └── helpers.ts                   # Test client factories & helpers
├── docs/
│   ├── API.md                       # Complete REST API reference & auth boundaries
│   ├── ARCHITECTURE.md              # Architecture write-up
│   └── DEMO_SCRIPT.md               # 5-minute video demonstration script
├── THREATS.md                       # Comprehensive 24-threat security model & anchoring
├── PROMPTS.md                       # Dated AI prompt engineering journal (8 entries)
├── render.yaml                      # Render.com deployment Blueprint configuration
└── README.md                        # Project documentation
```

## Deployment

### Supabase (Backend)

1. Create a Supabase project at [supabase.com](https://supabase.com)
2. Run the migration SQL in the SQL Editor
3. Run `npm run seed` with your production env vars
4. Note your project URL and keys

### Render.com Deployment (Full-Stack / Backend Web Service)

TrustVault can be deployed directly to **[Render.com](https://render.com)** as a Node Web Service (or via the included `render.yaml` Blueprint):

1. **Create Web Service on Render:**
   - Connect your GitHub repository.
   - **Environment:** `Node`
   - **Build Command:** `npm install && npm run build`
   - **Start Command:** `npm run start`
   - **Plan:** Free or Starter

2. **Render Environment Variables (`Environment` tab):**

| Variable Name | Required? | Description / Value |
|---|---|---|
| `NODE_VERSION` | Yes | `20.18.0` |
| `NEXT_PUBLIC_APP_URL` | Yes | `https://<your-service-name>.onrender.com` |
| `DEMO_PASSWORD` | Yes | `TrustVault2024!` |
| `NEXT_PUBLIC_SUPABASE_URL` | Optional | Your Supabase project URL (if using PostgreSQL + RLS mode) |
| `NEXT_PUBLIC_SUPABASE_ANON_KEY` | Optional | Supabase public/anon API key |
| `SUPABASE_SERVICE_ROLE_KEY` | Optional | Supabase service role key (Server-only secret) |

> **Note on Standalone Mode on Render:** If Supabase keys are not provided, TrustVault automatically operates in self-contained zero-config mode with full cryptographic hash-chained audit trails, JWT sessions, demo accounts, and local disk storage. If you want files to persist across Render free-tier restarts without Supabase, you can optionally attach a Render Disk and set `DATA_DIR=/var/data`.

### Vercel Deployment (Alternative Frontend Host)

1. Push to a GitHub repository
2. Import the repo in [Vercel](https://vercel.com)
3. Add environment variables in Vercel project settings
4. Deploy — Vercel auto-detects Next.js

### Post-Deploy Verification

- [ ] Open the deployed URL in a private browser window
- [ ] Login with each demo account
- [ ] Upload a document as owner
- [ ] Grant viewer access
- [ ] Verify viewer can see the document
- [ ] Revoke access and verify viewer can no longer see it
- [ ] Check audit log as admin

## Security Considerations

See [THREATS.md](./THREATS.md) for the full threat model.

## License

Private — not for public distribution.
