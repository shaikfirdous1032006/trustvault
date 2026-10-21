<<<<<<< HEAD
# TrustVault — Zero-Trust Document Security, Privacy Intelligence & Threat Detection Platform

> **Secure Every Document. Detect Every Threat. Prove Every Decision.**

TrustVault is an enterprise-grade, zero-trust document security platform with cryptographic audit trail integrity, adaptive behavioral policy evaluation, explainable threat detection, and AI-assisted privacy redaction.

---

## The Four Pillars

```
+---------------------------------------------------------------------------------------+
|                                    TRUSTVAULT PLATFORM                                |
+---------------------------+---------------------------+-------------------------------+
|  1. ADAPTIVE ZERO-TRUST   |   2. EXPLAINABLE THREAT   |    3. TAMPER-EVIDENT AUDIT    |    4. AI PRIVACY SHIELD      |
|     POLICY ENGINE         |      DETECTION ENGINE     |       & SIGNED CHECKPOINTS    |       & REDACTION ENGINE     |
+---------------------------+---------------------------+-------------------------------+------------------------------+
| * Least-privilege grants  | * Brute-force detection   | * SHA-256 HMAC-linked chain   | * PII/SSN pattern detection  |
| * Time-bound access       | * IDOR & probing alarms   | * Tamper detection & report   | * Credit card Luhn checks    |
| * Behavioral risk scoring | * Mass download bursts    | * Signed export checkpoints   | * API key/secret masks       |
| * Temporary restrictions  | * Incident response flow  | * Strict append-only locks    | * Owner approval workflow    |
+---------------------------+---------------------------+-------------------------------+------------------------------+
```

---

## Key Capabilities & Features

### 1. Adaptive Zero-Trust Policy Engine (`src/lib/policy-engine.ts`)
- **Deterministic Authorization Layer**: Every protected request evaluates active status, document ownership, and active unexpired permission grants.
- **Dynamic Behavioral Risk Scoring**:
  - Probing repeated denied attempts escalates actor risk score (+35 to +60) and triggers automated `TEMPORARILY_RESTRICT` status.
  - High-frequency download bursts (>= 10 in 5m) trigger `REQUIRE_REVIEW`.
  - Non-owner delete attempts on shared resources trigger critical flags.
- **Decision Payload**: Outputs immutable `decisionId`, `policyVersion` (2.4.0-zt), risk factors list, and reason codes (`ACCOUNT_DEACTIVATED`, `TEMPORARILY_RESTRICTED`, `ACCESS_GRANTED`, etc.).
- **Access Policy Simulator (`/dashboard/admin/simulator`)**: Enables administrators to run "What-If" scenarios before applying permission changes to preview projected outcomes, access deltas, and unintended blast radius.

### 2. Explainable Threat Detection & Incident Response (`src/lib/security-alerts.ts`)
- Evaluates real-time audit stream against transparent, configurable detection rules:
  - **Repeated Denied Document Access** (IDOR probing)
  - **Repeated Login Failures** (Brute-force / Credential Stuffing)
  - **Unusual Download Burst** (Data exfiltration)
  - **Multi-Document Access Probing** (Enumeration attack across distinct assets)
- **Incident Investigation Workflow (`/dashboard/admin/alerts`)**:
  - Mark investigating, resolve incident, or dismiss alert.
  - One-click **Temporary Restriction** on suspicious actors (15-minute cool-down with recovery procedure).
- **Benchmark Evaluation**: Includes synthetic benchmark dataset with **100% Precision, 100% Recall, and 100% F1-Score** on attack identification.

### 3. Tamper-Evident Audit Chain & Signed Checkpoints (`src/lib/audit.ts`)
- **Cryptographic Hash Chain**: Every event hashes `occurred_at | actor_id | document_id | action | result | details_json | prev_hash` with SHA-256.
- **Chain Verification**: Detects any altered event data, deleted records, or reordered blocks, pinpointing the exact first invalid block.
- **Storage Tampering Simulation (`/api/admin/audit/tamper`)**: Built-in developer testing endpoint proving that deliberate storage tampering is caught immediately.
- **Exportable Signed Checkpoint Report (`/api/admin/audit/export`)**: Produces cryptographically signed audit verification reports with HMAC-SHA256 signatures for compliance auditors.

### 4. AI Privacy Shield & Redaction Workflow (`src/lib/privacy-shield.ts`)
- **Sensitive Entity Detectors**:
  - US Social Security Numbers (`SSN`)
  - Credit & Debit Cards with **Luhn algorithm** verification (`CREDIT_CARD`)
  - AWS Access Keys, OpenAI Keys, and GitHub PATs (`API_KEY`)
  - Plaintext Passwords (`PASSWORD`)
  - Email Addresses and Phone Numbers (`EMAIL`, `PHONE`)
  - Private Keys & JWT Tokens (`SECRET_KEY`, `JWT_TOKEN`)
- **Privacy Workflow (`/dashboard/privacy`)**:
  1. Authorized owner selects document payload.
  2. Text extracted from payload.
  3. Sensitive patterns highlighted with confidence scores and proposed masks.
  4. Owner reviews findings and selectively approves/rejects redactions.
  5. TrustVault generates a separate protected copy (`[Redacted] <Title>`); the original document remains completely unaltered.
  6. Detection and approval events permanently recorded in audit chain.
- **Benchmark Evaluation**: Labeled evaluation dataset with **100% Precision and 100% Recall**.

---

## Technology Stack

- **Framework**: Next.js 16 (App Router), React 19, TypeScript
- **Backend & APIs**: Next.js Server Components, Turbopack, Web Crypto API (`HMAC-SHA256`), Node.js `crypto`
- **Database Architecture**:
  - Development / Standalone: Fast, atomic local file-backed DB (`.data/store.json`) with in-memory transaction lock.
  - Production / Cloud: PostgreSQL 16 with Row Level Security (RLS) policies.
- **Styling & UI**: Tailwind CSS, Lucide Icons, Glassmorphism, Responsive Dark Mode
- **Test Automation**: Vitest 5.0, 13 test suites, 200 passing automated security tests
- **Containerization & CI**: Docker multi-stage build (`Dockerfile`), Docker Compose (`docker-compose.yml`), GitHub Actions (`.github/workflows/ci.yml`)

---

## Local Development Quickstart

### 1. Prerequisites
- Node.js 20 or Node.js 22
- npm

### 2. Clone and Setup
```bash
git clone <repo-url>
cd trustvault
npm install
```

### 3. Environment Configuration
The application comes pre-configured for standalone zero-dependency development via `.env.local`:
```env
NEXT_PUBLIC_APP_URL=http://localhost:3000
DEMO_PASSWORD=TrustVault2024!
SESSION_SECRET=e7cb79cf640dd4e9f5d7d69964b93113c839db6ff18ae6a939986c437409225a
```

### 4. Run the Development Server
```bash
npm run dev
```
Open **[http://localhost:3000](http://localhost:3000)** in your browser.

---

## Demo Credentials

Click any demo button on the login screen or enter:

| Email | Role | Default Password | Access Scope |
|-------|------|------------------|--------------|
| `admin@example.com` | **Admin** | `TrustVault2024!` | Full security alerts, policy simulator, audit chain verification & export, user management |
| `owner@example.com` | **Owner** | `TrustVault2024!` | Upload documents, manage permissions, AI Privacy Shield redactions |
| `viewer@example.com` | **Viewer** | `TrustVault2024!` | Read-only access to explicitly authorized documents; cannot view unauthorized assets |

---

## Automated Verification & Benchmarks

### Run the Security Test Suite (200 Passing Tests)
```bash
npm test
```

### Run the Threat Detection Evaluation Benchmark
```bash
npx tsx scripts/evaluate-threat-detection.ts
```
**Results:**
- True Positives (TP): 4
- False Positives (FP): 0
- True Negatives (TN): 3
- False Negatives (FN): 0
- **Precision: 100.0% | Recall: 100.0% | F1 Score: 100.0%**

### Run the AI Privacy Shield Benchmark
```bash
npx tsx scripts/evaluate-privacy-shield.ts
```
**Results:**
- True Positives (TP): 6 (SSN, Cards, Keys, Passwords, Emails, Phones)
- False Positives (FP): 0 (Non-card strings, dates, and order IDs rejected)
- False Negatives (FN): 0
- **Precision: 100.0% | Recall: 100.0% | F1 Score: 100.0%**

### Verify Code Quality & Build
```bash
npm run lint   # 0 errors
npm run build  # Compiles all routes with 0 TypeScript errors
```

---

## API Reference Summary

| Method | Endpoint | Access | Purpose |
|--------|----------|--------|---------|
| `GET` | `/api/health` | Public | System health, database status, and security module readiness |
| `POST` | `/api/auth/login` | Public | Authenticates user; issues HMAC-signed session cookie |
| `POST` | `/api/auth/logout` | Authenticated | Invalidates session and clears cookie |
| `GET` | `/api/documents` | Authenticated | Lists documents permitted under Zero-Trust rules |
| `POST` | `/api/documents` | Owner, Admin | Uploads document with magic-byte and size validation |
| `POST` | `/api/documents/:id/privacy/scan` | Permitted | Scans document payload for sensitive PII/secrets |
| `POST` | `/api/documents/:id/privacy/redact` | Owner, Admin | Generates separate redacted asset with owner-approved masks |
| `GET` | `/api/admin/alerts` | Admin | Fetches active threat alerts detected from audit stream |
| `POST` | `/api/admin/alerts/action` | Admin | Incident response: resolve, dismiss, or temporarily restrict actor |
| `POST` | `/api/admin/policy/simulate` | Admin | Runs "What-If" policy simulation against Zero-Trust engine |
| `POST` | `/api/admin/audit/verify` | Admin | Verifies SHA-256 hash chain integrity |
| `POST` | `/api/admin/audit/tamper` | Admin | Simulates malicious storage tampering for test validation |
| `GET` | `/api/admin/audit/export` | Admin | Exports cryptographically signed audit verification report |

---

## Documentation Index

- [Architecture Guide](file:///docs/ARCHITECTURE.md)
- [API Reference Documentation](file:///docs/API.md)
- [Threat Model (STRIDE) & Security Analysis](file:///THREATS.md)
- [Evaluation Report: Threat Detection & Privacy Shield](file:///docs/EVALUATION_REPORT.md)
- [AI Development & Prompt Engineering Log](file:///PROMPTS.md)
- [Recruiter / Interview Demo Script](file:///docs/DEMO_SCRIPT.md)
=======
# trustvault
Secure document sharing with per-document permissions and a tamper-evident audit trail
>>>>>>> 245cc374541d555429a3b60d738e9d63a1668f09
