/**
 * Test setup — shared across all Vitest tests.
 * Validates required environment variables are present.
 */

import { randomBytes } from 'crypto';
import { join } from 'path';
import { tmpdir } from 'os';

// Session signing key for tests. Random per worker process so no reusable
// secret is ever committed to the repository.
if (!process.env.SESSION_SECRET) {
  process.env.SESSION_SECRET = randomBytes(32).toString('hex');
}

// Standalone-mode tests read and write a JSON store. Point them at a scratch
// directory per worker so a test run cannot mutate or race the real .data/store.json
// that a running dev server owns. Must be set before any module import reads it.
if (!process.env.DATA_DIR) {
  process.env.DATA_DIR = join(tmpdir(), 'trustvault-tests', String(process.pid));
}

// Vitest does not read .env.local, and share links refuse to mint a URL they cannot
// render as absolute.
if (!process.env.NEXT_PUBLIC_APP_URL) {
  process.env.NEXT_PUBLIC_APP_URL = 'http://localhost:3000';
}

// The login route refuses seeded demo sign-in unless DEMO_PASSWORD is configured, so
// the credential tests need one. This value exists only inside the test process and
// is never written to disk; it is not a production secret.
if (!process.env.DEMO_PASSWORD) {
  process.env.DEMO_PASSWORD = 'test-only-credential-not-a-secret';
}

// Ensure test environment variables are set
const requiredVars = [
  'NEXT_PUBLIC_SUPABASE_URL',
  'NEXT_PUBLIC_SUPABASE_ANON_KEY',
  'SUPABASE_SERVICE_ROLE_KEY',
];

for (const envVar of requiredVars) {
  if (!process.env[envVar]) {
    console.warn(
      `⚠️  Missing env var: ${envVar}. Tests requiring Supabase will be skipped.`
    );
  }
}
