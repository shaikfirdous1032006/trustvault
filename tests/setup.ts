/**
 * Test setup — shared across all Vitest tests.
 * Validates required environment variables are present.
 */

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
