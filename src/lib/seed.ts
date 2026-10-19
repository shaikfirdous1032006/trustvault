/**
 * Seed script for TrustVault demo accounts.
 * Run with: npx tsx src/lib/seed.ts
 * 
 * Creates three demo accounts via Supabase Auth API:
 * - admin@example.com (role: admin)
 * - owner@example.com (role: owner)
 * - viewer@example.com (role: viewer)
 * 
 * The handle_new_user trigger automatically creates user profiles.
 */

import { createClient } from '@supabase/supabase-js';

const SUPABASE_URL = process.env.NEXT_PUBLIC_SUPABASE_URL!;
const SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY!;

if (!SUPABASE_URL || !SERVICE_ROLE_KEY) {
  console.error('Missing NEXT_PUBLIC_SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY');
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SERVICE_ROLE_KEY, {
  auth: {
    autoRefreshToken: false,
    persistSession: false,
  },
});

const DEMO_PASSWORD = process.env.DEMO_PASSWORD || 'TrustVault2024!';

const demoUsers = [
  {
    email: 'admin@example.com',
    password: DEMO_PASSWORD,
    role: 'admin',
    full_name: 'Admin User',
  },
  {
    email: 'owner@example.com',
    password: DEMO_PASSWORD,
    role: 'owner',
    full_name: 'Document Owner',
  },
  {
    email: 'viewer@example.com',
    password: DEMO_PASSWORD,
    role: 'viewer',
    full_name: 'Document Viewer',
  },
];

async function seed() {
  console.log('🌱 Seeding TrustVault demo accounts...\n');

  for (const user of demoUsers) {
    try {
      // Check if user already exists
      const { data: existingUsers } = await supabase.auth.admin.listUsers();
      const existing = existingUsers?.users?.find((u) => u.email === user.email);

      if (existing) {
        console.log(`  ✓ ${user.email} already exists (${user.role})`);

        // Ensure profile has correct role
        await supabase
          .from('users')
          .update({ role: user.role, full_name: user.full_name })
          .eq('id', existing.id);
        continue;
      }

      // Create auth user
      const { data, error } = await supabase.auth.admin.createUser({
        email: user.email,
        password: user.password,
        email_confirm: true,
        user_metadata: {
          full_name: user.full_name,
          role: user.role,
        },
      });

      if (error) {
        console.error(`  ✗ Failed to create ${user.email}:`, error.message);
        continue;
      }

      console.log(`  ✓ Created ${user.email} (${user.role}) - ID: ${data.user.id}`);
    } catch (err) {
      console.error(`  ✗ Error creating ${user.email}:`, err);
    }
  }

  console.log('\n✅ Seeding complete!');
  console.log('\nDemo credentials:');
  console.log(`  Password for all accounts: ${DEMO_PASSWORD}`);
  demoUsers.forEach((u) => {
    console.log(`  ${u.role.padEnd(8)} → ${u.email}`);
  });
}

seed().catch(console.error);
