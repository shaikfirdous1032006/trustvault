/**
 * Test helpers for TrustVault.
 * Creates authenticated Supabase clients for each demo user role.
 * All authorization tests should use these helpers.
 */

import { createClient, SupabaseClient } from '@supabase/supabase-js';

const SUPABASE_URL = process.env.NEXT_PUBLIC_SUPABASE_URL!;
const SUPABASE_ANON_KEY = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!;
const SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY!;
const DEMO_PASSWORD = process.env.DEMO_PASSWORD || 'TrustVault2024!';

export const DEMO_USERS = {
  admin: { email: 'admin@example.com', password: DEMO_PASSWORD, role: 'admin' as const },
  owner: { email: 'owner@example.com', password: DEMO_PASSWORD, role: 'owner' as const },
  viewer: { email: 'viewer@example.com', password: DEMO_PASSWORD, role: 'viewer' as const },
};

/**
 * Create an admin/service-role Supabase client (bypasses RLS).
 */
export function createServiceClient(): SupabaseClient {
  return createClient(SUPABASE_URL, SERVICE_ROLE_KEY, {
    auth: { autoRefreshToken: false, persistSession: false },
  });
}

/**
 * Create a Supabase client authenticated as a specific demo user.
 */
export async function createAuthenticatedClient(
  role: 'admin' | 'owner' | 'viewer'
): Promise<SupabaseClient> {
  const user = DEMO_USERS[role];
  const client = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
    auth: { autoRefreshToken: false, persistSession: false },
  });

  const { error } = await client.auth.signInWithPassword({
    email: user.email,
    password: user.password,
  });

  if (error) {
    throw new Error(`Failed to authenticate as ${role}: ${error.message}`);
  }

  return client;
}

/**
 * Get the user ID for a demo account.
 */
export async function getUserId(role: 'admin' | 'owner' | 'viewer'): Promise<string> {
  const client = await createAuthenticatedClient(role);
  const { data: { user } } = await client.auth.getUser();
  if (!user) throw new Error(`Could not get user for role: ${role}`);
  return user.id;
}

/**
 * Create a test document owned by the 'owner' demo user.
 * Returns the document ID.
 */
export async function createTestDocument(
  title = 'Test Document',
  category = 'general'
): Promise<string> {
  const serviceClient = createServiceClient();
  const ownerId = await getUserId('owner');

  const { data, error } = await serviceClient
    .from('documents')
    .insert({
      owner_id: ownerId,
      title,
      category,
      storage_path: `${ownerId}/test_${Date.now()}.pdf`,
      file_name: 'test.pdf',
      file_size: 1024,
      mime_type: 'application/pdf',
      checksum: 'test_checksum_' + Date.now(),
      current_version: 1,
    })
    .select('id')
    .single();

  if (error || !data) {
    throw new Error(`Failed to create test document: ${error?.message}`);
  }

  return data.id;
}

/**
 * Grant a permission on a document and return the permission ID.
 */
export async function grantTestPermission(
  documentId: string,
  userRole: 'admin' | 'owner' | 'viewer',
  permissionLevel: 'read' | 'edit' = 'read',
  expiresAt?: string
): Promise<string> {
  const serviceClient = createServiceClient();
  const userId = await getUserId(userRole);
  const ownerId = await getUserId('owner');

  const { data, error } = await serviceClient
    .from('document_permissions')
    .insert({
      document_id: documentId,
      user_id: userId,
      permission_level: permissionLevel,
      granted_by: ownerId,
      expires_at: expiresAt || null,
    })
    .select('id')
    .single();

  if (error || !data) {
    throw new Error(`Failed to grant permission: ${error?.message}`);
  }

  return data.id;
}

/**
 * Revoke a permission immediately.
 */
export async function revokeTestPermission(permissionId: string): Promise<void> {
  const serviceClient = createServiceClient();
  const ownerId = await getUserId('owner');

  const { error } = await serviceClient
    .from('document_permissions')
    .update({
      revoked_at: new Date().toISOString(),
      revoked_by: ownerId,
    })
    .eq('id', permissionId);

  if (error) {
    throw new Error(`Failed to revoke permission: ${error.message}`);
  }
}

/**
 * Clean up a test document (hard delete for test cleanup only).
 */
export async function cleanupTestDocument(documentId: string): Promise<void> {
  const serviceClient = createServiceClient();

  // Delete permissions first
  await serviceClient
    .from('document_permissions')
    .delete()
    .eq('document_id', documentId);

  // Delete versions
  await serviceClient
    .from('document_versions')
    .delete()
    .eq('document_id', documentId);

  // Delete document
  await serviceClient
    .from('documents')
    .delete()
    .eq('id', documentId);
}

/**
 * Check if Supabase environment is configured for testing.
 */
export function isSupabaseConfigured(): boolean {
  return !!(SUPABASE_URL && SUPABASE_ANON_KEY && SERVICE_ROLE_KEY);
}
