import { createClient, createAdminClient } from '@/lib/supabase/server';
import type { User, UserRole, PermissionLevel } from '@/lib/types';
import { headers } from 'next/headers';

/**
 * Get the authenticated user from the current request.
 * Returns null if not authenticated — never trust client-supplied identity.
 */
export async function getAuthenticatedUser(): Promise<User | null> {
  const supabase = await createClient();
  const { data: { user: authUser } } = await supabase.auth.getUser();

  if (!authUser) return null;

  const { data: profile } = await supabase
    .from('users')
    .select('*')
    .eq('id', authUser.id)
    .single();

  return profile as User | null;
}

/**
 * Require an authenticated user. Throws if not authenticated.
 */
export async function requireAuth(): Promise<User> {
  const user = await getAuthenticatedUser();
  if (!user) {
    throw new AuthorizationError('Authentication required', 401);
  }
  if (!user.is_active) {
    throw new AuthorizationError('Account is deactivated', 403);
  }
  return user;
}

/**
 * Require a specific role. Throws if user doesn't have the role.
 */
export async function requireRole(allowedRoles: UserRole[]): Promise<User> {
  const user = await requireAuth();
  if (!allowedRoles.includes(user.role)) {
    throw new AuthorizationError(
      `Insufficient role. Required: ${allowedRoles.join(', ')}`,
      403
    );
  }
  return user;
}

/**
 * Check if a user has active permission on a document.
 * This is the application-level check (defense in depth — RLS is the final boundary).
 * 
 * IMPORTANT: This checks revoked_at and expires_at on every call.
 * No caching of authorization decisions.
 */
export async function checkDocumentPermission(
  userId: string,
  documentId: string,
  requiredLevel: PermissionLevel = 'read'
): Promise<{ allowed: boolean; reason: string }> {
  const supabaseAdmin = createAdminClient();

  // Check if document exists and is not deleted
  const { data: doc } = await supabaseAdmin
    .from('documents')
    .select('id, owner_id, is_deleted')
    .eq('id', documentId)
    .single();

  if (!doc) {
    return { allowed: false, reason: 'Document not found' };
  }

  if (doc.is_deleted) {
    return { allowed: false, reason: 'Document has been deleted' };
  }

  // Owner always has full access to their own documents
  if (doc.owner_id === userId) {
    return { allowed: true, reason: 'Document owner' };
  }

  // Check for active permission grant
  const { data: permissions } = await supabaseAdmin
    .from('document_permissions')
    .select('*')
    .eq('document_id', documentId)
    .eq('user_id', userId)
    .is('revoked_at', null);

  if (!permissions || permissions.length === 0) {
    return { allowed: false, reason: 'No permission grant exists' };
  }

  // Filter for valid (non-expired) permissions with sufficient level
  interface PermissionRow {
    permission_level: string;
    expires_at: string | null;
  }
  const validPermission = (permissions as unknown as PermissionRow[]).find((p) => {
    // Check expiry
    if (p.expires_at && new Date(p.expires_at) <= new Date()) {
      return false;
    }
    // Check level
    if (requiredLevel === 'edit') {
      return p.permission_level === 'edit';
    }
    // Read access: either 'read' or 'edit' grants read
    return p.permission_level === 'read' || p.permission_level === 'edit';
  });

  if (!validPermission) {
    return {
      allowed: false,
      reason: 'Permission expired or insufficient level',
    };
  }

  return { allowed: true, reason: `Has ${validPermission.permission_level} permission` };
}

/**
 * Check if a user is the owner of a document.
 */
export async function isDocumentOwner(
  userId: string,
  documentId: string
): Promise<boolean> {
  const supabaseAdmin = createAdminClient();
  const { data: doc } = await supabaseAdmin
    .from('documents')
    .select('owner_id')
    .eq('id', documentId)
    .single();

  return doc?.owner_id === userId;
}

/**
 * Extract request metadata for audit logging.
 */
export async function getRequestMeta(): Promise<{
  ipAddress: string | null;
  userAgent: string | null;
}> {
  const headersList = await headers();
  return {
    ipAddress:
      headersList.get('x-forwarded-for')?.split(',')[0]?.trim() ||
      headersList.get('x-real-ip') ||
      null,
    userAgent: headersList.get('user-agent') || null,
  };
}

/**
 * Custom error for authorization failures.
 */
export class AuthorizationError extends Error {
  constructor(
    message: string,
    public statusCode: number = 403
  ) {
    super(message);
    this.name = 'AuthorizationError';
  }
}
