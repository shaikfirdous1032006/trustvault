import { createAdminClient, isSupabaseConfigured } from '@/lib/supabase/server';
import type { User, UserRole, PermissionLevel } from '@/lib/types';
import { headers, cookies } from 'next/headers';
import { evaluateDocumentPermission } from '@/lib/permission';
import { getDocument, getPermissionsForDocument, findUserById } from '@/lib/local-db';
import { SESSION_COOKIE, verifySessionToken } from '@/lib/session';

/**
 * Get the authenticated user from the current request.
 * Returns null if not authenticated — never trust client-supplied identity.
 */
export async function getAuthenticatedUser(): Promise<User | null> {
  try {
    const cookieStore = await cookies();
    const token = cookieStore.get(SESSION_COOKIE)?.value;
    const sessionUser = await verifySessionToken(token);
    if (sessionUser) {
      if (!isSupabaseConfigured()) {
        return findUserById(sessionUser.id) ?? sessionUser;
      }
      return sessionUser;
    }
  } catch {
    // cookies() unavailable
  }

  if (!isSupabaseConfigured()) return null;

  try {
    const supabase = await (await import('@/lib/supabase/server')).createClient();
    const { data: { user: authUser } } = await supabase.auth.getUser();

    if (!authUser) return null;

    const { data: profile } = await supabase
      .from('users')
      .select('*')
      .eq('id', authUser.id)
      .single();

    return profile as User | null;
  } catch {
    return null;
  }
}

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
 * Application-level check — RLS is the final boundary when Supabase is on.
 * Checks revoked_at and expires_at on every call. No caching.
 */
export async function checkDocumentPermission(
  userId: string,
  documentId: string,
  requiredLevel: PermissionLevel = 'read'
): Promise<{ allowed: boolean; reason: string }> {
  if (!isSupabaseConfigured()) {
    const doc = getDocument(documentId) ?? null;
    const grants = getPermissionsForDocument(documentId);
    return evaluateDocumentPermission({
      document: doc
        ? { id: doc.id, owner_id: doc.owner_id, is_deleted: doc.is_deleted }
        : null,
      grants,
      userId,
      requiredLevel,
    });
  }

  const supabaseAdmin = createAdminClient();

  const { data: doc } = await supabaseAdmin
    .from('documents')
    .select('id, owner_id, is_deleted')
    .eq('id', documentId)
    .single();

  const { data: permissions } = await supabaseAdmin
    .from('document_permissions')
    .select('user_id, permission_level, revoked_at, expires_at')
    .eq('document_id', documentId);

  return evaluateDocumentPermission({
    document: doc ?? null,
    grants: (permissions as Array<{
      user_id: string;
      permission_level: string;
      revoked_at: string | null;
      expires_at: string | null;
    }>) || [],
    userId,
    requiredLevel,
  });
}

export async function isDocumentOwner(
  userId: string,
  documentId: string
): Promise<boolean> {
  if (!isSupabaseConfigured()) {
    const doc = getDocument(documentId);
    return doc?.owner_id === userId;
  }

  const supabaseAdmin = createAdminClient();
  const { data: doc } = await supabaseAdmin
    .from('documents')
    .select('owner_id')
    .eq('id', documentId)
    .single();

  return doc?.owner_id === userId;
}

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

export class AuthorizationError extends Error {
  constructor(
    message: string,
    public statusCode: number = 403
  ) {
    super(message);
    this.name = 'AuthorizationError';
  }
}
