
import {
  createAdminClient,
  isSupabaseConfigured,
} from '@/lib/supabase/server';
import type { User, UserRole, PermissionLevel } from '@/lib/types';
import { headers, cookies } from 'next/headers';
import { evaluateDocumentPermission } from '@/lib/permission';
import {
  getDocument,
  getPermissionsForDocument,
  findUserById,
} from '@/lib/local-db';
import { SESSION_COOKIE, verifySessionToken } from '@/lib/session';

/**
 * Gets the authenticated user from a verified server-side session.
 * Never trusts identity supplied by a client request.
 */
export async function getAuthenticatedUser(): Promise<User | null> {
  try {
    const cookieStore = await cookies();
    const token = cookieStore.get(SESSION_COOKIE)?.value;
    if (!token) {
  return null;
}

const sessionUser = await verifySessionToken(token);

    if (sessionUser) {
      if (!isSupabaseConfigured()) {
        const storedUser = findUserById(sessionUser.id);

        if (storedUser) {
          return storedUser;
        }

        // Resilient fallback to verified cryptographically-signed session payload
        return {
          id: sessionUser.id,
          email: sessionUser.email,
          role: sessionUser.role,
          full_name: sessionUser.full_name,
          is_active: sessionUser.is_active ?? true,
          created_at: new Date(sessionUser.iat * 1000).toISOString(),
          updated_at: new Date(sessionUser.iat * 1000).toISOString(),
        };
      }

      const { createClient } = await import('@/lib/supabase/server');
      const supabase = await createClient();

      const {
        data: { user: authUser },
        error: authError,
      } = await supabase.auth.getUser();

      if (authError || !authUser || authUser.id !== sessionUser.id) {
        return null;
      }

      const { data: profile, error: profileError } = await supabase
        .from('users')
        .select('*')
        .eq('id', authUser.id)
        .single();

      if (profileError || !profile) {
        return null;
      }

      return profile as User;
    }
  } catch {
    // Continue to the configured Supabase authentication fallback.
  }

  if (!isSupabaseConfigured()) {
    return null;
  }

  try {
    const { createClient } = await import('@/lib/supabase/server');
    const supabase = await createClient();
    const {
      data: { user: authUser },
      error: authError,
    } = await supabase.auth.getUser();

    if (authError || !authUser) {
      return null;
    }

    const { data: profile, error: profileError } = await supabase
      .from('users')
      .select('*')
      .eq('id', authUser.id)
      .single();

    if (profileError || !profile || !profile.is_active) {
      return null;
    }

    return profile as User;
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

export async function requireRole(
  allowedRoles: UserRole[]
): Promise<User> {
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
 * Checks document access on every request.
 * Database errors fail closed: they never grant access.
 */
export async function checkDocumentPermission(
  userId: string,
  documentId: string,
  requiredLevel: PermissionLevel = 'read'
): Promise<{ allowed: boolean; reason: string }> {
  if (!userId || !documentId) {
    return {
      allowed: false,
      reason: 'User ID and document ID are required',
    };
  }

  if (!isSupabaseConfigured()) {
    try {
      const doc = getDocument(documentId) ?? null;
      const grants = getPermissionsForDocument(documentId);

      return evaluateDocumentPermission({
        document: doc
          ? {
              id: doc.id,
              owner_id: doc.owner_id,
              is_deleted: doc.is_deleted,
            }
          : null,
        grants,
        userId,
        requiredLevel,
      });
    } catch {
      return {
        allowed: false,
        reason: 'Unable to verify document permissions',
      };
    }
  }

  try {
    const supabaseAdmin = createAdminClient();

    const { data: doc, error: documentError } = await supabaseAdmin
      .from('documents')
      .select('id, owner_id, is_deleted')
      .eq('id', documentId)
      .maybeSingle();

    if (documentError) {
      return {
        allowed: false,
        reason: 'Unable to verify document access',
      };
    }

    if (!doc) {
      return {
        allowed: false,
        reason: 'Document not found',
      };
    }

    const { data: permissions, error: permissionsError } =
      await supabaseAdmin
        .from('document_permissions')
        .select(
          'user_id, permission_level, revoked_at, expires_at, max_access_count, access_count'
        )
        .eq('document_id', documentId);

    if (permissionsError || !permissions) {
      return {
        allowed: false,
        reason: 'Unable to verify document permissions',
      };
    }

    return evaluateDocumentPermission({
      document: {
        id: doc.id,
        owner_id: doc.owner_id,
        is_deleted: doc.is_deleted,
      },
      grants: permissions,
      userId,
      requiredLevel,
    });
  } catch {
    return {
      allowed: false,
      reason: 'Unable to verify document permissions',
    };
  }
}

/**
 * Checks ownership independently of role.
 * Admin status alone does not make a user the document owner.
 */
export async function isDocumentOwner(
  userId: string,
  documentId: string
): Promise<boolean> {
  if (!userId || !documentId) {
    return false;
  }

  if (!isSupabaseConfigured()) {
    try {
      const doc = getDocument(documentId);
      return Boolean(
        doc &&
          !doc.is_deleted &&
          doc.owner_id === userId
      );
    } catch {
      return false;
    }
  }

  try {
    const supabaseAdmin = createAdminClient();

    const { data: doc, error } = await supabaseAdmin
      .from('documents')
      .select('owner_id, is_deleted')
      .eq('id', documentId)
      .maybeSingle();

    if (error || !doc || doc.is_deleted) {
      return false;
    }

    return doc.owner_id === userId;
  } catch {
    return false;
  }
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