import { createClient, createAdminClient } from '@/lib/supabase/server';
import { requireAuth, isDocumentOwner, getRequestMeta, AuthorizationError } from '@/lib/auth';
import { logAuditEvent } from '@/lib/audit';
import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';

type RouteParams = { params: Promise<{ id: string }> };

const grantSchema = z.object({
  user_email: z.string().email('Invalid email'),
  permission_level: z.enum(['read', 'edit']),
  expires_at: z.string().datetime().optional(),
});

/**
 * GET /api/documents/:id/permissions
 * List permissions for a document. Owner only.
 */
export async function GET(request: NextRequest, { params }: RouteParams) {
  const { id } = await params;

  try {
    const user = await requireAuth();
    const ownerCheck = await isDocumentOwner(user.id, id);

    // Admin can also view permissions (for audit purposes)
    if (!ownerCheck && user.role !== 'admin') {
      return NextResponse.json(
        { success: false, error: 'Only the document owner can view permissions' },
        { status: 403 }
      );
    }

    const supabase = await createClient();
    const { data: permissions, error } = await supabase
      .from('document_permissions')
      .select('*, user:users!document_permissions_user_id_fkey(id, email, full_name), grantor:users!document_permissions_granted_by_fkey(id, email, full_name)')
      .eq('document_id', id)
      .order('granted_at', { ascending: false });

    if (error) {
      return NextResponse.json(
        { success: false, error: 'Failed to fetch permissions' },
        { status: 500 }
      );
    }

    return NextResponse.json({ success: true, data: permissions || [] });
  } catch (err: unknown) {
    if (err instanceof AuthorizationError) {
      return NextResponse.json(
        { success: false, error: err.message },
        { status: err.statusCode }
      );
    }
    return NextResponse.json(
      { success: false, error: 'Internal server error' },
      { status: 500 }
    );
  }
}

/**
 * POST /api/documents/:id/permissions
 * Grant permission to a user. Owner only.
 */
export async function POST(request: NextRequest, { params }: RouteParams) {
  const { id } = await params;
  const { ipAddress, userAgent } = await getRequestMeta();

  try {
    const user = await requireAuth();
    const ownerCheck = await isDocumentOwner(user.id, id);

    if (!ownerCheck) {
      await logAuditEvent({
        actorId: user.id,
        actorEmail: user.email,
        documentId: id,
        action: 'permission_grant',
        result: 'denied',
        ipAddress,
        userAgent,
        details: { reason: 'Not document owner' },
      });

      return NextResponse.json(
        { success: false, error: 'Only the document owner can grant permissions' },
        { status: 403 }
      );
    }

    const body = await request.json();
    const parsed = grantSchema.safeParse(body);

    if (!parsed.success) {
      return NextResponse.json(
        { success: false, error: 'Invalid permission data', details: parsed.error.flatten() },
        { status: 400 }
      );
    }

    // Look up the target user by email
    const supabaseAdmin = createAdminClient();
    const { data: targetUser } = await supabaseAdmin
      .from('users')
      .select('id, email')
      .eq('email', parsed.data.user_email)
      .single();

    if (!targetUser) {
      return NextResponse.json(
        { success: false, error: 'User not found' },
        { status: 404 }
      );
    }

    // Cannot grant permission to yourself
    if (targetUser.id === user.id) {
      return NextResponse.json(
        { success: false, error: 'Cannot grant permission to yourself' },
        { status: 400 }
      );
    }

    // Check if permission already exists (and is active)
    const { data: existing } = await supabaseAdmin
      .from('document_permissions')
      .select('id, revoked_at')
      .eq('document_id', id)
      .eq('user_id', targetUser.id)
      .eq('permission_level', parsed.data.permission_level)
      .is('revoked_at', null)
      .maybeSingle();

    if (existing) {
      return NextResponse.json(
        { success: false, error: 'Permission already exists for this user' },
        { status: 409 }
      );
    }

    // Grant permission
    const supabase = await createClient();
    const { data: perm, error } = await supabase
      .from('document_permissions')
      .insert({
        document_id: id,
        user_id: targetUser.id,
        permission_level: parsed.data.permission_level,
        granted_by: user.id,
        expires_at: parsed.data.expires_at || null,
      })
      .select('*, user:users!document_permissions_user_id_fkey(id, email, full_name)')
      .single();

    if (error) {
      // Handle unique constraint violation — may have a revoked permission
      if (error.code === '23505') {
        // Upsert: re-activate by clearing revoked_at
        const { data: reactivated, error: upsertError } = await supabase
          .from('document_permissions')
          .update({
            revoked_at: null,
            revoked_by: null,
            granted_by: user.id,
            granted_at: new Date().toISOString(),
            expires_at: parsed.data.expires_at || null,
          })
          .eq('document_id', id)
          .eq('user_id', targetUser.id)
          .eq('permission_level', parsed.data.permission_level)
          .select()
          .single();

        if (upsertError) {
          return NextResponse.json(
            { success: false, error: 'Failed to grant permission' },
            { status: 500 }
          );
        }

        await logAuditEvent({
          actorId: user.id,
          actorEmail: user.email,
          documentId: id,
          action: 'permission_grant',
          result: 'allowed',
          ipAddress,
          userAgent,
          details: {
            target_user_email: parsed.data.user_email,
            permission_level: parsed.data.permission_level,
            reactivated: true,
          },
        });

        return NextResponse.json({ success: true, data: reactivated }, { status: 201 });
      }

      return NextResponse.json(
        { success: false, error: 'Failed to grant permission' },
        { status: 500 }
      );
    }

    await logAuditEvent({
      actorId: user.id,
      actorEmail: user.email,
      documentId: id,
      action: 'permission_grant',
      result: 'allowed',
      ipAddress,
      userAgent,
      details: {
        target_user_email: parsed.data.user_email,
        permission_level: parsed.data.permission_level,
      },
    });

    return NextResponse.json({ success: true, data: perm }, { status: 201 });
  } catch (err: unknown) {
    if (err instanceof AuthorizationError) {
      return NextResponse.json(
        { success: false, error: err.message },
        { status: err.statusCode }
      );
    }
    return NextResponse.json(
      { success: false, error: 'Internal server error' },
      { status: 500 }
    );
  }
}
