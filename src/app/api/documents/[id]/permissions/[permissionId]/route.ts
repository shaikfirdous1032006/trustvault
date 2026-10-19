import { createClient } from '@/lib/supabase/server';
import { requireAuth, isDocumentOwner, getRequestMeta, AuthorizationError } from '@/lib/auth';
import { logAuditEvent } from '@/lib/audit';
import { NextRequest, NextResponse } from 'next/server';

type RouteParams = { params: Promise<{ id: string; permissionId: string }> };

/**
 * DELETE /api/documents/:id/permissions/:permissionId
 * Revoke a permission. Owner only.
 * Sets revoked_at = now() for immediate effect.
 */
export async function DELETE(request: NextRequest, { params }: RouteParams) {
  const { id, permissionId } = await params;
  const { ipAddress, userAgent } = await getRequestMeta();

  try {
    const user = await requireAuth();
    const ownerCheck = await isDocumentOwner(user.id, id);

    if (!ownerCheck) {
      await logAuditEvent({
        actorId: user.id,
        actorEmail: user.email,
        documentId: id,
        action: 'permission_revoke',
        result: 'denied',
        ipAddress,
        userAgent,
        details: { reason: 'Not document owner', permission_id: permissionId },
      });

      return NextResponse.json(
        { success: false, error: 'Only the document owner can revoke permissions' },
        { status: 403 }
      );
    }

    const supabase = await createClient();

    // Fetch the permission to get target user info for audit
    const { data: perm } = await supabase
      .from('document_permissions')
      .select('*, user:users!document_permissions_user_id_fkey(id, email)')
      .eq('id', permissionId)
      .eq('document_id', id)
      .single();

    if (!perm) {
      return NextResponse.json(
        { success: false, error: 'Permission not found' },
        { status: 404 }
      );
    }

    // Set revoked_at for immediate revocation
    const { error } = await supabase
      .from('document_permissions')
      .update({
        revoked_at: new Date().toISOString(),
        revoked_by: user.id,
      })
      .eq('id', permissionId)
      .eq('document_id', id);

    if (error) {
      return NextResponse.json(
        { success: false, error: 'Failed to revoke permission' },
        { status: 500 }
      );
    }

    await logAuditEvent({
      actorId: user.id,
      actorEmail: user.email,
      documentId: id,
      action: 'permission_revoke',
      result: 'allowed',
      ipAddress,
      userAgent,
      details: {
        permission_id: permissionId,
        target_user_email: perm.user?.email,
        permission_level: perm.permission_level,
      },
    });

    return NextResponse.json({ success: true, message: 'Permission revoked' });
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
