import { csrfRejection } from '@/lib/security';
import { createClient, isSupabaseConfigured } from '@/lib/supabase/server';
import { requireAuth, isDocumentOwner, getRequestMeta, AuthorizationError } from '@/lib/auth';
import { logAuditEvent } from '@/lib/audit';
import { NextRequest, NextResponse } from 'next/server';
import { mutateStore } from '@/lib/local-db';
import { z } from 'zod';

type RouteParams = { params: Promise<{ id: string; permissionId: string }> };

const updatePermSchema = z.object({
  permission_level: z.enum(['read', 'edit']).optional(),
  expires_at: z.string().datetime().optional().nullable(),
  max_access_count: z.number().int().positive().optional().nullable(),
  watermark_enabled: z.boolean().optional(),
});

export async function DELETE(request: NextRequest, { params }: RouteParams) {
  const crossOrigin = csrfRejection(request);
  if (crossOrigin) return crossOrigin;
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

    if (!isSupabaseConfigured()) {
      const perm = await mutateStore((store) => {
        const found = store.permissions.find((p) => p.id === permissionId && p.document_id === id);
        if (!found) return null;
        found.revoked_at = new Date().toISOString();
        found.revoked_by = user.id;
        return found;
      });

      if (!perm) {
        return NextResponse.json({ success: false, error: 'Permission not found' }, { status: 404 });
      }

      const target = (await import('@/lib/local-db')).findUserById(perm.user_id);

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
          target_user_email: target?.email,
          permission_level: perm.permission_level,
        },
      });

      return NextResponse.json({ success: true, message: 'Permission revoked' });
    }

    const supabase = await createClient();
    const { data: perm } = await supabase
      .from('document_permissions')
      .select('*, user:users!document_permissions_user_id_fkey(id, email)')
      .eq('id', permissionId)
      .eq('document_id', id)
      .single();

    if (!perm) {
      return NextResponse.json({ success: false, error: 'Permission not found' }, { status: 404 });
    }

    const { error } = await supabase
      .from('document_permissions')
      .update({
        revoked_at: new Date().toISOString(),
        revoked_by: user.id,
      })
      .eq('id', permissionId)
      .eq('document_id', id);

    if (error) {
      return NextResponse.json({ success: false, error: 'Failed to revoke permission' }, { status: 500 });
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
      return NextResponse.json({ success: false, error: err.message }, { status: err.statusCode });
    }
    return NextResponse.json({ success: false, error: 'Internal server error' }, { status: 500 });
  }
}

export async function PATCH(request: NextRequest, { params }: RouteParams) {
  const crossOrigin = csrfRejection(request);
  if (crossOrigin) return crossOrigin;
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
        action: 'permission_update',
        result: 'denied',
        ipAddress,
        userAgent,
        details: { reason: 'Not document owner', permission_id: permissionId },
      });
      return NextResponse.json(
        { success: false, error: 'Only the document owner can update permissions' },
        { status: 403 }
      );
    }

    const body = await request.json();
    const parsed = updatePermSchema.safeParse(body);
    if (!parsed.success) {
      return NextResponse.json(
        { success: false, error: 'Invalid permission update payload', details: parsed.error.flatten() },
        { status: 400 }
      );
    }

    if (!isSupabaseConfigured()) {
      const perm = await mutateStore((store) => {
        const found = store.permissions.find((p) => p.id === permissionId && p.document_id === id);
        if (!found || found.revoked_at) return null;
        if (parsed.data.permission_level) found.permission_level = parsed.data.permission_level;
        if (parsed.data.expires_at !== undefined) found.expires_at = parsed.data.expires_at;
        if (parsed.data.max_access_count !== undefined) found.max_access_count = parsed.data.max_access_count;
        if (parsed.data.watermark_enabled !== undefined) found.watermark_enabled = parsed.data.watermark_enabled;
        return found;
      });

      if (!perm) {
        return NextResponse.json({ success: false, error: 'Permission not found or revoked' }, { status: 404 });
      }

      const target = (await import('@/lib/local-db')).findUserById(perm.user_id);

      await logAuditEvent({
        actorId: user.id,
        actorEmail: user.email,
        documentId: id,
        action: 'permission_update',
        result: 'allowed',
        ipAddress,
        userAgent,
        targetResourceType: 'permission',
        targetResourceId: permissionId,
        details: {
          permission_id: permissionId,
          target_user_email: target?.email,
          permission_level: perm.permission_level,
          updates: parsed.data,
        },
      });

      return NextResponse.json({ success: true, data: perm });
    }

    const supabase = await createClient();
    const { data: existing } = await supabase
      .from('document_permissions')
      .select('*, user:users!document_permissions_user_id_fkey(id, email)')
      .eq('id', permissionId)
      .eq('document_id', id)
      .single();

    if (!existing || existing.revoked_at) {
      return NextResponse.json({ success: false, error: 'Permission not found or revoked' }, { status: 404 });
    }

    const updates: Record<string, unknown> = {};
    if (parsed.data.permission_level) updates.permission_level = parsed.data.permission_level;
    if (parsed.data.expires_at !== undefined) updates.expires_at = parsed.data.expires_at;

    const { data: updated, error } = await supabase
      .from('document_permissions')
      .update(updates)
      .eq('id', permissionId)
      .eq('document_id', id)
      .select('*, user:users!document_permissions_user_id_fkey(id, email)')
      .single();

    if (error || !updated) {
      return NextResponse.json({ success: false, error: 'Failed to update permission' }, { status: 500 });
    }

    await logAuditEvent({
      actorId: user.id,
      actorEmail: user.email,
      documentId: id,
      action: 'permission_update',
      result: 'allowed',
      ipAddress,
      userAgent,
      targetResourceType: 'permission',
      targetResourceId: permissionId,
      details: {
        permission_id: permissionId,
        target_user_email: existing.user?.email,
        permission_level: updated.permission_level,
        updates: parsed.data,
      },
    });

    return NextResponse.json({ success: true, data: updated });
  } catch (err: unknown) {
    if (err instanceof AuthorizationError) {
      return NextResponse.json({ success: false, error: err.message }, { status: err.statusCode });
    }
    return NextResponse.json({ success: false, error: 'Internal server error' }, { status: 500 });
  }
}

