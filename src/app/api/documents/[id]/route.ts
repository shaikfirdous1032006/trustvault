import { createClient, isSupabaseConfigured } from '@/lib/supabase/server';
import { requireAuth, checkDocumentPermission, isDocumentOwner, getRequestMeta, AuthorizationError } from '@/lib/auth';
import { logAuditEvent } from '@/lib/audit';
import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { getDocument, getStore, mutateStore, withUser } from '@/lib/local-db';

type RouteParams = { params: Promise<{ id: string }> };

const updateSchema = z.object({
  title: z.string().min(1).max(255).optional(),
  description: z.string().max(1000).optional(),
  category: z.string().min(1).max(50).optional(),
});

function denyNotFound() {
  return NextResponse.json({ success: false, error: 'Document not found' }, { status: 404 });
}

export async function GET(request: NextRequest, { params }: RouteParams) {
  const { id } = await params;
  const { ipAddress, userAgent } = await getRequestMeta();

  try {
    const user = await requireAuth();
    const permission = await checkDocumentPermission(user.id, id, 'read');

    if (!permission.allowed) {
      await logAuditEvent({
        actorId: user.id,
        actorEmail: user.email,
        documentId: id,
        action: 'preview',
        result: 'denied',
        ipAddress,
        userAgent,
        details: { reason: permission.reason },
      });
      return NextResponse.json(
        { success: false, error: 'Access denied' },
        { status: 403 }
      );
    }

    const owner = await isDocumentOwner(user.id, id);
    const canEdit = owner || (await checkDocumentPermission(user.id, id, 'edit')).allowed;

    if (!isSupabaseConfigured()) {
      const store = getStore();
      const local = getDocument(id);
      const demoFallback = {
        id,
        owner_id: 'user-owner',
        title: 'Secret Financial Plan',
        description: 'Highly confidential.',
        category: 'financial',
        storage_path: 'user-owner/secret_plan.pdf',
        file_name: 'secret_plan.pdf',
        file_size: 1024,
        mime_type: 'application/pdf',
        checksum: 'abc',
        current_version: 1,
        is_deleted: false,
        deleted_at: null,
        deleted_by: null,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
        owner: { id: 'user-owner', email: 'owner@example.com', full_name: 'Document Owner', role: 'owner' as const, is_active: true, created_at: '', updated_at: '' },
      };
      const doc = local ? withUser(local, store) : demoFallback;

      await logAuditEvent({
        actorId: user.id,
        actorEmail: user.email,
        documentId: id,
        action: 'preview',
        result: 'allowed',
        ipAddress,
        userAgent,
      });

      return NextResponse.json({
        success: true,
        data: {
          ...doc,
          access: { is_owner: owner, can_edit: canEdit, can_delete: owner },
        },
      });
    }

    const supabase = await createClient();
    const { data: doc, error } = await supabase
      .from('documents')
      .select('*, owner:users!documents_owner_id_fkey(id, email, full_name)')
      .eq('id', id)
      .single();

    if (error || !doc) {
      return denyNotFound();
    }

    await logAuditEvent({
      actorId: user.id,
      actorEmail: user.email,
      documentId: id,
      action: 'preview',
      result: 'allowed',
      ipAddress,
      userAgent,
    });

    return NextResponse.json({
      success: true,
      data: { ...doc, access: { is_owner: owner, can_edit: canEdit, can_delete: owner } },
    });
  } catch (err: unknown) {
    const error = err as { statusCode?: number; message?: string };
    if (error?.statusCode) {
      return NextResponse.json({ success: false, error: error.message || 'Access denied' }, { status: error.statusCode });
    }
    if (err instanceof AuthorizationError) {
      return NextResponse.json({ success: false, error: err.message }, { status: err.statusCode });
    }
    return NextResponse.json({ success: false, error: 'Internal server error' }, { status: 500 });
  }
}

export async function PATCH(request: NextRequest, { params }: RouteParams) {
  const { id } = await params;
  const { ipAddress, userAgent } = await getRequestMeta();

  try {
    const user = await requireAuth();
    const permission = await checkDocumentPermission(user.id, id, 'edit');
    const ownerCheck = await isDocumentOwner(user.id, id);

    if (!permission.allowed && !ownerCheck) {
      await logAuditEvent({
        actorId: user.id,
        actorEmail: user.email,
        documentId: id,
        action: 'update',
        result: 'denied',
        ipAddress,
        userAgent,
        details: { reason: permission.reason },
      });
      return NextResponse.json(
        { success: false, error: 'Access denied' },
        { status: 403 }
      );
    }

    const body = await request.json();
    const parsed = updateSchema.safeParse(body);

    if (!parsed.success) {
      return NextResponse.json(
        { success: false, error: 'Invalid update data', details: parsed.error.flatten() },
        { status: 400 }
      );
    }

    if (!isSupabaseConfigured()) {
      const doc = await mutateStore((store) => {
        const found = store.documents.find((d) => d.id === id && !d.is_deleted);
        if (!found) return null;
        Object.assign(found, parsed.data, { updated_at: new Date().toISOString() });
        return found;
      });
      if (!doc) {
        return NextResponse.json({ success: false, error: 'Failed to update document' }, { status: 500 });
      }
      await logAuditEvent({
        actorId: user.id,
        actorEmail: user.email,
        documentId: id,
        action: 'update',
        result: 'allowed',
        ipAddress,
        userAgent,
        details: { changes: parsed.data },
      });
      return NextResponse.json({ success: true, data: doc });
    }

    const supabase = await createClient();
    const { data: doc, error } = await supabase
      .from('documents')
      .update(parsed.data)
      .eq('id', id)
      .select()
      .single();

    if (error || !doc) {
      return NextResponse.json({ success: false, error: 'Failed to update document' }, { status: 500 });
    }

    await logAuditEvent({
      actorId: user.id,
      actorEmail: user.email,
      documentId: id,
      action: 'update',
      result: 'allowed',
      ipAddress,
      userAgent,
      details: { changes: parsed.data },
    });

    return NextResponse.json({ success: true, data: doc });
  } catch (err: unknown) {
    const error = err as { statusCode?: number; message?: string };
    if (error?.statusCode) {
      return NextResponse.json({ success: false, error: error.message || 'Access denied' }, { status: error.statusCode });
    }
    if (err instanceof AuthorizationError) {
      return NextResponse.json({ success: false, error: err.message }, { status: err.statusCode });
    }
    return NextResponse.json({ success: false, error: 'Internal server error' }, { status: 500 });
  }
}

export async function DELETE(request: NextRequest, { params }: RouteParams) {
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
        action: 'delete',
        result: 'denied',
        ipAddress,
        userAgent,
        details: { reason: 'Not document owner' },
      });
      return NextResponse.json(
        { success: false, error: 'Only the document owner can delete' },
        { status: 403 }
      );
    }

    if (!isSupabaseConfigured()) {
      await mutateStore((store) => {
        const found = store.documents.find((d) => d.id === id);
        if (found) {
          found.is_deleted = true;
          found.deleted_at = new Date().toISOString();
          found.deleted_by = user.id;
        }
      });
      await logAuditEvent({
        actorId: user.id,
        actorEmail: user.email,
        documentId: id,
        action: 'delete',
        result: 'allowed',
        ipAddress,
        userAgent,
      });
      return NextResponse.json({ success: true, message: 'Document deleted' });
    }

    const supabase = await createClient();
    const { error } = await supabase
      .from('documents')
      .update({
        is_deleted: true,
        deleted_at: new Date().toISOString(),
        deleted_by: user.id,
      })
      .eq('id', id);

    if (error) {
      return NextResponse.json({ success: false, error: 'Failed to delete document' }, { status: 500 });
    }

    await logAuditEvent({
      actorId: user.id,
      actorEmail: user.email,
      documentId: id,
      action: 'delete',
      result: 'allowed',
      ipAddress,
      userAgent,
    });

    return NextResponse.json({ success: true, message: 'Document deleted' });
  } catch (err: unknown) {
    const error = err as { statusCode?: number; message?: string };
    if (error?.statusCode) {
      return NextResponse.json({ success: false, error: error.message || 'Access denied' }, { status: error.statusCode });
    }
    if (err instanceof AuthorizationError) {
      return NextResponse.json({ success: false, error: err.message }, { status: err.statusCode });
    }
    return NextResponse.json({ success: false, error: 'Internal server error' }, { status: 500 });
  }
}
