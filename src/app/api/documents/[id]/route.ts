import { createClient } from '@/lib/supabase/server';
import { requireAuth, checkDocumentPermission, isDocumentOwner, getRequestMeta, AuthorizationError } from '@/lib/auth';
import { logAuditEvent } from '@/lib/audit';
import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';

type RouteParams = { params: Promise<{ id: string }> };

const updateSchema = z.object({
  title: z.string().min(1).max(255).optional(),
  description: z.string().max(1000).optional(),
  category: z.string().min(1).max(50).optional(),
});

/**
 * GET /api/documents/:id
 * Get document details. Requires read permission.
 */
export async function GET(request: NextRequest, { params }: RouteParams) {
  const { id } = await params;
  const { ipAddress, userAgent } = await getRequestMeta();

  try {
    const user = await requireAuth();

    // Application-level permission check (defense in depth)
    // Non-negotiable rule: Admins cannot read a document without explicit permission
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

    const supabase = await createClient();
    const { data: doc, error } = await supabase
      .from('documents')
      .select('*, owner:users!documents_owner_id_fkey(id, email, full_name)')
      .eq('id', id)
      .single();

    if (error || !doc) {
      return NextResponse.json(
        { success: false, error: 'Document not found' },
        { status: 404 }
      );
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

    return NextResponse.json({ success: true, data: doc });
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
 * PATCH /api/documents/:id
 * Update document metadata. Requires edit permission or owner.
 */
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

    const supabase = await createClient();
    const { data: doc, error } = await supabase
      .from('documents')
      .update(parsed.data)
      .eq('id', id)
      .select()
      .single();

    if (error || !doc) {
      return NextResponse.json(
        { success: false, error: 'Failed to update document' },
        { status: 500 }
      );
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
 * DELETE /api/documents/:id
 * Soft-delete a document. Owner only.
 */
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
      return NextResponse.json(
        { success: false, error: 'Failed to delete document' },
        { status: 500 }
      );
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
