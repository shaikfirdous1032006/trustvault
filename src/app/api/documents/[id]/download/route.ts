import { createAdminClient, isSupabaseConfigured } from '@/lib/supabase/server';
import { requireAuth, checkDocumentPermission, getRequestMeta, AuthorizationError } from '@/lib/auth';
import { logAuditEvent } from '@/lib/audit';
import { NextRequest, NextResponse } from 'next/server';
import { getDocument, readFileBytes } from '@/lib/local-db';

type RouteParams = { params: Promise<{ id: string }> };

/**
 * GET /api/documents/:id/download
 * Streams the file after a fresh permission check.
 * No durable URL is issued, so revocation is immediate.
 */
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
        action: 'download',
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

    if (!isSupabaseConfigured()) {
      const doc = getDocument(id);
      if (!doc || doc.is_deleted) {
        return NextResponse.json({ success: false, error: 'Document not found' }, { status: 404 });
      }
      const bytes = readFileBytes(doc.storage_path);
      if (!bytes) {
        return NextResponse.json({ success: false, error: 'File missing' }, { status: 500 });
      }

      await logAuditEvent({
        actorId: user.id,
        actorEmail: user.email,
        documentId: id,
        action: 'download',
        result: 'allowed',
        ipAddress,
        userAgent,
        details: { file_name: doc.file_name },
      });

      return new NextResponse(new Uint8Array(bytes), {
        headers: {
          'Content-Type': doc.mime_type || 'application/octet-stream',
          'Content-Disposition': `attachment; filename="${doc.file_name.replace(/"/g, '')}"`,
          'Cache-Control': 'no-store',
        },
      });
    }

    const supabaseAdmin = createAdminClient();
    const { data: doc, error } = await supabaseAdmin
      .from('documents')
      .select('storage_path, file_name, mime_type')
      .eq('id', id)
      .eq('is_deleted', false)
      .single();

    if (error || !doc) {
      return NextResponse.json({ success: false, error: 'Document not found' }, { status: 404 });
    }

    const { data: file, error: downloadError } = await supabaseAdmin.storage
      .from('documents')
      .download(doc.storage_path);

    if (downloadError || !file) {
      return NextResponse.json({ success: false, error: 'Failed to fetch file' }, { status: 500 });
    }

    await logAuditEvent({
      actorId: user.id,
      actorEmail: user.email,
      documentId: id,
      action: 'download',
      result: 'allowed',
      ipAddress,
      userAgent,
      details: { file_name: doc.file_name },
    });

    const arrayBuffer = await file.arrayBuffer();
    return new NextResponse(new Uint8Array(arrayBuffer), {
      headers: {
        'Content-Type': doc.mime_type || 'application/octet-stream',
        'Content-Disposition': `attachment; filename="${doc.file_name.replace(/"/g, '')}"`,
        'Cache-Control': 'no-store',
      },
    });
  } catch (err: unknown) {
    if (err instanceof AuthorizationError) {
      return NextResponse.json({ success: false, error: err.message }, { status: err.statusCode });
    }
    return NextResponse.json({ success: false, error: 'Internal server error' }, { status: 500 });
  }
}
