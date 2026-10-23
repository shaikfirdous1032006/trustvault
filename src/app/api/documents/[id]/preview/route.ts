import { createClient, createAdminClient, isSupabaseConfigured } from '@/lib/supabase/server';
import { requireAuth, checkDocumentPermission, getRequestMeta, AuthorizationError } from '@/lib/auth';
import { logAuditEvent } from '@/lib/audit';
import { NextRequest, NextResponse } from 'next/server';
import { getDocument, readFileBytes } from '@/lib/local-db';

type RouteParams = { params: Promise<{ id: string }> };

/**
 * GET /api/documents/:id/preview
 * Streams the document for inline display (PDF, CSV, image, plain text).
 * Validates session, verifies read permission, and writes audit event.
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

    if (!isSupabaseConfigured()) {
      const doc = getDocument(id);
      if (!doc || doc.is_deleted) {
        return NextResponse.json({ success: false, error: 'Document not found' }, { status: 404 });
      }

      const rawBytes = readFileBytes(doc.storage_path);
      if (!rawBytes) {
        return NextResponse.json({ success: false, error: 'Document file missing from store' }, { status: 500 });
      }

      await logAuditEvent({
        actorId: user.id,
        actorEmail: user.email,
        documentId: id,
        action: 'preview',
        result: 'allowed',
        ipAddress,
        userAgent,
        details: {
          file_name: doc.file_name,
          mime_type: doc.mime_type,
          file_size: doc.file_size,
        },
      });

      const mimeType = doc.mime_type || (doc.file_name.endsWith('.pdf') ? 'application/pdf' : doc.file_name.endsWith('.csv') ? 'text/csv' : 'text/plain');

      return new NextResponse(new Blob([new Uint8Array(rawBytes)]), {
        headers: {
          'Content-Type': mimeType,
          'Content-Disposition': `inline; filename="${encodeURIComponent(doc.file_name)}"`,
          'Content-Length': String(rawBytes.byteLength),
          'X-Content-Type-Options': 'nosniff',
          'Cache-Control': 'private, no-cache, no-store, must-revalidate',
        },
      });
    }

    // Supabase Mode
    const supabase = await createClient();
    const { data: doc, error: docError } = await supabase
      .from('documents')
      .select('*')
      .eq('id', id)
      .eq('is_deleted', false)
      .single();

    if (docError || !doc) {
      return NextResponse.json({ success: false, error: 'Document not found' }, { status: 404 });
    }

    const supabaseAdmin = createAdminClient();
    const { data: fileData, error: downloadError } = await supabaseAdmin.storage
      .from('documents')
      .download(doc.storage_path);

    if (downloadError || !fileData) {
      return NextResponse.json({ success: false, error: 'File download failed' }, { status: 500 });
    }

    await logAuditEvent({
      actorId: user.id,
      actorEmail: user.email,
      documentId: id,
      action: 'preview',
      result: 'allowed',
      ipAddress,
      userAgent,
      details: {
        file_name: doc.file_name,
        mime_type: doc.mime_type,
        file_size: doc.file_size,
      },
    });

    const mimeType = doc.mime_type || (doc.file_name.endsWith('.pdf') ? 'application/pdf' : doc.file_name.endsWith('.csv') ? 'text/csv' : 'text/plain');
    const arrayBuffer = await fileData.arrayBuffer();

    return new NextResponse(new Blob([arrayBuffer]), {
      headers: {
        'Content-Type': mimeType,
        'Content-Disposition': `inline; filename="${encodeURIComponent(doc.file_name)}"`,
        'Content-Length': String(arrayBuffer.byteLength),
        'X-Content-Type-Options': 'nosniff',
        'Cache-Control': 'private, no-cache, no-store, must-revalidate',
      },
    });
  } catch (err: unknown) {
    if (err instanceof AuthorizationError) {
      return NextResponse.json({ success: false, error: err.message }, { status: err.statusCode });
    }
    return NextResponse.json({ success: false, error: 'Internal server error' }, { status: 500 });
  }
}
