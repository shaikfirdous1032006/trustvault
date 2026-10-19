import { createClient } from '@/lib/supabase/server';
import { requireAuth, checkDocumentPermission, getRequestMeta, AuthorizationError } from '@/lib/auth';
import { logAuditEvent } from '@/lib/audit';
import { NextRequest, NextResponse } from 'next/server';

type RouteParams = { params: Promise<{ id: string }> };

/**
 * GET /api/documents/:id/download
 * Generate a short-lived signed URL for document download.
 * Requires read permission. Fresh permission check on every request.
 * Never returns a permanent public URL.
 */
export async function GET(request: NextRequest, { params }: RouteParams) {
  const { id } = await params;
  const { ipAddress, userAgent } = await getRequestMeta();

  try {
    const user = await requireAuth();

    // Fresh permission check — no caching
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

    // Fetch document to get storage path
    const supabase = await createClient();
    const { data: doc, error } = await supabase
      .from('documents')
      .select('storage_path, file_name, mime_type')
      .eq('id', id)
      .eq('is_deleted', false)
      .single();

    if (error || !doc) {
      return NextResponse.json(
        { success: false, error: 'Document not found' },
        { status: 404 }
      );
    }

    // Generate short-lived signed URL (5 minutes)
    const { data: signedUrlData, error: signError } = await supabase.storage
      .from('documents')
      .createSignedUrl(doc.storage_path, 300); // 300 seconds = 5 minutes

    if (signError || !signedUrlData) {
      console.error('[DOWNLOAD] Signed URL error:', signError);
      return NextResponse.json(
        { success: false, error: 'Failed to generate download URL' },
        { status: 500 }
      );
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

    return NextResponse.json({
      success: true,
      data: {
        url: signedUrlData.signedUrl,
        file_name: doc.file_name,
        mime_type: doc.mime_type,
        expires_in: 300,
      },
    });
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
