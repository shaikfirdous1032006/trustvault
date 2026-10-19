import { createClient } from '@/lib/supabase/server';
import { requireAuth, checkDocumentPermission, isDocumentOwner, getRequestMeta, AuthorizationError } from '@/lib/auth';
import { logAuditEvent } from '@/lib/audit';
import { NextRequest, NextResponse } from 'next/server';
import { createHash } from 'crypto';

type RouteParams = { params: Promise<{ id: string }> };

/**
 * POST /api/documents/:id/versions
 * Upload a new version of a document.
 * Requires edit permission or owner.
 */
export async function POST(request: NextRequest, { params }: RouteParams) {
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
        action: 'version_upload',
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

    const formData = await request.formData();
    const file = formData.get('file') as File | null;
    const changeNotes = formData.get('change_notes') as string | null;

    if (!file) {
      return NextResponse.json(
        { success: false, error: 'File is required' },
        { status: 400 }
      );
    }

    if (file.size > 52428800) {
      return NextResponse.json(
        { success: false, error: 'File size exceeds 50MB limit' },
        { status: 400 }
      );
    }

    // Compute checksum
    const arrayBuffer = await file.arrayBuffer();
    const checksum = createHash('sha256')
      .update(Buffer.from(arrayBuffer))
      .digest('hex');

    // Get current document to determine next version number
    const supabase = await createClient();
    const { data: doc } = await supabase
      .from('documents')
      .select('current_version, owner_id')
      .eq('id', id)
      .single();

    if (!doc) {
      return NextResponse.json(
        { success: false, error: 'Document not found' },
        { status: 404 }
      );
    }

    const nextVersion = doc.current_version + 1;
    const storagePath = `${doc.owner_id}/${Date.now()}_v${nextVersion}_${file.name}`;

    // Upload file
    const { error: uploadError } = await supabase.storage
      .from('documents')
      .upload(storagePath, arrayBuffer, {
        contentType: file.type,
        upsert: false,
      });

    if (uploadError) {
      return NextResponse.json(
        { success: false, error: 'Failed to upload file' },
        { status: 500 }
      );
    }

    // Create version record
    const { data: version, error: versionError } = await supabase
      .from('document_versions')
      .insert({
        document_id: id,
        version_number: nextVersion,
        storage_path: storagePath,
        file_name: file.name,
        file_size: file.size,
        mime_type: file.type,
        checksum,
        uploaded_by: user.id,
        change_notes: changeNotes,
      })
      .select()
      .single();

    if (versionError) {
      await supabase.storage.from('documents').remove([storagePath]);
      return NextResponse.json(
        { success: false, error: 'Failed to create version record' },
        { status: 500 }
      );
    }

    // Update document with new version info
    await supabase
      .from('documents')
      .update({
        current_version: nextVersion,
        storage_path: storagePath,
        file_name: file.name,
        file_size: file.size,
        mime_type: file.type,
        checksum,
      })
      .eq('id', id);

    await logAuditEvent({
      actorId: user.id,
      actorEmail: user.email,
      documentId: id,
      action: 'version_upload',
      result: 'allowed',
      ipAddress,
      userAgent,
      details: {
        version_number: nextVersion,
        file_name: file.name,
        checksum,
        change_notes: changeNotes,
      },
    });

    return NextResponse.json({ success: true, data: version }, { status: 201 });
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
 * GET /api/documents/:id/versions (handled by the same route file)
 * List all versions. Requires read permission.
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
        details: { reason: permission.reason, resource: 'versions' },
      });

      return NextResponse.json(
        { success: false, error: 'Access denied' },
        { status: 403 }
      );
    }

    const supabase = await createClient();
    const { data: versions, error } = await supabase
      .from('document_versions')
      .select('*, uploader:users!document_versions_uploaded_by_fkey(id, email, full_name)')
      .eq('document_id', id)
      .order('version_number', { ascending: false });

    if (error) {
      return NextResponse.json(
        { success: false, error: 'Failed to fetch versions' },
        { status: 500 }
      );
    }

    return NextResponse.json({ success: true, data: versions || [] });
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
