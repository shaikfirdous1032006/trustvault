import { csrfRejection } from '@/lib/security';
import { createClient, isSupabaseConfigured } from '@/lib/supabase/server';
import { requireAuth, checkDocumentPermission, isDocumentOwner, getRequestMeta, AuthorizationError } from '@/lib/auth';
import { logAuditEvent } from '@/lib/audit';
import { NextRequest, NextResponse } from 'next/server';
import { createHash, randomUUID } from 'crypto';
import { validateUpload, sanitizeFilename, generateStorageKey } from '@/lib/permission';
import { getStore, mutateStore, putFile } from '@/lib/local-db';

type RouteParams = { params: Promise<{ id: string }> };

function denyNotFound() {
  return NextResponse.json({ success: false, error: 'Document not found' }, { status: 404 });
}

export async function POST(request: NextRequest, { params }: RouteParams) {
  const crossOrigin = csrfRejection(request);
  if (crossOrigin) return crossOrigin;
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
      return NextResponse.json({ success: false, error: 'File is required' }, { status: 400 });
    }

    const arrayBuffer = await file.arrayBuffer();
    const buffer = Buffer.from(arrayBuffer);

    const invalid = validateUpload({
      type: file.type,
      size: file.size,
      name: file.name,
      buffer,
    });
    if (invalid) {
      return NextResponse.json({ success: false, error: invalid }, { status: 400 });
    }

    const { safeName } = sanitizeFilename(file.name);
    const checksum = createHash('sha256').update(buffer).digest('hex');

    if (!isSupabaseConfigured()) {
      const version = await mutateStore((store) => {
        const doc = store.documents.find((d) => d.id === id && !d.is_deleted);
        if (!doc) return null;
        const nextVersion = doc.current_version + 1;
        const ext = file.name.includes('.') ? file.name.split('.').pop() : '';
        const storagePath = generateStorageKey(doc.owner_id, `v${nextVersion}.${ext}`);
        putFile(storagePath, buffer);
        const now = new Date().toISOString();
        const created = {
          id: randomUUID(),
          document_id: id,
          version_number: nextVersion,
          storage_path: storagePath,
          file_name: safeName,
          file_size: file.size,
          mime_type: file.type,
          checksum,
          uploaded_by: user.id,
          change_notes: changeNotes,
          created_at: now,
        };
        store.versions.push(created);
        doc.current_version = nextVersion;
        doc.storage_path = storagePath;
        doc.file_name = safeName;
        doc.file_size = file.size;
        doc.mime_type = file.type;
        doc.checksum = checksum;
        doc.updated_at = now;
        return created;
      });

      if (!version) return denyNotFound();

      await logAuditEvent({
        actorId: user.id,
        actorEmail: user.email,
        documentId: id,
        action: 'version_upload',
        result: 'allowed',
        ipAddress,
        userAgent,
        details: { version_number: version.version_number, file_name: file.name, checksum, change_notes: changeNotes },
      });

      return NextResponse.json({ success: true, data: version }, { status: 201 });
    }

    const supabase = await createClient();
    const { data: doc } = await supabase
      .from('documents')
      .select('current_version, owner_id')
      .eq('id', id)
      .single();

    if (!doc) return denyNotFound();

    const nextVersion = doc.current_version + 1;
    const ext = file.name.includes('.') ? file.name.split('.').pop() : '';
    const storagePath = generateStorageKey(doc.owner_id, `v${nextVersion}.${ext}`);

    const { error: uploadError } = await supabase.storage
      .from('documents')
      .upload(storagePath, arrayBuffer, { contentType: file.type, upsert: false });

    if (uploadError) {
      return NextResponse.json({ success: false, error: 'Failed to upload file' }, { status: 500 });
    }

    const { data: version, error: versionError } = await supabase
      .from('document_versions')
      .insert({
        document_id: id,
        version_number: nextVersion,
        storage_path: storagePath,
        file_name: safeName,
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
      return NextResponse.json({ success: false, error: 'Failed to create version record' }, { status: 500 });
    }

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
      details: { version_number: nextVersion, file_name: file.name, checksum, change_notes: changeNotes },
    });

    return NextResponse.json({ success: true, data: version }, { status: 201 });
  } catch (err: unknown) {
    if (err instanceof AuthorizationError) {
      return NextResponse.json({ success: false, error: err.message }, { status: err.statusCode });
    }
    return NextResponse.json({ success: false, error: 'Internal server error' }, { status: 500 });
  }
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
        details: { reason: permission.reason, resource: 'versions' },
      });
      return NextResponse.json(
        { success: false, error: 'Access denied' },
        { status: 403 }
      );
    }

    if (!isSupabaseConfigured()) {
      const store = getStore();
      const versions = store.versions
        .filter((v) => v.document_id === id)
        .map((v) => ({ ...v, uploader: store.users.find((u) => u.id === v.uploaded_by) }))
        .sort((a, b) => b.version_number - a.version_number);
      return NextResponse.json({ success: true, data: versions });
    }

    const supabase = await createClient();
    const { data: versions, error } = await supabase
      .from('document_versions')
      .select('*, uploader:users!document_versions_uploaded_by_fkey(id, email, full_name)')
      .eq('document_id', id)
      .order('version_number', { ascending: false });

    if (error) {
      return NextResponse.json({ success: false, error: 'Failed to fetch versions' }, { status: 500 });
    }

    return NextResponse.json({ success: true, data: versions || [] });
  } catch (err: unknown) {
    if (err instanceof AuthorizationError) {
      return NextResponse.json({ success: false, error: err.message }, { status: err.statusCode });
    }
    return NextResponse.json({ success: false, error: 'Internal server error' }, { status: 500 });
  }
}
