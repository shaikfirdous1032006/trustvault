import { createClient, isSupabaseConfigured } from '@/lib/supabase/server';
import { requireAuth, getRequestMeta } from '@/lib/auth';
import { logAuditEvent } from '@/lib/audit';
import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { createHash, randomUUID } from 'crypto';
import {
  evaluateDocumentPermission,
  validateUpload,
  sanitizeFilename,
  generateStorageKey,
} from '@/lib/permission';
import {
  getStore,
  mutateStore,
  putFile,
  withUser,
} from '@/lib/local-db';

const uploadSchema = z.object({
  title: z.string().min(1).max(255),
  description: z.string().max(1000).optional(),
  category: z.string().min(1).max(50),
});

function visibleLocalDocuments(userId: string) {
  const store = getStore();
  return store.documents
    .filter((doc) => {
      const decision = evaluateDocumentPermission({
        document: doc,
        grants: store.permissions.filter((p) => p.document_id === doc.id),
        userId,
        requiredLevel: 'read',
      });
      return decision.allowed;
    })
    .map((doc) => withUser(doc, store));
}

export async function GET(request: NextRequest) {
  const { ipAddress, userAgent } = await getRequestMeta();

  try {
    const user = await requireAuth();
    const searchParams = request.nextUrl.searchParams;
    const search = searchParams.get('search');
    const category = searchParams.get('category');
    const owner = searchParams.get('owner');
    const dateFrom = searchParams.get('dateFrom');
    const dateTo = searchParams.get('dateTo');
    const page = parseInt(searchParams.get('page') || '1');
    const pageSize = Math.min(parseInt(searchParams.get('pageSize') || '20'), 100);

    if (!isSupabaseConfigured()) {
      let docs = visibleLocalDocuments(user.id);

      if (search) {
        const q = search.toLowerCase();
        docs = docs.filter(
          (d) =>
            d.title.toLowerCase().includes(q) ||
            (d.description || '').toLowerCase().includes(q) ||
            d.file_name.toLowerCase().includes(q) ||
            (d.owner?.email || '').toLowerCase().includes(q) ||
            (d.owner?.full_name || '').toLowerCase().includes(q)
        );
      }
      if (category && category !== 'all') {
        docs = docs.filter((d) => d.category === category);
      }
      if (owner) {
        const q = owner.toLowerCase();
        docs = docs.filter(
          (d) =>
            (d.owner?.email || '').toLowerCase().includes(q) ||
            (d.owner?.full_name || '').toLowerCase().includes(q)
        );
      }
      if (dateFrom) {
        docs = docs.filter((d) => d.created_at >= dateFrom);
      }
      if (dateTo) {
        docs = docs.filter((d) => d.created_at <= `${dateTo}T23:59:59.999Z`);
      }

      docs.sort((a, b) => b.created_at.localeCompare(a.created_at));
      const total = docs.length;
      const offset = (page - 1) * pageSize;
      const pageDocs = docs.slice(offset, offset + pageSize);

      if (search) {
        await logAuditEvent({
          actorId: user.id,
          actorEmail: user.email,
          action: 'search',
          result: 'allowed',
          ipAddress,
          userAgent,
          details: { search_term: search, results_count: pageDocs.length },
        });
      }

      return NextResponse.json({
        success: true,
        data: pageDocs,
        total,
        page,
        pageSize,
      });
    }

    const supabase = await createClient();
    const offset = (page - 1) * pageSize;

    let query = supabase
      .from('documents')
      .select('*, owner:users!documents_owner_id_fkey(id, email, full_name)', { count: 'exact' })
      .eq('is_deleted', false)
      .order('created_at', { ascending: false })
      .range(offset, offset + pageSize - 1);

    if (search) {
      query = query.or(`title.ilike.%${search}%,description.ilike.%${search}%,file_name.ilike.%${search}%`);
    }

    if (category && category !== 'all') {
      query = query.eq('category', category);
    }

    if (dateFrom) {
      query = query.gte('created_at', dateFrom);
    }

    if (dateTo) {
      query = query.lte('created_at', `${dateTo}T23:59:59.999Z`);
    }

    const { data, count, error } = await query;

    if (error) {
      return NextResponse.json(
        { success: false, error: 'Failed to fetch documents' },
        { status: 500 }
      );
    }

    let rows = data || [];
    if (owner) {
      const q = owner.toLowerCase();
      rows = rows.filter((d: { owner?: { email?: string; full_name?: string | null } }) => {
        const email = d.owner?.email || '';
        const name = d.owner?.full_name || '';
        return email.toLowerCase().includes(q) || name.toLowerCase().includes(q);
      });
    }

    if (search) {
      await logAuditEvent({
        actorId: user.id,
        actorEmail: user.email,
        action: 'search',
        result: 'allowed',
        ipAddress,
        userAgent,
        details: { search_term: search, results_count: rows.length },
      });
    }

    return NextResponse.json({
      success: true,
      data: rows,
      total: owner ? rows.length : count || 0,
      page,
      pageSize,
    });
  } catch (err: unknown) {
    const error = err as { statusCode?: number; message?: string };
    if (error.statusCode) {
      return NextResponse.json(
        { success: false, error: error.message },
        { status: error.statusCode }
      );
    }
    return NextResponse.json(
      { success: false, error: 'Internal server error' },
      { status: 500 }
    );
  }
}

export async function POST(request: NextRequest) {
  const { ipAddress, userAgent } = await getRequestMeta();

  try {
    const user = await requireAuth();

    if (user.role !== 'owner' && user.role !== 'admin') {
      await logAuditEvent({
        actorId: user.id,
        actorEmail: user.email,
        action: 'upload',
        result: 'denied',
        ipAddress,
        userAgent,
        details: { reason: 'Insufficient role' },
      });

      return NextResponse.json(
        { success: false, error: 'Only owners can upload documents' },
        { status: 403 }
      );
    }

    const formData = await request.formData();
    const file = formData.get('file') as File | null;
    const title = formData.get('title') as string;
    const description = formData.get('description') as string | null;
    const category = formData.get('category') as string;

    const metaParsed = uploadSchema.safeParse({ title, description, category });
    if (!metaParsed.success) {
      return NextResponse.json(
        { success: false, error: 'Invalid document metadata', details: metaParsed.error.flatten() },
        { status: 400 }
      );
    }

    if (!file) {
      return NextResponse.json(
        { success: false, error: 'File is required' },
        { status: 400 }
      );
    }

    const arrayBuffer = await file.arrayBuffer();
    const buffer = Buffer.from(arrayBuffer);

    const uploadError = validateUpload({
      type: file.type,
      size: file.size,
      name: file.name,
      buffer,
    });
    if (uploadError) {
      return NextResponse.json({ success: false, error: uploadError }, { status: 400 });
    }

    const { safeName } = sanitizeFilename(file.name);
    const ext = file.name.includes('.') ? file.name.split('.').pop() : '';
    const storagePath = generateStorageKey(user.id, ext);
    const checksum = createHash('sha256').update(buffer).digest('hex');

    if (!isSupabaseConfigured()) {
      putFile(storagePath, buffer);
      const now = new Date().toISOString();
      const doc = await mutateStore((store) => {
        const created = {
          id: randomUUID(),
          owner_id: user.id,
          title: metaParsed.data.title,
          description: metaParsed.data.description || null,
          category: metaParsed.data.category,
          storage_path: storagePath,
          file_name: safeName,
          file_size: file.size,
          mime_type: file.type,
          checksum,
          current_version: 1,
          is_deleted: false,
          deleted_at: null,
          deleted_by: null,
          created_at: now,
          updated_at: now,
        };
        store.documents.push(created);
        store.versions.push({
          id: randomUUID(),
          document_id: created.id,
          version_number: 1,
          storage_path: storagePath,
          file_name: safeName,
          file_size: file.size,
          mime_type: file.type,
          checksum,
          uploaded_by: user.id,
          change_notes: 'Initial upload',
          created_at: now,
        });
        return created;
      });

      await logAuditEvent({
        actorId: user.id,
        actorEmail: user.email,
        documentId: doc.id,
        action: 'upload',
        result: 'allowed',
        ipAddress,
        userAgent,
        details: {
          file_name: safeName,
          file_size: file.size,
          mime_type: file.type,
          checksum,
        },
      });

      return NextResponse.json({ success: true, data: doc }, { status: 201 });
    }

    const supabase = await createClient();

    const { error: storageError } = await supabase.storage
      .from('documents')
      .upload(storagePath, arrayBuffer, {
        contentType: file.type,
        upsert: false,
      });

    if (storageError) {
      console.error('[UPLOAD] Storage error:', storageError);
      return NextResponse.json(
        { success: false, error: 'Failed to upload file' },
        { status: 500 }
      );
    }

    const { data: doc, error: dbError } = await supabase
      .from('documents')
      .insert({
        owner_id: user.id,
        title: metaParsed.data.title,
        description: metaParsed.data.description || null,
        category: metaParsed.data.category,
        storage_path: storagePath,
        file_name: safeName,
        file_size: file.size,
        mime_type: file.type,
        checksum,
        current_version: 1,
      })
      .select()
      .single();

    if (dbError || !doc) {
      await supabase.storage.from('documents').remove([storagePath]);
      return NextResponse.json(
        { success: false, error: 'Failed to create document record' },
        { status: 500 }
      );
    }

    await supabase.from('document_versions').insert({
      document_id: doc.id,
      version_number: 1,
      storage_path: storagePath,
      file_name: file.name,
      file_size: file.size,
      mime_type: file.type,
      checksum,
      uploaded_by: user.id,
      change_notes: 'Initial upload',
    });

    await logAuditEvent({
      actorId: user.id,
      actorEmail: user.email,
      documentId: doc.id,
      action: 'upload',
      result: 'allowed',
      ipAddress,
      userAgent,
      details: {
        file_name: file.name,
        file_size: file.size,
        mime_type: file.type,
        checksum,
      },
    });

    return NextResponse.json({ success: true, data: doc }, { status: 201 });
  } catch (err: unknown) {
    const error = err as { statusCode?: number; message?: string };
    if (error.statusCode) {
      return NextResponse.json(
        { success: false, error: error.message },
        { status: error.statusCode }
      );
    }
    return NextResponse.json(
      { success: false, error: 'Internal server error' },
      { status: 500 }
    );
  }
}
