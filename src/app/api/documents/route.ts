import { createClient } from '@/lib/supabase/server';
import { requireAuth, getRequestMeta } from '@/lib/auth';
import { logAuditEvent } from '@/lib/audit';
import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { createHash } from 'crypto';

const uploadSchema = z.object({
  title: z.string().min(1).max(255),
  description: z.string().max(1000).optional(),
  category: z.string().min(1).max(50),
});

/**
 * GET /api/documents
 * Returns documents the authenticated user can see.
 * RLS ensures only permitted documents are returned.
 * Supports: ?search=, ?category=, ?page=, ?pageSize=
 */
export async function GET(request: NextRequest) {
  const { ipAddress, userAgent } = await getRequestMeta();

  try {
    const user = await requireAuth();
    const supabase = await createClient();

    const searchParams = request.nextUrl.searchParams;
    const search = searchParams.get('search');
    const category = searchParams.get('category');
    const page = parseInt(searchParams.get('page') || '1');
    const pageSize = Math.min(parseInt(searchParams.get('pageSize') || '20'), 100);
    const offset = (page - 1) * pageSize;

    let query = supabase
      .from('documents')
      .select('*, owner:users!documents_owner_id_fkey(id, email, full_name)', { count: 'exact' })
      .eq('is_deleted', false)
      .order('created_at', { ascending: false })
      .range(offset, offset + pageSize - 1);

    if (search) {
      query = query.or(`title.ilike.%${search}%,description.ilike.%${search}%`);
    }

    if (category && category !== 'all') {
      query = query.eq('category', category);
    }

    const { data, count, error } = await query;

    if (error) {
      return NextResponse.json(
        { success: false, error: 'Failed to fetch documents' },
        { status: 500 }
      );
    }

    // Log search if search term was used
    if (search) {
      await logAuditEvent({
        actorId: user.id,
        actorEmail: user.email,
        action: 'search',
        result: 'allowed',
        ipAddress,
        userAgent,
        details: { search_term: search, results_count: data?.length || 0 },
      });
    }

    return NextResponse.json({
      success: true,
      data: data || [],
      total: count || 0,
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

/**
 * POST /api/documents
 * Upload a new document. Only owners and admins can upload.
 * Validates file type, computes checksum, stores in private bucket.
 */
export async function POST(request: NextRequest) {
  const { ipAddress, userAgent } = await getRequestMeta();

  try {
    const user = await requireAuth();

    // Only owner and admin roles can upload
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

    // Validate metadata
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

    // Validate file size (50MB max)
    if (file.size > 52428800) {
      return NextResponse.json(
        { success: false, error: 'File size exceeds 50MB limit' },
        { status: 400 }
      );
    }

    // Compute file checksum
    const arrayBuffer = await file.arrayBuffer();
    const checksum = createHash('sha256')
      .update(Buffer.from(arrayBuffer))
      .digest('hex');

    // Upload to private storage bucket
    // Path: {user_id}/{timestamp}_{filename}
    const storagePath = `${user.id}/${Date.now()}_${file.name}`;
    const supabase = await createClient();

    const { error: uploadError } = await supabase.storage
      .from('documents')
      .upload(storagePath, arrayBuffer, {
        contentType: file.type,
        upsert: false,
      });

    if (uploadError) {
      console.error('[UPLOAD] Storage error:', uploadError);
      return NextResponse.json(
        { success: false, error: 'Failed to upload file' },
        { status: 500 }
      );
    }

    // Create document record
    const { data: doc, error: dbError } = await supabase
      .from('documents')
      .insert({
        owner_id: user.id,
        title: metaParsed.data.title,
        description: metaParsed.data.description || null,
        category: metaParsed.data.category,
        storage_path: storagePath,
        file_name: file.name,
        file_size: file.size,
        mime_type: file.type,
        checksum,
        current_version: 1,
      })
      .select()
      .single();

    if (dbError || !doc) {
      // Rollback: delete uploaded file
      await supabase.storage.from('documents').remove([storagePath]);
      return NextResponse.json(
        { success: false, error: 'Failed to create document record' },
        { status: 500 }
      );
    }

    // Create initial version record
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

    // Audit log
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
