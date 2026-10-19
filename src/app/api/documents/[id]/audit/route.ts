import { createClient } from '@/lib/supabase/server';
import { requireAuth, isDocumentOwner, getRequestMeta, AuthorizationError } from '@/lib/auth';
import { NextRequest, NextResponse } from 'next/server';

type RouteParams = { params: Promise<{ id: string }> };

/**
 * GET /api/documents/:id/audit
 * Get audit trail for a specific document.
 * Document owner can see full audit trail for their documents.
 * Admin can see audit trail in metadata form.
 */
export async function GET(request: NextRequest, { params }: RouteParams) {
  const { id } = await params;

  try {
    const user = await requireAuth();
    const ownerCheck = await isDocumentOwner(user.id, id);

    if (!ownerCheck && user.role !== 'admin') {
      return NextResponse.json(
        { success: false, error: 'Only the document owner or admin can view the audit trail' },
        { status: 403 }
      );
    }

    const supabase = await createClient();
    const searchParams = request.nextUrl.searchParams;
    const page = parseInt(searchParams.get('page') || '1');
    const pageSize = Math.min(parseInt(searchParams.get('pageSize') || '50'), 100);
    const offset = (page - 1) * pageSize;

    const { data: events, count, error } = await supabase
      .from('audit_events')
      .select('*', { count: 'exact' })
      .eq('document_id', id)
      .order('occurred_at', { ascending: false })
      .range(offset, offset + pageSize - 1);

    if (error) {
      return NextResponse.json(
        { success: false, error: 'Failed to fetch audit events' },
        { status: 500 }
      );
    }

    return NextResponse.json({
      success: true,
      data: events || [],
      total: count || 0,
      page,
      pageSize,
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
