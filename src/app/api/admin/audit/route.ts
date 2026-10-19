import { createClient } from '@/lib/supabase/server';
import { requireRole, AuthorizationError } from '@/lib/auth';
import { NextRequest, NextResponse } from 'next/server';

/**
 * GET /api/admin/audit
 * Admin-only: view platform-wide audit events in metadata form.
 * Supports filtering by action, result, date range.
 */
export async function GET(request: NextRequest) {
  try {
    const user = await requireRole(['admin']);
    const supabase = await createClient();

    const searchParams = request.nextUrl.searchParams;
    const page = parseInt(searchParams.get('page') || '1');
    const pageSize = Math.min(parseInt(searchParams.get('pageSize') || '50'), 100);
    const offset = (page - 1) * pageSize;
    const action = searchParams.get('action');
    const result = searchParams.get('result');
    const startDate = searchParams.get('startDate');
    const endDate = searchParams.get('endDate');

    let query = supabase
      .from('audit_events')
      .select('*', { count: 'exact' })
      .order('occurred_at', { ascending: false })
      .range(offset, offset + pageSize - 1);

    if (action) {
      query = query.eq('action', action);
    }

    if (result) {
      query = query.eq('result', result);
    }

    if (startDate) {
      query = query.gte('occurred_at', startDate);
    }

    if (endDate) {
      query = query.lte('occurred_at', endDate);
    }

    const { data: events, count, error } = await query;

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
