import { createClient, isSupabaseConfigured } from '@/lib/supabase/server';
import { requireRole, AuthorizationError } from '@/lib/auth';
import { NextRequest, NextResponse } from 'next/server';
import { getStore } from '@/lib/local-db';

export async function GET(request: NextRequest) {
  try {
    await requireRole(['admin']);
    const searchParams = request.nextUrl.searchParams;
    const page = parseInt(searchParams.get('page') || '1');
    const pageSize = Math.min(parseInt(searchParams.get('pageSize') || '50'), 100);
    const offset = (page - 1) * pageSize;
    const action = searchParams.get('action');
    const result = searchParams.get('result');
    const startDate = searchParams.get('startDate');
    const endDate = searchParams.get('endDate');

    if (!isSupabaseConfigured()) {
      let events = getStore().audit.slice();
      if (action && action !== 'all') events = events.filter((e) => e.action === action);
      if (result && result !== 'all') events = events.filter((e) => e.result === result);
      if (startDate) events = events.filter((e) => e.occurred_at >= startDate);
      if (endDate) events = events.filter((e) => e.occurred_at <= endDate);
      events.sort((a, b) => b.occurred_at.localeCompare(a.occurred_at));
      return NextResponse.json({
        success: true,
        data: events.slice(offset, offset + pageSize),
        total: events.length,
        page,
        pageSize,
      });
    }

    const supabase = await createClient();
    let query = supabase
      .from('audit_events')
      .select('*', { count: 'exact' })
      .order('occurred_at', { ascending: false })
      .range(offset, offset + pageSize - 1);

    if (action) query = query.eq('action', action);
    if (result) query = query.eq('result', result);
    if (startDate) query = query.gte('occurred_at', startDate);
    if (endDate) query = query.lte('occurred_at', endDate);

    const { data: events, count, error } = await query;

    if (error) {
      return NextResponse.json({ success: false, error: 'Failed to fetch audit events' }, { status: 500 });
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
      return NextResponse.json({ success: false, error: err.message }, { status: err.statusCode });
    }
    return NextResponse.json({ success: false, error: 'Internal server error' }, { status: 500 });
  }
}
