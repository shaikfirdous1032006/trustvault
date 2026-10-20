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

    if (!isSupabaseConfigured()) {
      const users = getStore().users.slice().sort((a, b) => b.created_at.localeCompare(a.created_at));
      return NextResponse.json({
        success: true,
        data: users.slice(offset, offset + pageSize),
        total: users.length,
        page,
        pageSize,
      });
    }

    const supabase = await createClient();
    const { data: users, count, error } = await supabase
      .from('users')
      .select('*', { count: 'exact' })
      .order('created_at', { ascending: false })
      .range(offset, offset + pageSize - 1);

    if (error) {
      return NextResponse.json({ success: false, error: 'Failed to fetch users' }, { status: 500 });
    }

    return NextResponse.json({
      success: true,
      data: users || [],
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
