import { createClient } from '@/lib/supabase/server';
import { requireRole, AuthorizationError } from '@/lib/auth';
import { NextRequest, NextResponse } from 'next/server';

/**
 * GET /api/admin/users
 * Admin-only: list all users with their roles and status.
 */
export async function GET(request: NextRequest) {
  try {
    const user = await requireRole(['admin']);
    const supabase = await createClient();

    const searchParams = request.nextUrl.searchParams;
    const page = parseInt(searchParams.get('page') || '1');
    const pageSize = Math.min(parseInt(searchParams.get('pageSize') || '50'), 100);
    const offset = (page - 1) * pageSize;

    const { data: users, count, error } = await supabase
      .from('users')
      .select('*', { count: 'exact' })
      .order('created_at', { ascending: false })
      .range(offset, offset + pageSize - 1);

    if (error) {
      return NextResponse.json(
        { success: false, error: 'Failed to fetch users' },
        { status: 500 }
      );
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
