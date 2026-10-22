import { createClient, isSupabaseConfigured } from '@/lib/supabase/server';
import { requireRole, AuthorizationError } from '@/lib/auth';
import { NextRequest, NextResponse } from 'next/server';
import { getStore } from '@/lib/local-db';
import type { AuditEvent, AuditAction, AuditResult } from '@/lib/types';

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
      let events: AuditEvent[] = [];

      try {
        const { getMongoDb, isMongoConfigured } = await import('@/lib/mongodb');
        if (isMongoConfigured()) {
          const db = await getMongoDb();
          const mongoAudit = await db.collection('audit').find({}).sort({ occurred_at: -1 }).toArray();
          if (mongoAudit.length > 0) {
            events = mongoAudit.map((e: Record<string, unknown>) => ({
              id: (e.id as string) || String(e._id),
              occurred_at: e.occurred_at as string,
              actor_id: (e.actor_id as string) || null,
              actor_email: (e.actor_email as string) || null,
              document_id: (e.document_id as string) || null,
              action: e.action as AuditAction,
              result: e.result as AuditResult,
              ip_hash: (e.ip_hash as string) || null,
              user_agent_hash: (e.user_agent_hash as string) || null,
              request_id: (e.request_id as string) || null,
              details_jsonb: (e.details_jsonb as Record<string, unknown>) || {},
              event_hash: (e.event_hash as string) || '',
              prev_hash: (e.prev_hash as string) || null,
            }));
          }
        }
      } catch {
        // fallback to in-memory store
      }

      if (events.length === 0) {
        events = getStore().audit.slice();
      }

      const AUTH_ACTIONS = ['login', 'login_failure', 'logout'];
      const DOC_ACTIONS = ['upload', 'download', 'preview', 'version_upload', 'update', 'delete', 'restore'];
      const PERM_ACTIONS = ['permission_grant', 'permission_revoke', 'share_link_created', 'share_link_revoked'];

      if (action && action !== 'all') {
        if (action === 'auth' || action === 'auth_events') {
          events = events.filter((e) => AUTH_ACTIONS.includes(e.action));
        } else if (action === 'documents') {
          events = events.filter((e) => DOC_ACTIONS.includes(e.action));
        } else if (action === 'permissions') {
          events = events.filter((e) => PERM_ACTIONS.includes(e.action));
        } else {
          events = events.filter((e) => e.action === action);
        }
      }

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
