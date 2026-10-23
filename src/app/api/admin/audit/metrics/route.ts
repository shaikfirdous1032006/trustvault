import { NextRequest, NextResponse } from 'next/server';
import { requireRole, AuthorizationError } from '@/lib/auth';
import { createAdminClient, isSupabaseConfigured } from '@/lib/supabase/server';
import { getStore } from '@/lib/local-db';
import { getMongoDb, isMongoConfigured } from '@/lib/mongodb';

export const dynamic = 'force-dynamic';

export interface AuditMetricsResponse {
  period: string;
  totalActivities: number;
  allowedCount: number;
  deniedCount: number;
  securityEventsCount: number;
  mostActiveUsers: Array<{ email: string; count: number }>;
  actionDistribution: Record<string, number>;
  generatedAt: string;
}

export async function GET(request: NextRequest) {
  try {
    await requireRole(['admin']);

    const { searchParams } = new URL(request.url);
    const period = searchParams.get('period') || '7d';

    let sinceDate: Date | null = null;
    const now = new Date();
    if (period === '24h') {
      sinceDate = new Date(now.getTime() - 24 * 60 * 60 * 1000);
    } else if (period === '7d') {
      sinceDate = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
    } else if (period === '30d') {
      sinceDate = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
    }

    const sinceIso = sinceDate ? sinceDate.toISOString() : null;

    let events: Array<{
      action: string;
      result: string;
      occurred_at: string;
      actor_email: string | null;
    }> = [];

    if (isSupabaseConfigured()) {
      const supabaseAdmin = createAdminClient();
      let query = supabaseAdmin
        .from('audit_events')
        .select('action, result, occurred_at, actor_email');

      if (sinceIso) {
        query = query.gte('occurred_at', sinceIso);
      }

      const { data, error } = await query;
      if (error) {
        return NextResponse.json(
          { success: false, error: 'Failed to fetch audit metrics from database' },
          { status: 500 }
        );
      }
      events = data || [];
    } else {
      if (isMongoConfigured()) {
        try {
          const db = await getMongoDb();
          const filter: Record<string, unknown> = {};
          if (sinceIso) {
            filter.occurred_at = { $gte: sinceIso };
          }
          const mongoEvents = await db
            .collection('audit')
            .find(filter)
            .project({ action: 1, result: 1, occurred_at: 1, actor_email: 1 })
            .toArray();

          events = mongoEvents.map((e: Record<string, unknown>) => ({
            action: String(e.action || 'action'),
            result: String(e.result || 'allowed'),
            occurred_at: String(e.occurred_at || new Date().toISOString()),
            actor_email: e.actor_email ? String(e.actor_email) : null,
          }));
        } catch {
          // fallback to store
        }
      }

      if (events.length === 0) {
        const store = getStore();
        events = store.audit.map((e) => ({
          action: e.action,
          result: e.result,
          occurred_at: e.occurred_at,
          actor_email: e.actor_email,
        }));
        if (sinceIso) {
          events = events.filter((e) => e.occurred_at >= sinceIso);
        }
      }
    }

    let allowedCount = 0;
    let deniedCount = 0;
    let securityEventsCount = 0;
    const actorCounts = new Map<string, number>();
    const actionCounts: Record<string, number> = {};

    for (const e of events) {
      if (e.result === 'allowed') allowedCount++;
      else deniedCount++;

      if (
        e.result === 'denied' ||
        e.action === 'security_alert' ||
        e.action === 'login_failure' ||
        e.action === 'share_link_denied'
      ) {
        securityEventsCount++;
      }

      const actor = e.actor_email || 'System';
      actorCounts.set(actor, (actorCounts.get(actor) || 0) + 1);

      actionCounts[e.action] = (actionCounts[e.action] || 0) + 1;
    }

    const mostActiveUsers = Array.from(actorCounts.entries())
      .map(([email, count]) => ({ email, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);

    const metrics: AuditMetricsResponse = {
      period,
      totalActivities: events.length,
      allowedCount,
      deniedCount,
      securityEventsCount,
      mostActiveUsers,
      actionDistribution: actionCounts,
      generatedAt: new Date().toISOString(),
    };

    return NextResponse.json({
      success: true,
      data: metrics,
    });
  } catch (err: unknown) {
    if (err instanceof AuthorizationError) {
      return NextResponse.json({ success: false, error: err.message }, { status: err.statusCode });
    }
    return NextResponse.json({ success: false, error: 'Internal server error' }, { status: 500 });
  }
}
