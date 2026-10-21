import { requireRole, AuthorizationError } from '@/lib/auth';
import { NextRequest, NextResponse } from 'next/server';
import { isSupabaseConfigured } from '@/lib/supabase/server';
import { getStore } from '@/lib/local-db';
import { detectSuspiciousActivity, DETECTION_RULES } from '@/lib/security-alerts';

/**
 * GET /api/admin/alerts
 * Returns security alerts detected from recent audit events.
 * Admin-only endpoint.
 */
export async function GET(_request?: NextRequest) {
  void _request;
  try {
    await requireRole(['admin']);

    if (!isSupabaseConfigured()) {
      const store = getStore();
      const alerts = detectSuspiciousActivity(store.audit);

      return NextResponse.json({
        success: true,
        data: alerts,
        total: alerts.length,
        rules: DETECTION_RULES.map((r) => ({
          id: r.id,
          title: r.title,
          description: r.description,
          severity: r.severity,
          threshold: r.threshold,
          window_minutes: r.windowMinutes,
        })),
      });
    }

    // Supabase mode: fetch recent audit events and analyze
    const { createClient } = await import('@/lib/supabase/server');
    const supabase = await createClient();
    const { data: events, error } = await supabase
      .from('audit_events')
      .select('*')
      .order('occurred_at', { ascending: false })
      .limit(1000);

    if (error) {
      return NextResponse.json(
        { success: false, error: 'Failed to fetch audit events for analysis' },
        { status: 500 }
      );
    }

    const alerts = detectSuspiciousActivity(events || []);

    return NextResponse.json({
      success: true,
      data: alerts,
      total: alerts.length,
      rules: DETECTION_RULES.map((r) => ({
        id: r.id,
        title: r.title,
        description: r.description,
        severity: r.severity,
        threshold: r.threshold,
        window_minutes: r.windowMinutes,
      })),
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
