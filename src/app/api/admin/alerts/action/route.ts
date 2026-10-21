import { requireRole, AuthorizationError, getRequestMeta } from '@/lib/auth';
import { applyTemporaryRestriction } from '@/lib/policy-engine';
import { logAuditEvent } from '@/lib/audit';
import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';

const alertActionSchema = z.object({
  alertId: z.string().min(1, 'Alert ID is required'),
  action: z.enum(['investigate', 'resolve', 'dismiss', 'restrict_actor']),
  actorId: z.string().optional().nullable(),
  notes: z.string().max(500).optional(),
  durationMinutes: z.number().int().min(1).max(1440).optional().default(15),
});

export async function POST(request: NextRequest) {
  const { ipAddress, userAgent } = await getRequestMeta();

  try {
    const admin = await requireRole(['admin']);
    const body = await request.json().catch(() => ({}));
    const parsed = alertActionSchema.safeParse(body);

    if (!parsed.success) {
      return NextResponse.json(
        { success: false, error: 'Invalid alert action payload', details: parsed.error.format() },
        { status: 400 }
      );
    }

    const { alertId, action, actorId, notes, durationMinutes } = parsed.data;

    let restrictionApplied = null;
    if (action === 'restrict_actor' && actorId) {
      restrictionApplied = applyTemporaryRestriction(
        actorId,
        notes || `Security restriction triggered by alert ${alertId}`,
        durationMinutes,
        95
      );
    }

    await logAuditEvent({
      actorId: admin.id,
      actorEmail: admin.email,
      action: 'admin_action',
      result: 'allowed',
      ipAddress,
      userAgent,
      details: {
        operation: 'alert_investigation_response',
        alertId,
        alertAction: action,
        targetActorId: actorId,
        notes: notes || null,
        restrictionApplied: restrictionApplied ? true : false,
      },
    });

    return NextResponse.json({
      success: true,
      message: `Alert action '${action}' recorded successfully`,
      data: {
        alertId,
        action,
        status: action === 'dismiss' ? 'dismissed' : action === 'resolve' ? 'resolved' : 'investigating',
        updatedAt: new Date().toISOString(),
        restriction: restrictionApplied,
      },
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
