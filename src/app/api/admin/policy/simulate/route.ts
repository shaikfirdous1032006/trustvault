import { requireRole, AuthorizationError, getRequestMeta } from '@/lib/auth';
import { simulatePolicyChange } from '@/lib/policy-simulator';
import { logAuditEvent } from '@/lib/audit';
import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';

const simulateSchema = z.object({
  targetUserId: z.string().min(1, 'Target user ID is required'),
  documentId: z.string().min(1, 'Document ID is required'),
  proposedPermissionLevel: z.enum(['read', 'edit', 'none']),
  expiresInHours: z.number().int().positive().nullable().optional(),
});

export async function POST(request: NextRequest) {
  const { ipAddress, userAgent } = await getRequestMeta();

  try {
    const admin = await requireRole(['admin']);
    const body = await request.json().catch(() => ({}));
    const parsed = simulateSchema.safeParse(body);

    if (!parsed.success) {
      return NextResponse.json(
        {
          success: false,
          error: 'Validation failed',
          details: parsed.error.format(),
        },
        { status: 400 }
      );
    }

    const result = simulatePolicyChange(parsed.data, admin.id);

    await logAuditEvent({
      actorId: admin.id,
      actorEmail: admin.email,
      documentId: parsed.data.documentId,
      action: 'admin_action',
      result: 'allowed',
      ipAddress,
      userAgent,
      details: {
        operation: 'policy_simulation',
        targetUserId: parsed.data.targetUserId,
        proposedPermissionLevel: parsed.data.proposedPermissionLevel,
        accessDelta: result.accessDelta,
        projectedOutcome: result.projectedOutcome,
      },
    });

    return NextResponse.json({
      success: true,
      data: result,
    });
  } catch (err: unknown) {
    if (err instanceof AuthorizationError) {
      return NextResponse.json(
        { success: false, error: err.message },
        { status: err.statusCode }
      );
    }
    const message = err instanceof Error ? err.message : 'Internal simulation error';
    return NextResponse.json(
      { success: false, error: message },
      { status: 500 }
    );
  }
}
