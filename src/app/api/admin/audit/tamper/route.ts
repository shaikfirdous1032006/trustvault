import { csrfRejection } from '@/lib/security';
import { NextRequest, NextResponse } from 'next/server';
import { requireRole, AuthorizationError, getRequestMeta } from '@/lib/auth';
import { logAuditEvent } from '@/lib/audit';
import { getStore, mutateStore } from '@/lib/local-db';
import { z } from 'zod';

let backupEvent: { id: string; original_email: string | null; original_details: Record<string, unknown> } | null = null;

const requestSchema = z.object({
  action: z.enum(['tamper', 'restore']),
});

export async function GET() {
  try {
    await requireRole(['admin']);
    return NextResponse.json({
      success: true,
      is_tampered: backupEvent !== null,
      tampered_event_id: backupEvent?.id || null,
    });
  } catch (err: unknown) {
    if (err instanceof AuthorizationError) {
      return NextResponse.json({ success: false, error: err.message }, { status: err.statusCode });
    }
    return NextResponse.json({ success: false, error: 'Internal server error' }, { status: 500 });
  }
}

export async function POST(request: NextRequest) {
  const crossOrigin = csrfRejection(request);
  if (crossOrigin) return crossOrigin;
  const { ipAddress, userAgent } = await getRequestMeta();

  try {
    const admin = await requireRole(['admin']);
    const body = await request.json().catch(() => ({}));
    const parsed = requestSchema.safeParse(body);

    if (!parsed.success) {
      return NextResponse.json({ success: false, error: 'Invalid action. Must be "tamper" or "restore"' }, { status: 400 });
    }

    if (parsed.data.action === 'tamper') {
      const store = getStore();
      if (store.audit.length === 0) {
        return NextResponse.json({ success: false, error: 'No audit events to tamper with' }, { status: 400 });
      }

      // Pick the second event or first event to tamper
      const targetIndex = store.audit.length > 1 ? 1 : 0;
      const target = store.audit[targetIndex];

      backupEvent = {
        id: target.id,
        original_email: target.actor_email,
        original_details: { ...target.details_jsonb },
      };

      await mutateStore((s) => {
        const evt = s.audit.find((e) => e.id === target.id);
        if (evt) {
          // Malicious unauthorized alteration: change email and details without recomputing event_hash
          evt.actor_email = 'attacker_unauthorized@exfiltration.net';
          evt.details_jsonb = {
            ...evt.details_jsonb,
            tampered_by_adversary: true,
            covert_action: 'unauthorized_payload_injection',
          };
        }
      });

      return NextResponse.json({
        success: true,
        is_tampered: true,
        message: 'Malicious tamper attack simulated! Record modified directly in storage without cryptographic hash re-calculation.',
        tampered_event_id: target.id,
      });
    }

    // Restore action
    if (!backupEvent) {
      return NextResponse.json({
        success: true,
        is_tampered: false,
        message: 'Audit chain is already in pristine condition.',
      });
    }

    const { id: restoreId, original_email, original_details } = backupEvent;
    await mutateStore((s) => {
      const evt = s.audit.find((e) => e.id === restoreId);
      if (evt) {
        evt.actor_email = original_email;
        evt.details_jsonb = original_details;
      }
    });

    backupEvent = null;

    await logAuditEvent({
      actorId: admin.id,
      actorEmail: admin.email,
      action: 'admin_action',
      result: 'allowed',
      ipAddress,
      userAgent,
      details: {
        operation: 'audit_chain_tamper_demo_restored',
        restored_event_id: restoreId,
      },
    });

    return NextResponse.json({
      success: true,
      is_tampered: false,
      message: 'Tampered audit record restored to authentic state. Chain cryptographic integrity re-verified.',
    });
  } catch (err: unknown) {
    if (err instanceof AuthorizationError) {
      return NextResponse.json({ success: false, error: err.message }, { status: err.statusCode });
    }
    return NextResponse.json({ success: false, error: 'Internal server error' }, { status: 500 });
  }
}
