import { requireRole, AuthorizationError, getRequestMeta } from '@/lib/auth';
import { verifyAuditChain, logAuditEvent } from '@/lib/audit';
import { getStore } from '@/lib/local-db';
import { NextRequest, NextResponse } from 'next/server';
import { createHmac, randomUUID } from 'node:crypto';

export async function GET(request: NextRequest) {
  const { ipAddress, userAgent } = await getRequestMeta();

  try {
    const admin = await requireRole(['admin']);
    const verification = await verifyAuditChain();
    const store = getStore();

    const events = store.audit;
    const totalEvents = events.length;
    const chainHeadHash = events[totalEvents - 1]?.event_hash || null;
    const genesisHash = events[0]?.event_hash || null;
    const now = new Date().toISOString();

    // Generate signed checkpoint
    const checkpointId = `chk-${randomUUID()}`;
    const secret = process.env.SESSION_SECRET || 'trustvault-audit-signing-fallback-key';
    const checkpointCanonical = [
      checkpointId,
      now,
      totalEvents.toString(),
      chainHeadHash || 'empty',
      verification.valid ? 'VALID' : 'INVALID',
    ].join('|');

    const signature = createHmac('sha256', secret)
      .update(checkpointCanonical)
      .digest('hex');

    const report = {
      title: 'TrustVault Tamper-Evident Audit Verification Report',
      exportedAt: now,
      exportedBy: {
        id: admin.id,
        email: admin.email,
        role: admin.role,
      },
      integritySummary: {
        totalEvents,
        chainHeadHash,
        genesisHash,
        valid: verification.valid,
        mismatchCount: verification.mismatches.length,
        firstInvalidEvent: verification.firstInvalid || null,
      },
      cryptographicCheckpoint: {
        checkpointId,
        timestamp: now,
        algorithm: 'HMAC-SHA256',
        chainHeadHash,
        eventCount: totalEvents,
        signature,
      },
      events: events.map((e) => ({
        id: e.id,
        occurred_at: e.occurred_at,
        actor_id: e.actor_id,
        actor_email: e.actor_email,
        document_id: e.document_id,
        action: e.action,
        result: e.result,
        event_hash: e.event_hash,
        prev_hash: e.prev_hash,
        ip_hash: e.ip_hash,
      })),
    };

    await logAuditEvent({
      actorId: admin.id,
      actorEmail: admin.email,
      action: 'admin_action',
      result: 'allowed',
      ipAddress,
      userAgent,
      details: {
        operation: 'audit_report_export',
        checkpointId,
        valid: verification.valid,
        eventCount: totalEvents,
      },
    });

    const isDownload = request.nextUrl.searchParams.get('download') === 'true';

    return NextResponse.json(report, {
      status: 200,
      headers: isDownload
        ? {
            'Content-Disposition': `attachment; filename="trustvault-audit-report-${Date.now()}.json"`,
            'Content-Type': 'application/json',
          }
        : undefined,
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
