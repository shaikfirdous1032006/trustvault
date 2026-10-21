import { requireRole, AuthorizationError, getRequestMeta } from '@/lib/auth';
import { verifyAuditChain, logAuditEvent } from '@/lib/audit';
import { NextRequest, NextResponse } from 'next/server';

export async function POST(_request?: NextRequest) {
  void _request;
  const { ipAddress, userAgent } = await getRequestMeta();

  try {
    const admin = await requireRole(['admin']);

    const verificationResult = await verifyAuditChain();

    await logAuditEvent({
      actorId: admin.id,
      actorEmail: admin.email,
      action: 'admin_action',
      result: verificationResult.valid ? 'allowed' : 'denied',
      ipAddress,
      userAgent,
      details: {
        operation: 'audit_chain_verification',
        valid: verificationResult.valid,
        mismatch_count: verificationResult.mismatches.length,
        first_invalid_event: verificationResult.firstInvalid,
      },
    });

    return NextResponse.json({
      success: true,
      valid: verificationResult.valid,
      mismatches: verificationResult.mismatches,
      first_invalid: verificationResult.firstInvalid,
      verified_at: new Date().toISOString(),
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
