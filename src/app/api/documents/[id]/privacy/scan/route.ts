import { requireAuth, AuthorizationError, getRequestMeta } from '@/lib/auth';
import { getDocument, getPermissionsForDocument, readFileBytes } from '@/lib/local-db';
import { evaluateDocumentPermission } from '@/lib/permission';
import { extractTextFromBuffer, scanTextForPrivacyEntities } from '@/lib/privacy-shield';
import { logAuditEvent } from '@/lib/audit';
import { NextRequest, NextResponse } from 'next/server';

interface RouteParams {
  params: Promise<{ id: string }>;
}

export async function POST(_request: NextRequest, { params }: RouteParams) {
  const { ipAddress, userAgent } = await getRequestMeta();

  try {
    const user = await requireAuth();
    const { id: documentId } = await params;

    const doc = getDocument(documentId);
    if (!doc || doc.is_deleted) {
      return NextResponse.json(
        { success: false, error: 'Document not found' },
        { status: 404 }
      );
    }

    const grants = getPermissionsForDocument(documentId);
    const decision = evaluateDocumentPermission({
      document: doc,
      grants,
      userId: user.id,
      requiredLevel: 'read',
    });

    if (!decision.allowed && user.role !== 'admin') {
      await logAuditEvent({
        actorId: user.id,
        actorEmail: user.email,
        documentId,
        action: 'preview',
        result: 'denied',
        ipAddress,
        userAgent,
        details: { reason: 'Unauthorized privacy scan attempt' },
      });

      return NextResponse.json(
        { success: false, error: 'Permission denied' },
        { status: 403 }
      );
    }

    const bytes = readFileBytes(doc.storage_path);
    if (!bytes) {
      return NextResponse.json(
        { success: false, error: 'Document payload file missing on disk' },
        { status: 404 }
      );
    }

    const textContent = extractTextFromBuffer(bytes, doc.mime_type);
    const scanResult = scanTextForPrivacyEntities(textContent, doc.id, doc.title);

    await logAuditEvent({
      actorId: user.id,
      actorEmail: user.email,
      documentId,
      action: 'ai_suggestion',
      result: 'allowed',
      ipAddress,
      userAgent,
      details: {
        operation: 'privacy_shield_scan',
        totalFindings: scanResult.totalFindings,
        findingsByType: scanResult.findingsByType,
        detectorVersion: scanResult.detectorVersion,
      },
    });

    return NextResponse.json({
      success: true,
      data: scanResult,
    });
  } catch (err: unknown) {
    if (err instanceof AuthorizationError) {
      return NextResponse.json(
        { success: false, error: err.message },
        { status: err.statusCode }
      );
    }
    console.error('[PRIVACY SHIELD] Scan failed:', err);
    return NextResponse.json(
      { success: false, error: 'Internal server error during privacy scan' },
      { status: 500 }
    );
  }
}
