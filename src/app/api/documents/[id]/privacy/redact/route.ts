import { requireAuth, AuthorizationError, getRequestMeta } from '@/lib/auth';
import {
  getDocument,
  readFileBytes,
  putFile,
  mutateStore,
} from '@/lib/local-db';
import {
  extractTextFromBuffer,
  scanTextForPrivacyEntities,
  applyPrivacyRedactions,
} from '@/lib/privacy-shield';
import { logAuditEvent } from '@/lib/audit';
import { NextRequest, NextResponse } from 'next/server';
import { createHash, randomUUID } from 'node:crypto';
import type { Document } from '@/lib/types';

interface RouteParams {
  params: Promise<{ id: string }>;
}

export async function POST(request: NextRequest, { params }: RouteParams) {
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

    // Only owner or admin can authorize redaction and generate a new redacted asset
    if (doc.owner_id !== user.id && user.role !== 'admin') {
      await logAuditEvent({
        actorId: user.id,
        actorEmail: user.email,
        documentId,
        action: 'update',
        result: 'denied',
        ipAddress,
        userAgent,
        details: { reason: 'Unauthorized privacy redaction attempt' },
      });

      return NextResponse.json(
        { success: false, error: 'Only the document owner or an admin can generate a redacted version' },
        { status: 403 }
      );
    }

    const body = await request.json().catch(() => ({}));
    const approvedFindingIds: string[] | undefined = body.approvedFindingIds;
    const customTitle: string | undefined = body.customTitle;

    const bytes = readFileBytes(doc.storage_path);
    if (!bytes) {
      return NextResponse.json(
        { success: false, error: 'Original document payload missing on disk' },
        { status: 404 }
      );
    }

    const textContent = extractTextFromBuffer(bytes, doc.mime_type);
    const scan = scanTextForPrivacyEntities(textContent, doc.id, doc.title);

    // Filter to approved findings
    const findingsToApply = approvedFindingIds
      ? scan.findings.filter((f) => approvedFindingIds.includes(f.id))
      : scan.findings;

    if (findingsToApply.length === 0) {
      return NextResponse.json(
        { success: false, error: 'No sensitive findings were selected for redaction' },
        { status: 400 }
      );
    }

    // Apply redactions
    const redactedText = applyPrivacyRedactions(textContent, findingsToApply);
    const redactedBuffer = Buffer.from(redactedText, 'utf-8');

    // Create new redacted file in storage
    const newDocId = `doc-${randomUUID()}`;
    const newStoragePath = `uploads/${newDocId}/redacted_${doc.file_name}`;
    putFile(newStoragePath, redactedBuffer);

    const now = new Date().toISOString();
    const checksum = createHash('sha256').update(redactedBuffer).digest('hex');

    const newDoc: Document = {
      id: newDocId,
      owner_id: user.id,
      title: customTitle?.trim() || `[Redacted] ${doc.title}`,
      description: `Privacy-redacted version of document '${doc.title}'. Redacted ${findingsToApply.length} sensitive item(s).`,
      category: doc.category,
      storage_path: newStoragePath,
      file_name: `redacted_${doc.file_name}`,
      file_size: redactedBuffer.length,
      mime_type: 'text/plain',
      checksum,
      current_version: 1,
      is_deleted: false,
      deleted_at: null,
      deleted_by: null,
      created_at: now,
      updated_at: now,
    };

    // Store in database
    await mutateStore((store) => {
      store.documents.push(newDoc);
      return newDoc;
    });

    await logAuditEvent({
      actorId: user.id,
      actorEmail: user.email,
      documentId: newDoc.id,
      action: 'ai_suggestion_confirmed',
      result: 'allowed',
      ipAddress,
      userAgent,
      details: {
        operation: 'privacy_redaction_executed',
        sourceDocumentId: doc.id,
        newDocumentId: newDoc.id,
        redactedCount: findingsToApply.length,
        redactedTypes: findingsToApply.map((f) => f.entityType),
      },
    });

    return NextResponse.json({
      success: true,
      message: 'Redacted document successfully created',
      data: newDoc,
    });
  } catch (err: unknown) {
    if (err instanceof AuthorizationError) {
      return NextResponse.json(
        { success: false, error: err.message },
        { status: err.statusCode }
      );
    }
    console.error('[PRIVACY SHIELD] Redact failed:', err);
    return NextResponse.json(
      { success: false, error: 'Internal server error during privacy redaction' },
      { status: 500 }
    );
  }
}
