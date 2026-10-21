import { requireAuth, getRequestMeta } from '@/lib/auth';
import { getDocument, getPermissionsForDocument, readFileBytes } from '@/lib/local-db';
import { evaluateDocumentPermission } from '@/lib/permission';
import { queryDocumentAI } from '@/lib/document-ai';
import { logAuditEvent } from '@/lib/audit';
import { extractTextFromBuffer } from '@/lib/privacy-shield';
import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';

const aiQuerySchema = z.object({
  query: z.string().min(1).max(1000),
});

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
        details: { reason: 'Unauthorized AI Assistant query attempt' },
      });

      return NextResponse.json(
        { success: false, error: 'Permission denied: Cannot query document AI without read access' },
        { status: 403 }
      );
    }

    const body = await request.json().catch(() => ({}));
    const parsed = aiQuerySchema.safeParse(body);
    if (!parsed.success) {
      return NextResponse.json(
        { success: false, error: 'Invalid query', details: parsed.error.flatten() },
        { status: 400 }
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
    const aiResult = await queryDocumentAI({
      documentTitle: doc.title,
      documentContent: textContent,
      userQuery: parsed.data.query,
    });

    await logAuditEvent({
      actorId: user.id,
      actorEmail: user.email,
      documentId,
      action: 'ai_assistant_query',
      result: aiResult.promptInjectionDetected ? 'denied' : 'allowed',
      ipAddress,
      userAgent,
      details: {
        queryLength: parsed.data.query.length,
        promptInjectionDetected: aiResult.promptInjectionDetected,
        confidence: aiResult.groundedConfidence,
        model: aiResult.model,
      },
    });

    return NextResponse.json({
      success: true,
      data: aiResult,
    });
  } catch (err: unknown) {
    const error = err as { statusCode?: number; message?: string };
    if (error.statusCode) {
      return NextResponse.json(
        { success: false, error: error.message },
        { status: error.statusCode }
      );
    }
    return NextResponse.json(
      { success: false, error: 'Internal server error processing AI query' },
      { status: 500 }
    );
  }
}
