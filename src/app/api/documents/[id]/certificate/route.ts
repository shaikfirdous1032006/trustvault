import { NextRequest, NextResponse } from 'next/server';
import { requireAuth, isDocumentOwner, AuthorizationError, getRequestMeta } from '@/lib/auth';
import { createAdminClient, isSupabaseConfigured } from '@/lib/supabase/server';
import { getDocument, getStore, withPermissionUsers, withUser } from '@/lib/local-db';
import { verifyAuditChain, logAuditEvent } from '@/lib/audit';
import { createHash } from 'crypto';
import type { Document, DocumentPermission, AuditEvent } from '@/lib/types';

type RouteParams = { params: Promise<{ id: string }> };

function sha256(data: string): string {
  return createHash('sha256').update(data).digest('hex');
}

/**
 * GET /api/documents/:id/certificate
 * Generates an immutable, cryptographically verifiable compliance certificate
 * for auditors, compliance officers, and legal verification.
 */
export async function GET(request: NextRequest, { params }: RouteParams) {
  const { id } = await params;
  const { ipAddress, userAgent } = await getRequestMeta();
  const searchParams = request.nextUrl.searchParams;
  const shouldDownload = searchParams.get('download') === 'true';

  try {
    const user = await requireAuth();
    const isOwner = await isDocumentOwner(user.id, id);

    if (!isOwner && user.role !== 'admin') {
      return NextResponse.json(
        { success: false, error: 'Only the document owner or an administrator can generate compliance certificates' },
        { status: 403 }
      );
    }

    let doc: (Document & { owner?: { id?: string; email?: string; full_name?: string | null } }) | null = null;
    let permissions: DocumentPermission[] = [];
    let documentAuditEvents: AuditEvent[] = [];

    if (!isSupabaseConfigured()) {
      const store = getStore();
      const rawDoc = getDocument(id);
      if (!rawDoc || rawDoc.is_deleted) {
        return NextResponse.json({ success: false, error: 'Document not found' }, { status: 404 });
      }
      doc = withUser(rawDoc, store);
      permissions = store.permissions
        .filter((p) => p.document_id === id)
        .map((p) => withPermissionUsers(p, store));
      documentAuditEvents = store.audit
        .filter((a) => a.document_id === id)
        .sort((a, b) => a.occurred_at.localeCompare(b.occurred_at));
    } else {
      const supabaseAdmin = createAdminClient();
      const { data: dbDoc } = await supabaseAdmin
        .from('documents')
        .select('*, owner:users!documents_owner_id_fkey(id, email, full_name)')
        .eq('id', id)
        .eq('is_deleted', false)
        .single();

      if (!dbDoc) {
        return NextResponse.json({ success: false, error: 'Document not found' }, { status: 404 });
      }
      doc = dbDoc;

      const { data: dbPerms } = await supabaseAdmin
        .from('document_permissions')
        .select('*, user:users!document_permissions_user_id_fkey(id, email, full_name)')
        .eq('document_id', id);
      permissions = dbPerms || [];

      const { data: dbAudit } = await supabaseAdmin
        .from('audit_events')
        .select('*')
        .eq('document_id', id)
        .order('occurred_at', { ascending: true });
      documentAuditEvents = dbAudit || [];
    }

    if (!doc) {
      return NextResponse.json({ success: false, error: 'Document not found' }, { status: 404 });
    }

    const chainVerification = await verifyAuditChain();

    const issuedAt = new Date().toISOString();
    const certId = `TV-CERT-${id.slice(0, 8).toUpperCase()}-${Date.now()}`;

    const genesisHash = documentAuditEvents[0]?.event_hash ?? 'GENESIS_NONE';
    const headHash = documentAuditEvents[documentAuditEvents.length - 1]?.event_hash ?? 'HEAD_NONE';

    const digitalSignature = sha256(
      JSON.stringify({
        certId,
        documentId: doc.id,
        checksum: doc.checksum,
        headHash,
        issuedAt,
        eventsCount: documentAuditEvents.length,
      })
    );

    const certificate = {
      certificate_id: certId,
      issued_at: issuedAt,
      issued_by: {
        id: user.id,
        email: user.email,
        role: user.role,
      },
      verification_standard: 'TrustVault Verifiable Cryptographic Audit Protocol v1.0',
      document: {
        id: doc.id,
        title: doc.title,
        description: doc.description,
        category: doc.category,
        file_name: doc.file_name,
        file_size_bytes: doc.file_size,
        mime_type: doc.mime_type,
        sha256_checksum: doc.checksum,
        current_version: doc.current_version,
        created_at: doc.created_at,
        owner: {
          id: doc.owner?.id,
          email: doc.owner?.email,
          full_name: doc.owner?.full_name,
        },
      },
      compliance_metrics: {
        total_audit_events: documentAuditEvents.length,
        distinct_recipients_granted: permissions.length,
        active_grants: permissions.filter((p) => !p.revoked_at).length,
        revoked_grants: permissions.filter((p) => Boolean(p.revoked_at)).length,
        ephemeral_single_use_grants: permissions.filter((p) => p.max_access_count === 1).length,
      },
      audit_chain_proof: {
        chain_valid: chainVerification.valid,
        mismatch_count: chainVerification.mismatches.length,
        genesis_event_hash: genesisHash,
        head_event_hash: headHash,
        signature_digest: digitalSignature,
      },
      access_permissions_ledger: permissions.map((p) => ({
        permission_id: p.id,
        recipient_email: p.user?.email || 'unknown',
        permission_level: p.permission_level,
        granted_at: p.granted_at,
        expires_at: p.expires_at,
        revoked_at: p.revoked_at,
        max_access_count: p.max_access_count ?? null,
        access_count: p.access_count ?? 0,
        watermark_enabled: p.watermark_enabled ?? true,
      })),
      audit_events_chronology: documentAuditEvents.map((evt) => ({
        event_id: evt.id,
        timestamp: evt.occurred_at,
        actor_email: evt.actor_email,
        action: evt.action,
        result: evt.result,
        prev_hash: evt.prev_hash,
        event_hash: evt.event_hash,
        details: evt.details_jsonb,
      })),
    };

    await logAuditEvent({
      actorId: user.id,
      actorEmail: user.email,
      documentId: id,
      action: 'admin_action',
      result: 'allowed',
      ipAddress,
      userAgent,
      details: {
        operation: 'compliance_certificate_generated',
        certificate_id: certId,
        download: shouldDownload,
      },
    });

    if (shouldDownload) {
      const jsonContent = JSON.stringify(certificate, null, 2);
      const safeFilename = `compliance-certificate-${doc.title.replace(/[^a-zA-Z0-9_-]/g, '_')}.json`;
      return new NextResponse(jsonContent, {
        headers: {
          'Content-Type': 'application/json',
          'Content-Disposition': `attachment; filename="${safeFilename}"`,
          'Cache-Control': 'no-store',
        },
      });
    }

    return NextResponse.json({
      success: true,
      data: certificate,
    });
  } catch (err: unknown) {
    if (err instanceof AuthorizationError) {
      return NextResponse.json({ success: false, error: err.message }, { status: err.statusCode });
    }
    return NextResponse.json({ success: false, error: 'Internal server error' }, { status: 500 });
  }
}
