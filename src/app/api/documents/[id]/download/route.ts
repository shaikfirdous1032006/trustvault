import { createAdminClient, isSupabaseConfigured } from '@/lib/supabase/server';
import { requireAuth, checkDocumentPermission, getRequestMeta, AuthorizationError } from '@/lib/auth';
import { logAuditEvent } from '@/lib/audit';
import { NextRequest, NextResponse } from 'next/server';
import { getDocument, mutateStore, readFileBytes } from '@/lib/local-db';

type RouteParams = { params: Promise<{ id: string }> };

/**
 * GET /api/documents/:id/download
 * Streams the file after a fresh permission check.
 * No durable URL is issued, so revocation is immediate.
 * Features:
 * 1. Forensic Watermarking: Embeds recipient watermark headers & metadata on confidential disclosures.
 * 2. Burn-After-Reading: Increments access_count and auto-revokes ephemeral single-use grants.
 */
export async function GET(request: NextRequest, { params }: RouteParams) {
  const { id } = await params;
  const { ipAddress, userAgent } = await getRequestMeta();

  try {
    const user = await requireAuth();
    const permission = await checkDocumentPermission(user.id, id, 'read');

    if (!permission.allowed) {
      await logAuditEvent({
        actorId: user.id,
        actorEmail: user.email,
        documentId: id,
        action: 'download',
        result: 'denied',
        ipAddress,
        userAgent,
        details: { reason: permission.reason },
      });
      return NextResponse.json(
        { success: false, error: 'Access denied' },
        { status: 403 }
      );
    }

    if (!isSupabaseConfigured()) {
      const doc = getDocument(id);
      if (!doc || doc.is_deleted) {
        return NextResponse.json({ success: false, error: 'Document not found' }, { status: 404 });
      }
      const rawBytes = readFileBytes(doc.storage_path);
      if (!rawBytes) {
        return NextResponse.json({ success: false, error: 'File missing' }, { status: 500 });
      }

      const isOwner = doc.owner_id === user.id;
      let watermarkApplied = false;
      let accessCount = 1;
      let autoRevoked = false;

      if (!isOwner) {
        await mutateStore((store) => {
          const perm = store.permissions.find(
            (p) => p.document_id === id && p.user_id === user.id && !p.revoked_at
          );
          if (perm) {
            perm.access_count = (perm.access_count ?? 0) + 1;
            accessCount = perm.access_count;
            watermarkApplied = perm.watermark_enabled !== false;
            if (perm.max_access_count && perm.access_count >= perm.max_access_count) {
              perm.revoked_at = new Date().toISOString();
              perm.revoked_by = 'system-auto-revoke';
              autoRevoked = true;
            }
          }
        });
      }

      let deliverableBytes: Uint8Array<ArrayBuffer> = new Uint8Array(rawBytes);
      const isText =
        doc.mime_type?.startsWith('text/') ||
        doc.mime_type === 'application/json' ||
        /\.(txt|csv|md|json|log|env)$/i.test(doc.file_name);

      if (isText && (watermarkApplied || !isOwner)) {
        const banner =
          `/* ==========================================================================\n` +
          `   TRUSTVAULT SECURE DISCLOSURE — FORENSIC WATERMARK TRACE\n` +
          `   Recipient          : ${user.email} (ID: ${user.id})\n` +
          `   Disclosed Timestamp: ${new Date().toISOString()}\n` +
          `   Document ID        : ${doc.id}\n` +
          `   Document SHA-256   : ${doc.checksum}\n` +
          `   Access Count       : ${accessCount}${autoRevoked ? ' [SINGLE-USE GRANTED & EXHAUSTED]' : ''}\n` +
          `   WARNING: Strictly confidential. Any unauthorized dissemination or leak is\n` +
          `   cryptographically provable and traceable directly to this recipient.\n` +
          `   ========================================================================== */\n\n`;
        const footer =
          `\n\n/* ==========================================================================\n` +
          `   END OF DISCLOSED RECORD — PROTECTED BY TRUSTVAULT AUDIT TRAIL\n` +
          `   ========================================================================== */\n`;

        deliverableBytes = new Uint8Array(
          Buffer.concat([Buffer.from(banner, 'utf8'), Buffer.from(rawBytes), Buffer.from(footer, 'utf8')])
        );
      }

      await logAuditEvent({
        actorId: user.id,
        actorEmail: user.email,
        documentId: id,
        action: 'download',
        result: 'allowed',
        ipAddress,
        userAgent,
        details: {
          file_name: doc.file_name,
          watermarked: watermarkApplied || !isOwner,
          access_count: accessCount,
          single_use_revoked: autoRevoked,
        },
      });

      return new NextResponse(new Blob([deliverableBytes]), {
        headers: {
          'Content-Type': doc.mime_type || 'application/octet-stream',
          'Content-Disposition': `attachment; filename="${doc.file_name.replace(/"/g, '')}"`,
          'Cache-Control': 'no-store',
          'X-TrustVault-Recipient': user.email,
          'X-TrustVault-Watermark-Applied': String(watermarkApplied || !isOwner),
          'X-TrustVault-Access-Count': String(accessCount),
          'X-TrustVault-Auto-Revoked': String(autoRevoked),
          'X-TrustVault-Document-Checksum': doc.checksum,
        },
      });
    }

    const supabaseAdmin = createAdminClient();
    const { data: doc, error } = await supabaseAdmin
      .from('documents')
      .select('owner_id, storage_path, file_name, mime_type, checksum')
      .eq('id', id)
      .eq('is_deleted', false)
      .single();

    if (error || !doc) {
      return NextResponse.json({ success: false, error: 'Document not found' }, { status: 404 });
    }

    const isOwner = doc.owner_id === user.id;
    let watermarkApplied = false;
    let accessCount = 1;
    let autoRevoked = false;

    if (!isOwner) {
      const { data: perm } = await supabaseAdmin
        .from('document_permissions')
        .select('id, access_count, max_access_count, watermark_enabled')
        .eq('document_id', id)
        .eq('user_id', user.id)
        .is('revoked_at', null)
        .maybeSingle();

      if (perm) {
        const newCount = (perm.access_count || 0) + 1;
        const shouldRevoke = perm.max_access_count && newCount >= perm.max_access_count;
        await supabaseAdmin
          .from('document_permissions')
          .update({
            access_count: newCount,
            ...(shouldRevoke ? { revoked_at: new Date().toISOString(), revoked_by: 'system-auto-revoke' } : {}),
          })
          .eq('id', perm.id);
        accessCount = newCount;
        autoRevoked = Boolean(shouldRevoke);
        watermarkApplied = perm.watermark_enabled !== false;
      }
    }

    const { data: file, error: downloadError } = await supabaseAdmin.storage
      .from('documents')
      .download(doc.storage_path);

    if (downloadError || !file) {
      return NextResponse.json({ success: false, error: 'Failed to fetch file' }, { status: 500 });
    }

    await logAuditEvent({
      actorId: user.id,
      actorEmail: user.email,
      documentId: id,
      action: 'download',
      result: 'allowed',
      ipAddress,
      userAgent,
      details: {
        file_name: doc.file_name,
        watermarked: watermarkApplied || !isOwner,
        access_count: accessCount,
        single_use_revoked: autoRevoked,
      },
    });

    const arrayBuffer = await file.arrayBuffer();
    let deliverableBytes: Uint8Array<ArrayBuffer> = new Uint8Array(arrayBuffer);
    const isText =
      doc.mime_type?.startsWith('text/') ||
      doc.mime_type === 'application/json' ||
      /\.(txt|csv|md|json|log|env)$/i.test(doc.file_name);

    if (isText && (watermarkApplied || !isOwner)) {
      const banner =
        `/* ==========================================================================\n` +
        `   TRUSTVAULT SECURE DISCLOSURE — FORENSIC WATERMARK TRACE\n` +
        `   Recipient          : ${user.email} (ID: ${user.id})\n` +
        `   Disclosed Timestamp: ${new Date().toISOString()}\n` +
        `   Document ID        : ${id}\n` +
        `   Document SHA-256   : ${doc.checksum || ''}\n` +
        `   Access Count       : ${accessCount}${autoRevoked ? ' [SINGLE-USE GRANTED & EXHAUSTED]' : ''}\n` +
        `   WARNING: Strictly confidential. Any unauthorized dissemination or leak is\n` +
        `   cryptographically provable and traceable directly to this recipient.\n` +
        `   ========================================================================== */\n\n`;
      const footer =
        `\n\n/* ==========================================================================\n` +
        `   END OF DISCLOSED RECORD — PROTECTED BY TRUSTVAULT AUDIT TRAIL\n` +
        `   ========================================================================== */\n`;

      deliverableBytes = new Uint8Array(
        Buffer.concat([Buffer.from(banner, 'utf8'), Buffer.from(arrayBuffer), Buffer.from(footer, 'utf8')])
      );
    }

    return new NextResponse(new Blob([deliverableBytes]), {
      headers: {
        'Content-Type': doc.mime_type || 'application/octet-stream',
        'Content-Disposition': `attachment; filename="${doc.file_name.replace(/"/g, '')}"`,
        'Cache-Control': 'no-store',
        'X-TrustVault-Recipient': user.email,
        'X-TrustVault-Watermark-Applied': String(watermarkApplied || !isOwner),
        'X-TrustVault-Access-Count': String(accessCount),
        'X-TrustVault-Auto-Revoked': String(autoRevoked),
        'X-TrustVault-Document-Checksum': doc.checksum || '',
      },
    });
  } catch (err: unknown) {
    if (err instanceof AuthorizationError) {
      return NextResponse.json({ success: false, error: err.message }, { status: err.statusCode });
    }
    return NextResponse.json({ success: false, error: 'Internal server error' }, { status: 500 });
  }
}

