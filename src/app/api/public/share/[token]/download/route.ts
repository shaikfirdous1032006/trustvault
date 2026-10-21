import { NextRequest, NextResponse } from 'next/server';
import { getRequestMeta } from '@/lib/auth';
import { logAuditEvent } from '@/lib/audit';
import { checkRateLimit } from '@/lib/security';
import { resolveShare, readShareFileBytes } from '@/lib/share-access';
import { shareDenyResponse } from '@/lib/share';

type RouteParams = { params: Promise<{ token: string }> };

const NO_STORE = {
  'Cache-Control': 'no-store',
  'X-Robots-Tag': 'noindex, nofollow, noarchive, nosnippet',
};

function isTextish(mimeType: string, fileName: string): boolean {
  return (
    mimeType.startsWith('text/') ||
    mimeType === 'application/json' ||
    /\.(txt|csv|md|json|log)$/i.test(fileName)
  );
}

/**
 * GET /api/public/share/:token/download
 *
 * Streams the file to a bearer whose link permits download. The storage key never
 * leaves the server, so there is no durable URL to copy forward — revoking the
 * link is enough to stop every future fetch.
 */
export async function GET(request: NextRequest, { params }: RouteParams) {
  const { token } = await params;
  const { ipAddress, userAgent } = await getRequestMeta();

  const limiter = checkRateLimit(`share-download:${ipAddress || 'unknown'}`, 20, 60_000);
  if (!limiter.allowed) {
    return NextResponse.json(
      { success: false, error: 'Too many requests from this address.' },
      { status: 429, headers: { ...NO_STORE, 'Retry-After': String(Math.ceil(limiter.resetMs / 1000)) } }
    );
  }

  const resolution = await resolveShare(token, true);

  if (!resolution.allowed) {
    await logAuditEvent({
      actorId: null,
      actorEmail: null,
      documentId: resolution.documentId,
      action: 'share_link_denied',
      result: 'denied',
      ipAddress,
      userAgent,
      details: { reason: resolution.reason, kind: 'download' },
    });

    const deny = shareDenyResponse(resolution.reason);
    return NextResponse.json(
      { success: false, error: deny.message, reason: resolution.reason },
      { status: deny.status, headers: NO_STORE }
    );
  }

  const { link, document, autoRevoked } = resolution;
  const raw = await readShareFileBytes(document);
  if (!raw) {
    return NextResponse.json(
      { success: false, error: 'The stored file is missing.' },
      { status: 500, headers: NO_STORE }
    );
  }

  let deliverableBytes: Uint8Array<ArrayBuffer> = new Uint8Array(raw);
  const watermarkApplied = link.watermark_enabled && isTextish(document.mime_type, document.file_name);

  if (watermarkApplied) {
    const banner =
      `/* ==========================================================================\n` +
      `   TRUSTVAULT SECURE DISCLOSURE — FORENSIC WATERMARK TRACE\n` +
      `   Recipient link       : ${link.label || '(unlabelled)'} (ID: ${link.id})\n` +
      `   Disclosed Timestamp  : ${new Date().toISOString()}\n` +
      `   Document             : ${document.file_name} (${document.id})\n` +
      `   Document SHA-256     : ${document.checksum}\n` +
      `   View Count           : ${link.access_count}${autoRevoked ? ' [LINK CLOSED AFTER THIS VIEW]' : ''}\n` +
      `   WARNING: This copy was issued to one anonymous bearer link. A leak of this\n` +
      `   file is traceable to this link, and the link's issuer is on record.\n` +
      `   ========================================================================== */\n\n`;
    const footer =
      `\n\n/* ==========================================================================\n` +
      `   END OF DISCLOSED RECORD — PROTECTED BY TRUSTVAULT AUDIT TRAIL\n` +
      `   ========================================================================== */\n`;

    deliverableBytes = new Uint8Array(
      Buffer.concat([Buffer.from(banner, 'utf8'), Buffer.from(raw), Buffer.from(footer, 'utf8')])
    );
  }

  await logAuditEvent({
    actorId: null,
    actorEmail: null,
    documentId: document.id,
    action: 'share_link_viewed',
    result: 'allowed',
    ipAddress,
    userAgent,
    details: {
      share_link_id: link.id,
      recipient_label: link.label,
      kind: 'download',
      access_count: link.access_count,
      closed_after_view: autoRevoked,
      watermarked: watermarkApplied,
    },
  });

  return new NextResponse(new Blob([deliverableBytes]), {
    headers: {
      ...NO_STORE,
      'Content-Type': document.mime_type || 'application/octet-stream',
      'Content-Disposition': `attachment; filename="${document.file_name.replace(/"/g, '')}"`,
      'X-TrustVault-Share-Link': link.id,
      'X-TrustVault-Watermark-Applied': String(watermarkApplied),
      'X-TrustVault-Access-Count': String(link.access_count),
      'X-TrustVault-Auto-Revoked': String(autoRevoked),
      'X-TrustVault-Document-Checksum': document.checksum,
    },
  });
}
