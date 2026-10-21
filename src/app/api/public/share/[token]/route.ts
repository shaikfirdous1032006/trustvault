import { NextRequest, NextResponse } from 'next/server';
import { getRequestMeta } from '@/lib/auth';
import { logAuditEvent } from '@/lib/audit';
import { checkRateLimit } from '@/lib/security';
import { resolveShare, readShareFileBytes } from '@/lib/share-access';
import { shareDenyResponse } from '@/lib/share';

type RouteParams = { params: Promise<{ token: string }> };

const PREVIEW_BYTES = 256 * 1024;

const NO_STORE = {
  'Cache-Control': 'no-store',
  // A disclosure page must never be archived by a crawler or a link preview bot.
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
 * GET /api/public/share/:token
 *
 * The recipient-facing read. No session is consulted — the token is the whole
 * credential, and the server re-decides on every call.
 */
export async function GET(request: NextRequest, { params }: RouteParams) {
  const { token } = await params;
  const { ipAddress, userAgent } = await getRequestMeta();

  const limiter = checkRateLimit(`share-view:${ipAddress || 'unknown'}`, 30, 60_000);
  if (!limiter.allowed) {
    return NextResponse.json(
      { success: false, error: 'Too many requests from this address.' },
      { status: 429, headers: { ...NO_STORE, 'Retry-After': String(Math.ceil(limiter.resetMs / 1000)) } }
    );
  }

  const resolution = await resolveShare(token, false);

  if (!resolution.allowed) {
    await logAuditEvent({
      actorId: null,
      actorEmail: null,
      documentId: resolution.documentId,
      action: 'share_link_denied',
      result: 'denied',
      ipAddress,
      userAgent,
      details: { reason: resolution.reason },
    });

    const deny = shareDenyResponse(resolution.reason);
    return NextResponse.json({ success: false, error: deny.message, reason: resolution.reason }, {
      status: deny.status,
      headers: NO_STORE,
    });
  }

  const { link, document, autoRevoked } = resolution;
  const watermarked = link.watermark_enabled;

  let preview: string | null = null;
  let truncated = false;

  if (isTextish(document.mime_type, document.file_name)) {
    const bytes = await readShareFileBytes(document);
    if (!bytes) {
      return NextResponse.json({ success: false, error: 'The stored file is missing.' }, { status: 500, headers: NO_STORE });
    }
    const slice = bytes.subarray(0, PREVIEW_BYTES);
    truncated = bytes.length > PREVIEW_BYTES;
    const banner = watermarked
      ? `TRUSTVAULT SECURE DISCLOSURE\nRecipient link : ${link.label || link.id}\nDisclosed      : ${new Date().toISOString()}\nDocument       : ${document.file_name}\nSHA-256        : ${document.checksum}\nView count     : ${link.access_count}${autoRevoked ? ' (link closed after this view)' : ''}\nThis copy is traceable to this link. Do not redistribute.\n\n`
      : '';
    preview = `${banner}${slice.toString('utf8')}${truncated ? '\n\n… preview truncated; download for the full file.' : ''}`;
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
      // The link label is the only identity an anonymous bearer has. It is kept in
      // details rather than actor_email so the audit row never implies a platform
      // account performed the read.
      recipient_label: link.label,
      kind: 'preview',
      access_count: link.access_count,
      closed_after_view: autoRevoked,
      watermarked,
    },
  });

  return NextResponse.json(
    {
      success: true,
      data: {
        document: {
          id: document.id,
          title: document.title,
          file_name: document.file_name,
          mime_type: document.mime_type,
          file_size: document.file_size,
          checksum: document.checksum,
          current_version: document.current_version,
        },
        link: {
          id: link.id,
          label: link.label,
          expires_at: link.expires_at,
          access_count: link.access_count,
          max_access_count: link.max_access_count,
          allow_download: link.allow_download,
          watermark_enabled: link.watermark_enabled,
          closed_after_view: autoRevoked,
        },
        preview,
        preview_truncated: truncated,
      },
    },
    { headers: NO_STORE }
  );
}
