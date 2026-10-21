import { createClient, isSupabaseConfigured } from '@/lib/supabase/server';
import { requireAuth, isDocumentOwner, getRequestMeta, AuthorizationError } from '@/lib/auth';
import { logAuditEvent } from '@/lib/audit';
import { checkRateLimit, csrfRejection } from '@/lib/security';
import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { randomUUID } from 'crypto';
import { getStore, mutateStore } from '@/lib/local-db';
import type { ShareLink } from '@/lib/types';
import {
  buildShareUrl,
  generateShareToken,
  hashShareToken,
  shareExpiryError,
} from '@/lib/share';

type RouteParams = { params: Promise<{ id: string }> };

/**
 * token_hash is deliberately absent: it is the credential's only persisted form,
 * and the list endpoint has no reason to hand it to a browser.
 */
function toLinkView(link: ShareLink) {
  return {
    id: link.id,
    document_id: link.document_id,
    label: link.label,
    created_by: link.created_by,
    created_at: link.created_at,
    expires_at: link.expires_at,
    revoked_at: link.revoked_at,
    revoked_by: link.revoked_by,
    access_count: link.access_count,
    max_access_count: link.max_access_count,
    last_accessed_at: link.last_accessed_at,
    allow_download: link.allow_download,
    watermark_enabled: link.watermark_enabled,
    is_active: !link.revoked_at && new Date(link.expires_at).getTime() > Date.now(),
  };
}

const createSchema = z.object({
  label: z.string().trim().max(200).optional().nullable(),
  expires_at: z.string().min(1, 'expires_at is required'),
  max_views: z.number().int().positive().max(1000).optional().nullable(),
  allow_download: z.boolean().optional(),
  watermark_enabled: z.boolean().optional(),
});

async function loadDocument(id: string) {
  if (!isSupabaseConfigured()) {
    return getStore().documents.find((d) => d.id === id) ?? null;
  }
  const supabase = await createClient();
  const { data } = await supabase
    .from('documents')
    .select('id, owner_id, title, is_deleted')
    .eq('id', id)
    .maybeSingle();
  return data ?? null;
}

export async function GET(request: NextRequest, { params }: RouteParams) {
  const { id } = await params;

  try {
    const user = await requireAuth();
    const ownerCheck = await isDocumentOwner(user.id, id);
    if (!ownerCheck && user.role !== 'admin') {
      return NextResponse.json(
        { success: false, error: 'Only the document owner can list share links' },
        { status: 403 }
      );
    }

    if (!isSupabaseConfigured()) {
      const links = getStore()
        .share_links.filter((l) => l.document_id === id)
        .sort((a, b) => b.created_at.localeCompare(a.created_at))
        .map(toLinkView);
      return NextResponse.json({ success: true, data: links });
    }

    const supabase = await createClient();
    const { data, error } = await supabase
      .from('share_links')
      .select('id, document_id, label, created_by, created_at, expires_at, revoked_at, revoked_by, access_count, max_access_count, last_accessed_at, allow_download, watermark_enabled')
      .eq('document_id', id)
      .order('created_at', { ascending: false });

    if (error) {
      return NextResponse.json({ success: false, error: 'Failed to fetch share links' }, { status: 500 });
    }

    const now = Date.now();
    return NextResponse.json({
      success: true,
      data: (data || []).map((l: Record<string, unknown>) => ({
        ...l,
        is_active: !l.revoked_at && new Date(String(l.expires_at)).getTime() > now,
      })),
    });
  } catch (err: unknown) {
    if (err instanceof AuthorizationError) {
      return NextResponse.json({ success: false, error: err.message }, { status: err.statusCode });
    }
    return NextResponse.json({ success: false, error: 'Internal server error' }, { status: 500 });
  }
}

export async function POST(request: NextRequest, { params }: RouteParams) {
  const crossOrigin = csrfRejection(request);
  if (crossOrigin) return crossOrigin;
  const { id } = await params;
  const { ipAddress, userAgent } = await getRequestMeta();

  try {
    const user = await requireAuth();

    if (!process.env.NEXT_PUBLIC_APP_URL) {
      // Minting a link we cannot render as an absolute URL would produce a credential
      // nobody can use, so fail before anything is written.
      return NextResponse.json(
        { success: false, error: 'Share links are unavailable: NEXT_PUBLIC_APP_URL is not configured.' },
        { status: 503 }
      );
    }

    // Link minting is capped per account: a compromised owner session should not be
    // able to publish an unbounded number of bearer credentials for one document.
    const limiter = checkRateLimit(`share-create:${user.id}`, 20, 60_000);
    if (!limiter.allowed) {
      return NextResponse.json(
        { success: false, error: 'Too many share links created. Try again shortly.' },
        { status: 429, headers: { 'Retry-After': String(Math.ceil(limiter.resetMs / 1000)) } }
      );
    }

    const ownerCheck = await isDocumentOwner(user.id, id);
    if (!ownerCheck) {
      await logAuditEvent({
        actorId: user.id,
        actorEmail: user.email,
        documentId: id,
        action: 'share_link_created',
        result: 'denied',
        ipAddress,
        userAgent,
        details: { reason: 'Not document owner' },
      });
      return NextResponse.json(
        { success: false, error: 'Only the document owner can create share links' },
        { status: 403 }
      );
    }

    const body = await request.json().catch(() => ({}));
    const parsed = createSchema.safeParse(body);
    if (!parsed.success) {
      return NextResponse.json(
        { success: false, error: 'Invalid share link data', details: parsed.error.flatten() },
        { status: 400 }
      );
    }

    const now = Date.now();
    const expiresMs = Date.parse(parsed.data.expires_at);
    const expiryError = shareExpiryError(expiresMs, now);
    if (expiryError) {
      return NextResponse.json({ success: false, error: expiryError }, { status: 400 });
    }

    const document = await loadDocument(id);
    if (!document || document.is_deleted) {
      return NextResponse.json({ success: false, error: 'Document not found' }, { status: 404 });
    }

    const token = generateShareToken();
    const tokenHash = hashShareToken(token);
    const allowDownload = parsed.data.allow_download ?? true;
    const watermarkEnabled = parsed.data.watermark_enabled ?? true;
    const maxViews = parsed.data.max_views ?? null;

    let created: ShareLink;

    if (!isSupabaseConfigured()) {
      created = await mutateStore((store) => {
        const link: ShareLink = {
          id: randomUUID(),
          document_id: id,
          token_hash: tokenHash,
          label: parsed.data.label || null,
          created_by: user.id,
          created_at: new Date(now).toISOString(),
          expires_at: new Date(expiresMs).toISOString(),
          revoked_at: null,
          revoked_by: null,
          access_count: 0,
          max_access_count: maxViews,
          last_accessed_at: null,
          allow_download: allowDownload,
          watermark_enabled: watermarkEnabled,
        };
        store.share_links.push(link);
        return link;
      });
    } else {
      const supabase = await createClient();
      const { data, error } = await supabase
        .from('share_links')
        .insert({
          document_id: id,
          token_hash: tokenHash,
          label: parsed.data.label || null,
          created_by: user.id,
          created_at: new Date(now).toISOString(),
          expires_at: new Date(expiresMs).toISOString(),
          max_access_count: maxViews,
          allow_download: allowDownload,
          watermark_enabled: watermarkEnabled,
        })
        .select()
        .single();

      if (error || !data) {
        console.error('[SHARE] insert failed:', error?.message);
        return NextResponse.json({ success: false, error: 'Failed to create share link' }, { status: 500 });
      }
      created = data as ShareLink;
    }

    await logAuditEvent({
      actorId: user.id,
      actorEmail: user.email,
      documentId: id,
      action: 'share_link_created',
      result: 'allowed',
      ipAddress,
      userAgent,
      details: {
        share_link_id: created.id,
        label: created.label,
        expires_at: created.expires_at,
        max_views: created.max_access_count,
        allow_download: created.allow_download,
        // The token itself is never logged: the audit trail is readable by admins,
        // and a link id in a log must not be a usable credential.
        decision: 'human_confirmed',
      },
    });

    return NextResponse.json({
      success: true,
      data: {
        link: toLinkView(created),
        // Returned exactly once. Re-issuing is the only way to get a new URL.
        token,
        url: buildShareUrl(token),
      },
    }, { status: 201 });
  } catch (err: unknown) {
    if (err instanceof AuthorizationError) {
      return NextResponse.json({ success: false, error: err.message }, { status: err.statusCode });
    }
    return NextResponse.json({ success: false, error: 'Internal server error' }, { status: 500 });
  }
}
