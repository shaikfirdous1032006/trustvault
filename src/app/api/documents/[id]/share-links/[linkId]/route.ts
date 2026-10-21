import { csrfRejection } from '@/lib/security';
import { createClient, isSupabaseConfigured } from '@/lib/supabase/server';
import { requireAuth, isDocumentOwner, getRequestMeta, AuthorizationError } from '@/lib/auth';
import { logAuditEvent } from '@/lib/audit';
import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { getShareLinkById, mutateStore } from '@/lib/local-db';

type RouteParams = { params: Promise<{ id: string; linkId: string }> };

const patchSchema = z.object({
  action: z.enum(['revoke']),
});

/**
 * PATCH /api/documents/:id/share-links/:linkId  { action: "revoke" }
 *
 * Revocation writes revoked_at and nothing else. The bearer endpoint re-evaluates
 * the stored row on every request, so a link that was working moments ago stops
 * working on the next request — there is no cached grant and no token to recall.
 */
export async function PATCH(request: NextRequest, { params }: RouteParams) {
  const crossOrigin = csrfRejection(request);
  if (crossOrigin) return crossOrigin;
  const { id, linkId } = await params;
  const { ipAddress, userAgent } = await getRequestMeta();

  try {
    const user = await requireAuth();

    if (!(await isDocumentOwner(user.id, id)) && user.role !== 'admin') {
      await logAuditEvent({
        actorId: user.id,
        actorEmail: user.email,
        documentId: id,
        action: 'share_link_revoked',
        result: 'denied',
        ipAddress,
        userAgent,
        details: { share_link_id: linkId, reason: 'Not document owner' },
      });
      return NextResponse.json(
        { success: false, error: 'Only the document owner can revoke share links' },
        { status: 403 }
      );
    }

    const parsed = patchSchema.safeParse(await request.json().catch(() => ({})));
    if (!parsed.success) {
      return NextResponse.json(
        { success: false, error: 'Invalid request. Expected { action: "revoke" }' },
        { status: 400 }
      );
    }

    const link = getShareLinkById(linkId);
    if (!link || link.document_id !== id) {
      return NextResponse.json({ success: false, error: 'Share link not found' }, { status: 404 });
    }

    if (isSupabaseConfigured()) {
      const supabase = await createClient();
      const { data, error } = await supabase
        .from('share_links')
        .update({ revoked_at: new Date().toISOString(), revoked_by: user.id })
        .eq('id', linkId)
        .eq('document_id', id)
        .select('id, revoked_at')
        .maybeSingle();

      if (error || !data) {
        return NextResponse.json({ success: false, error: 'Failed to revoke share link' }, { status: 500 });
      }
    } else {
      await mutateStore((store) => {
        const target = store.share_links.find((l) => l.id === linkId && l.document_id === id);
        if (!target) return;
        target.revoked_at = new Date().toISOString();
        target.revoked_by = user.id;
      });
    }

    await logAuditEvent({
      actorId: user.id,
      actorEmail: user.email,
      documentId: id,
      action: 'share_link_revoked',
      result: 'allowed',
      ipAddress,
      userAgent,
      details: {
        share_link_id: linkId,
        label: link.label,
        was_already_revoked: Boolean(link.revoked_at),
      },
    });

    return NextResponse.json({ success: true, message: 'Share link revoked' });
  } catch (err: unknown) {
    if (err instanceof AuthorizationError) {
      return NextResponse.json({ success: false, error: err.message }, { status: err.statusCode });
    }
    return NextResponse.json({ success: false, error: 'Internal server error' }, { status: 500 });
  }
}
