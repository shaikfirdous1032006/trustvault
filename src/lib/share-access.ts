import { createAdminClient, isSupabaseConfigured } from '@/lib/supabase/server';
import { findShareLinkByTokenHash, getStore, mutateStore } from '@/lib/local-db';
import {
  evaluateShareLink,
  hashShareToken,
  isWellFormedToken,
  type ShareDenyReason,
} from '@/lib/share';
import type { Document, ShareLink } from '@/lib/types';

export type ShareResolution =
  | { allowed: true; link: ShareLink; document: Document; autoRevoked: boolean }
  | { allowed: false; reason: ShareDenyReason; documentId: string | null };

type LocalOutcome =
  | { kind: 'ok'; link: ShareLink; document: Document; autoRevoked: boolean }
  | { kind: 'denied'; reason: ShareDenyReason; documentId: string | null };

/**
 * Turn a bearer token into an authorisation decision.
 *
 * There is no session, no cookie and no cache on this path: every request hashes
 * the presented token, re-reads the stored row and re-runs the rules, so revoking
 * a link takes effect on the next request that arrives.
 *
 * A refusal still carries the document id when the token resolved to a link,
 * because "someone knocked on this document with a dead link at 03:12" is exactly
 * the evidence the audit trail is supposed to keep.
 */
export async function resolveShare(token: string, wantsDownload: boolean): Promise<ShareResolution> {
  // Reject junk before spending a hash on it, and never let an over-long "token"
  // turn this endpoint into a cheap CPU target.
  if (!isWellFormedToken(token)) return { allowed: false, reason: 'malformed_token', documentId: null };

  const tokenHash = hashShareToken(token);

  if (!isSupabaseConfigured()) {
    const candidate = findShareLinkByTokenHash(tokenHash);
    if (!candidate) return { allowed: false, reason: 'not_found', documentId: null };

    const document = getStore().documents.find((d) => d.id === candidate.document_id);
    const preCheck = evaluateShareLink({
      link: candidate,
      document,
      wantsDownload,
      nowMs: Date.now(),
    });
    if (!preCheck.allowed) {
      return { allowed: false, reason: preCheck.reason, documentId: candidate.document_id };
    }

    // The pre-check only decides whether a write is needed. The authoritative
    // decision happens inside the lock, because a revocation or a competing view
    // can land between the two reads.
    const outcome: LocalOutcome = await mutateStore((store) => {
      const link = store.share_links.find((l) => l.token_hash === tokenHash);
      if (!link) return { kind: 'denied', reason: 'not_found', documentId: null };

      const freshDocument = store.documents.find((d) => d.id === link.document_id);
      const decision = evaluateShareLink({
        link,
        document: freshDocument,
        wantsDownload,
        nowMs: Date.now(),
      });
      if (!decision.allowed) {
        return { kind: 'denied', reason: decision.reason, documentId: link.document_id };
      }

      const now = new Date().toISOString();
      link.access_count += 1;
      link.last_accessed_at = now;

      let autoRevoked = false;
      if (link.max_access_count !== null && link.access_count >= link.max_access_count) {
        link.revoked_at = now;
        link.revoked_by = 'system-auto-revoke';
        autoRevoked = true;
      }

      return {
        kind: 'ok',
        link: { ...link },
        document: { ...freshDocument! },
        autoRevoked,
      };
    });

    if (outcome.kind === 'denied') {
      return { allowed: false, reason: outcome.reason, documentId: outcome.documentId };
    }
    return { allowed: true, link: outcome.link, document: outcome.document, autoRevoked: outcome.autoRevoked };
  }

  const admin = createAdminClient();
  const { data, error } = await admin.rpc('resolve_share_link', {
    p_token_hash: tokenHash,
    p_wants_download: wantsDownload,
  });

  if (error || !data || data.length === 0) {
    console.error('[SHARE] resolve_share_link failed:', error?.message);
    return { allowed: false, reason: 'not_found', documentId: null };
  }

  const row = data[0] as Record<string, unknown>;
  const denied = row.denied_reason as ShareDenyReason | null;
  const rowDocumentId = row.document_id ? String(row.document_id) : null;
  if (denied) return { allowed: false, reason: denied, documentId: rowDocumentId };

  const link: ShareLink = {
    id: String(row.link_id),
    document_id: String(row.document_id),
    token_hash: tokenHash,
    label: (row.label as string | null) ?? null,
    // Provenance columns are not needed by the bearer path and are not returned by
    // the resolver, so they stay empty rather than being guessed at.
    created_by: '',
    created_at: '',
    expires_at: String(row.expires_at),
    revoked_at: null,
    revoked_by: null,
    access_count: Number(row.access_count),
    max_access_count:
      row.max_access_count === null || row.max_access_count === undefined
        ? null
        : Number(row.max_access_count),
    last_accessed_at: null,
    allow_download: Boolean(row.allow_download),
    watermark_enabled: Boolean(row.watermark_enabled),
  };

  const document = {
    id: String(row.document_id),
    title: String(row.title),
    file_name: String(row.file_name),
    mime_type: String(row.mime_type),
    file_size: Number(row.file_size),
    checksum: String(row.checksum),
    current_version: Number(row.current_version),
    storage_path: String(row.storage_path),
    is_deleted: false,
  } as unknown as Document;

  return { allowed: true, link, document, autoRevoked: false };
}

/**
 * Fetch the bytes for an already-resolved link. Only the caller that holds a live
 * link ever reaches this, and the storage key never leaves the server.
 */
export async function readShareFileBytes(document: Document): Promise<Buffer | null> {
  if (!isSupabaseConfigured()) {
    const { readFileBytes } = await import('@/lib/local-db');
    return readFileBytes(document.storage_path);
  }

  const admin = createAdminClient();
  const { data, error } = await admin.storage.from('documents').download(document.storage_path);
  if (error || !data) {
    console.error('[SHARE] storage download failed:', error?.message);
    return null;
  }
  return Buffer.from(await data.arrayBuffer());
}
