import { createHash, randomBytes } from 'crypto';
import type { Document, ShareLink } from '@/lib/types';

/** 256 bits of entropy, rendered as 43 base64url characters. */
export const SHARE_TOKEN_BYTES = 32;
export const SHARE_TOKEN_PATTERN = /^[A-Za-z0-9_-]{40,44}$/;

export const MIN_SHARE_LIFETIME_MS = 60_000;
export const MAX_SHARE_LIFETIME_MS = 365 * 24 * 60 * 60 * 1000;

/**
 * Mint a link token. The caller gets this string once; nothing downstream may
 * persist it.
 */
export function generateShareToken(): string {
  return randomBytes(SHARE_TOKEN_BYTES).toString('base64url');
}

/**
 * Tokens are looked up by digest, so the store holds no reversible form of the
 * credential. An attacker who reads the table still has to brute force 2^256 to
 * find a live token.
 */
export function hashShareToken(token: string): string {
  return createHash('sha256').update(token, 'utf8').digest('hex');
}

export function isWellFormedToken(token: string): boolean {
  return SHARE_TOKEN_PATTERN.test(token);
}

export type ShareDenyReason =
  | 'malformed_token'
  | 'not_found'
  | 'revoked'
  | 'expired'
  | 'exhausted'
  | 'download_forbidden'
  | 'document_unavailable';

export type ShareAccessDecision = { allowed: true } | { allowed: false; reason: ShareDenyReason };

/**
 * Decide whether a bearer token may read a document right now.
 *
 * Pure and clock-injected so revocation and expiry are testable without waiting:
 * every rule is re-derived from the stored row on each call, which is what makes
 * revocation take effect on the next request instead of when the link was opened.
 */
export function evaluateShareLink(params: {
  link: ShareLink | null | undefined;
  document: Pick<Document, 'is_deleted'> | null | undefined;
  wantsDownload: boolean;
  nowMs: number;
}): ShareAccessDecision {
  const { link, document, wantsDownload, nowMs } = params;

  if (!link) return { allowed: false, reason: 'not_found' };
  if (!document || document.is_deleted) return { allowed: false, reason: 'document_unavailable' };
  // Exhaustion is tested before revocation because closing a capped link writes
  // revoked_at: checking revocation first would misreport "used up" as "revoked
  // by its owner", which is a different fact for the recipient and for the audit.
  if (link.max_access_count !== null && link.access_count >= link.max_access_count) {
    return { allowed: false, reason: 'exhausted' };
  }
  if (link.revoked_at) return { allowed: false, reason: 'revoked' };
  if (new Date(link.expires_at).getTime() <= nowMs) return { allowed: false, reason: 'expired' };
  if (wantsDownload && !link.allow_download) return { allowed: false, reason: 'download_forbidden' };

  return { allowed: true };
}

/**
 * Public URL handed to the recipient. Requires the app origin, because a relative
 * link is useless to someone who has no account on this deployment.
 */
export function buildShareUrl(token: string): string {
  const base = process.env.NEXT_PUBLIC_APP_URL;
  if (!base) {
    throw new Error('NEXT_PUBLIC_APP_URL is not set; cannot build an absolute share URL.');
  }
  return `${base.replace(/\/+$/, '')}/share/${token}`;
}

export function shareExpiryError(expiresAtMs: number, nowMs: number): string | null {
  const lifetime = expiresAtMs - nowMs;
  if (!Number.isFinite(expiresAtMs)) return 'expires_at must be a valid timestamp';
  if (lifetime <= 0) return 'expires_at must be in the future';
  if (lifetime < MIN_SHARE_LIFETIME_MS) return `links must stay live for at least ${MIN_SHARE_LIFETIME_MS / 1000} seconds`;
  if (lifetime > MAX_SHARE_LIFETIME_MS) return 'links may not outlive one year';
  return null;
}

/**
 * Status codes and copy for a bearer request that was refused. Every reason other
 * than "this token is not a token" collapses to a message that confirms only that
 * the holder once had a valid link, and never names the document.
 */
export function shareDenyResponse(reason: ShareDenyReason): { status: number; message: string } {
  switch (reason) {
    case 'malformed_token':
    case 'not_found':
      return { status: 404, message: 'This link does not exist.' };
    case 'revoked':
      return { status: 410, message: 'This link was revoked by its owner.' };
    case 'expired':
      return { status: 410, message: 'This link has expired.' };
    case 'exhausted':
      return { status: 410, message: 'This link has been used up.' };
    case 'document_unavailable':
      return { status: 404, message: 'The document behind this link is no longer available.' };
    case 'download_forbidden':
      return { status: 403, message: 'This link allows viewing only.' };
  }
}
