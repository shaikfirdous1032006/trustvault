import { createAdminClient, isSupabaseConfigured } from '@/lib/supabase/server';
import type { AuditAction, AuditResult } from '@/lib/types';
import { createHash } from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import { appendAudit, getStore } from '@/lib/local-db';

interface AuditLogParams {
  actorId: string | null;
  actorEmail: string | null;
  documentId?: string | null;
  action: AuditAction;
  result: AuditResult;
  ipAddress?: string | null;
  userAgent?: string | null;
  requestId?: string;
  details?: Record<string, unknown>;
}

/**
 * Compute SHA-256 hash of a string.
 */
function sha256(data: string): string {
  return createHash('sha256').update(data).digest('hex');
}

/**
 * Hash PII fields (IP, User-Agent) for privacy-preserving audit trail.
 */
function hashPii(value: string | null | undefined): string | null {
  if (!value) return null;
  return sha256(value);
}

/**
 * Compute the event hash for hash-chain integrity.
 * Canonical data: occurred_at + actor_id + document_id + action + result + details_json + prev_hash
 */
function computeEventHash(
  occurredAt: string,
  actorId: string | null,
  documentId: string | null,
  action: string,
  result: string,
  detailsJson: string,
  prevHash: string | null
): string {
  const canonical = [
    occurredAt,
    actorId ?? '',
    documentId ?? '',
    action,
    result,
    detailsJson,
    prevHash ?? '',
  ].join('|');
  return sha256(canonical);
}

/**
 * Log an audit event with hash-chain integrity.
 * Uses the admin client to bypass RLS for insert (service role).
 */
export async function logAuditEvent(params: AuditLogParams): Promise<void> {
  const requestId = params.requestId || uuidv4();
  const occurredAt = new Date().toISOString();
  const detailsJson = JSON.stringify(params.details || {});

  try {
    if (!isSupabaseConfigured()) {
      await appendAudit({
        occurred_at: occurredAt,
        actor_id: params.actorId,
        actor_email: params.actorEmail,
        document_id: params.documentId ?? null,
        action: params.action,
        result: params.result,
        ip_hash: hashPii(params.ipAddress),
        user_agent_hash: hashPii(params.userAgent),
        request_id: requestId,
        details_jsonb: params.details || {},
      });
      return;
    }

    const supabaseAdmin = createAdminClient();
    const { data: lastEvent } = await supabaseAdmin
      .from('audit_events')
      .select('event_hash')
      .order('occurred_at', { ascending: false })
      .limit(1)
      .single();

    const prevHash = lastEvent?.event_hash ?? null;

    const eventHash = computeEventHash(
      occurredAt,
      params.actorId,
      params.documentId ?? null,
      params.action,
      params.result,
      detailsJson,
      prevHash
    );

    const { error } = await supabaseAdmin.from('audit_events').insert({
      occurred_at: occurredAt,
      actor_id: params.actorId,
      actor_email: params.actorEmail,
      document_id: params.documentId ?? null,
      action: params.action,
      result: params.result,
      ip_hash: hashPii(params.ipAddress),
      user_agent_hash: hashPii(params.userAgent),
      request_id: requestId,
      details_jsonb: params.details || {},
      prev_hash: prevHash,
      event_hash: eventHash,
    });

    if (error) {
      console.error('[AUDIT] Failed to log audit event:', error.message);
    }
  } catch (err) {
    console.error('[AUDIT] Exception logging audit event:', err);
  }
}

/**
 * Verify the integrity of the audit hash chain.
 * Returns mismatched events if any.
 */
export async function verifyAuditChain(): Promise<ChainVerification> {
  if (!isSupabaseConfigured()) {
    return verifyEvents(getStore().audit);
  }

  const supabaseAdmin = createAdminClient();

  const { data: events, error } = await supabaseAdmin
    .from('audit_events')
    .select('*');

  if (error || !events) {
    const mismatches = [
      { id: 'query_error', expected: 'a readable audit_events table', actual: error?.message || 'Unknown error' },
    ];
    return { valid: false, mismatches, firstInvalid: 'query_error' };
  }

  return verifyEvents(events);
}

export type ChainMismatch = { id: string; expected: string; actual: string };

export type ChainVerification = {
  valid: boolean;
  mismatches: ChainMismatch[];
  /** id of the first event that fails verification, or null when the chain is intact. */
  firstInvalid: string | null;
};

type ChainEvent = {
  id: string;
  occurred_at: string;
  actor_id: string | null;
  document_id: string | null;
  action: string;
  result: string;
  details_jsonb: Record<string, unknown>;
  event_hash: string;
  prev_hash: string | null;
};

/**
 * Walk the chain by following prev_hash links instead of trusting an ORDER BY.
 *
 * Timestamp order is not authoritative: two events can share a millisecond, a clock
 * can step backwards, and Postgres returns rows in whatever order it likes once the
 * ORDER BY is dropped. Following the links means the chain decides its own sequence,
 * and anything the walk cannot reach was excised, rewired or forked.
 */
function verifyEvents(events: ChainEvent[]): ChainVerification {
  const mismatches: ChainMismatch[] = [];
  const childrenByPrevHash = new Map<string, ChainEvent[]>();
  const roots: ChainEvent[] = [];

  for (const event of events) {
    if (event.prev_hash === null) {
      roots.push(event);
      continue;
    }
    const siblings = childrenByPrevHash.get(event.prev_hash);
    if (siblings) siblings.push(event);
    else childrenByPrevHash.set(event.prev_hash, [event]);
  }

  if (roots.length === 0 && events.length > 0) {
    mismatches.push({
      id: events[0].id,
      expected: 'the genesis event has prev_hash = null',
      actual: `no event links to a genesis across ${events.length} rows`,
    });
  }
  if (roots.length > 1) {
    mismatches.push({
      id: roots[1].id,
      expected: 'exactly one event with prev_hash = null',
      actual: `${roots.length} events claim to be first`,
    });
  }

  const visited = new Set<string>();
  let current: ChainEvent | undefined = roots[0];

  while (current) {
    visited.add(current.id);

    const expectedHash = computeEventHash(
      current.occurred_at,
      current.actor_id,
      current.document_id,
      current.action,
      current.result,
      JSON.stringify(current.details_jsonb || {}),
      current.prev_hash
    );

    if (current.event_hash !== expectedHash) {
      mismatches.push({
        id: current.id,
        expected: expectedHash,
        actual: current.event_hash,
      });
    }

    const next: ChainEvent[] = childrenByPrevHash.get(current.event_hash) ?? [];
    if (next.length > 1) {
      mismatches.push({
        id: next[1].id,
        expected: `only one event extends ${current.id}`,
        actual: `${next.length} events share prev_hash ${current.event_hash}`,
      });
    }
    current = next[0];
  }

  for (const event of events) {
    if (visited.has(event.id) || event.prev_hash === null) continue;
    mismatches.push({
      id: event.id,
      expected: 'reachable from the genesis event through prev_hash',
      actual: `orphaned: no stored event_hash matches ${event.prev_hash}`,
    });
  }

  return {
    valid: mismatches.length === 0,
    mismatches,
    firstInvalid: mismatches.length > 0 ? mismatches[0].id : null,
  };
}
