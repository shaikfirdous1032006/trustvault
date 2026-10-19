import { createAdminClient } from '@/lib/supabase/server';
import type { AuditAction, AuditResult } from '@/lib/types';
import { createHash } from 'crypto';
import { v4 as uuidv4 } from 'uuid';

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
  const supabaseAdmin = createAdminClient();
  const requestId = params.requestId || uuidv4();
  const occurredAt = new Date().toISOString();
  const detailsJson = JSON.stringify(params.details || {});

  try {
    // Get the previous event hash for chain continuity
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
      // Log to server console but don't fail the request
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
export async function verifyAuditChain(): Promise<{
  valid: boolean;
  mismatches: Array<{ id: string; expected: string; actual: string }>;
}> {
  const supabaseAdmin = createAdminClient();

  const { data: events, error } = await supabaseAdmin
    .from('audit_events')
    .select('*')
    .order('occurred_at', { ascending: true });

  if (error || !events) {
    return { valid: false, mismatches: [{ id: 'query_error', expected: '', actual: error?.message || 'Unknown error' }] };
  }

  const mismatches: Array<{ id: string; expected: string; actual: string }> = [];
  let prevHash: string | null = null;

  for (const event of events) {
    const detailsJson = JSON.stringify(event.details_jsonb || {});
    const expectedHash = computeEventHash(
      event.occurred_at,
      event.actor_id,
      event.document_id,
      event.action,
      event.result,
      detailsJson,
      prevHash
    );

    if (event.event_hash !== expectedHash) {
      mismatches.push({
        id: event.id,
        expected: expectedHash,
        actual: event.event_hash,
      });
    }

    if (event.prev_hash !== prevHash) {
      mismatches.push({
        id: event.id,
        expected: `prev_hash should be ${prevHash}`,
        actual: event.prev_hash || 'null',
      });
    }

    prevHash = event.event_hash;
  }

  return { valid: mismatches.length === 0, mismatches };
}
