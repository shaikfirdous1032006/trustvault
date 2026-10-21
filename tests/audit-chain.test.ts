import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { logAuditEvent, verifyAuditChain } from '@/lib/audit';
import { getStore, mutateStore } from '@/lib/local-db';
import type { AuditEvent } from '@/lib/types';

/**
 * Production code is imported here, never re-implemented. If src/lib/audit.ts
 * stops linking events, or the writer stops serialising appends, these fail.
 */
describe('audit hash chain', () => {
  let snapshot: AuditEvent[];

  beforeEach(async () => {
    snapshot = JSON.parse(JSON.stringify(getStore().audit));
    expect(snapshot.length).toBeGreaterThan(0);
  });

  afterEach(async () => {
    const restore = snapshot;
    await mutateStore((store) => {
      store.audit = JSON.parse(JSON.stringify(restore));
    });
  });

  it('keeps the chain strictly linked when callers append concurrently', async () => {
    // Asserts the invariant the writer exists to protect: one head, one predecessor
    // per event, no row dropped. In a single Node process the old synchronous writer
    // also satisfied this, so this test is a regression guard for the lock, not
    // proof that the lock fixed an in-process race.
    const before = getStore().audit.length;
    const APPENDS = 24;

    await Promise.all(
      Array.from({ length: APPENDS }, (_, i) =>
        logAuditEvent({
          actorId: 'usr-concurrency-test',
          actorEmail: 'load@example.com',
          action: 'download',
          result: i % 2 === 0 ? 'allowed' : 'denied',
          details: { seq: i },
        })
      )
    );

    expect(getStore().audit.length).toBe(before + APPENDS);
    expect(await verifyAuditChain()).toMatchObject({ valid: true, mismatches: [] });

    // A lost write shows up as two rows sharing one prev_hash, so walk the
    // persisted array and assert the links are strictly sequential and unique.
    const seen = new Set<string>();
    let prev: string | null = null;
    for (const event of getStore().audit) {
      expect(seen.has(event.event_hash)).toBe(false);
      seen.add(event.event_hash);
      expect(event.prev_hash).toBe(prev);
      prev = event.event_hash;
    }
  });

  it('reports the first invalid event when a payload is rewritten', async () => {
    expect(await verifyAuditChain()).toMatchObject({ valid: true, firstInvalid: null });

    const target = getStore().audit[1];
    await mutateStore((store) => {
      store.audit[1].details_jsonb = { forged: true };
    });

    const result = await verifyAuditChain();
    expect(result.valid).toBe(false);
    expect(result.firstInvalid).toBe(target.id);
  });

  it('detects an event rewired away from the genesis without relying on timestamps', async () => {
    const broken = getStore().audit[2];
    await mutateStore((store) => {
      store.audit[2].prev_hash = 'f'.repeat(64);
    });

    const result = await verifyAuditChain();
    expect(result.valid).toBe(false);
    expect(result.mismatches.some((m) => m.id === broken.id)).toBe(true);
  });

  it('detects a forked chain head', async () => {
    const head = getStore().audit[getStore().audit.length - 1];
    await mutateStore((store) => {
      store.audit.push({
        ...head,
        id: 'forked-event',
        occurred_at: new Date().toISOString(),
        details_jsonb: { forked: true },
        request_id: 'fork-request',
      });
    });

    const result = await verifyAuditChain();
    expect(result.valid).toBe(false);
    expect(result.mismatches.some((m) => m.expected.includes('only one event extends'))).toBe(true);
  });

  it('derives every hash from the current chain head instead of trusting callers', async () => {
    const before = getStore().audit.length;
    await logAuditEvent({
      actorId: 'usr-attempt',
      actorEmail: 'load@example.com',
      action: 'admin_action',
      result: 'denied',
      details: { attempt: 'client supplied hashes' },
    });

    const appended = getStore().audit[before];
    expect(getStore().audit.length).toBe(before + 1);
    expect(appended.prev_hash).toBe(getStore().audit[before - 1].event_hash);
    expect((await verifyAuditChain()).valid).toBe(true);
  });

  it('still verifies a healthy chain when a clock step lands inside the log', async () => {
    // occurred_at is hashed but is not the sequence. When an NTP correction (or a
    // container whose clock was stepped back) makes a newly appended event carry an
    // earlier timestamp than its predecessor, verification that sorts by timestamp
    // reads the reordered rows as a broken chain and cries tamper over healthy data.
    const headBefore = getStore().audit[getStore().audit.length - 1].occurred_at;
    vi.setSystemTime(new Date(Date.parse(headBefore) - 600_000));
    try {
      await logAuditEvent({
        actorId: 'usr-skew',
        actorEmail: 'load@example.com',
        action: 'preview',
        result: 'allowed',
        details: { clock_skew: true },
      });
    } finally {
      vi.useRealTimers();
    }

    const skewed = getStore().audit[getStore().audit.length - 1];
    expect(skewed.occurred_at < headBefore).toBe(true);
    expect(await verifyAuditChain()).toMatchObject({ valid: true, firstInvalid: null });
  });
});
