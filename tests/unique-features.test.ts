import { describe, it, expect, beforeEach } from 'vitest';
import { evaluateDocumentPermission } from '@/lib/permission';
import { getStore, mutateStore, appendAudit, sha256 } from '@/lib/local-db';
import { verifyAuditChain } from '@/lib/audit';

describe('TrustVault Unique Features Suite', () => {
  describe('Feature 1: Ephemeral Grants & Burn-After-Reading', () => {
    const document = {
      id: 'doc-confidential-100',
      owner_id: 'user-owner-1',
      is_deleted: false,
    };

    it('allows access when access_count is below max_access_count', () => {
      const decision = evaluateDocumentPermission({
        document,
        grants: [
          {
            user_id: 'user-auditor-1',
            permission_level: 'read',
            revoked_at: null,
            expires_at: null,
            max_access_count: 1, // Single-use burn after reading
            access_count: 0,
          },
        ],
        userId: 'user-auditor-1',
        requiredLevel: 'read',
      });

      expect(decision.allowed).toBe(true);
      expect(decision.reason).toContain('Has read permission');
    });

    it('immediately denies access once single-use grant count reaches threshold', () => {
      const decision = evaluateDocumentPermission({
        document,
        grants: [
          {
            user_id: 'user-auditor-1',
            permission_level: 'read',
            revoked_at: null,
            expires_at: null,
            max_access_count: 1,
            access_count: 1, // Already read once
          },
        ],
        userId: 'user-auditor-1',
        requiredLevel: 'read',
      });

      expect(decision.allowed).toBe(false);
      expect(decision.reason).toBe('Single-use / access count limit reached');
    });

    it('enforces multi-use threshold (e.g. 3-times access inspection)', () => {
      const grants = [
        {
          user_id: 'user-contractor-1',
          permission_level: 'read',
          revoked_at: null,
          expires_at: null,
          max_access_count: 3,
          access_count: 2,
        },
      ];

      // 3rd attempt allowed
      expect(
        evaluateDocumentPermission({
          document,
          grants,
          userId: 'user-contractor-1',
          requiredLevel: 'read',
        }).allowed
      ).toBe(true);

      // 4th attempt denied
      grants[0].access_count = 3;
      const fourthAttempt = evaluateDocumentPermission({
        document,
        grants,
        userId: 'user-contractor-1',
        requiredLevel: 'read',
      });
      expect(fourthAttempt.allowed).toBe(false);
      expect(fourthAttempt.reason).toBe('Single-use / access count limit reached');
    });
  });

  describe('Feature 2: Cryptographic Compliance Proofs & Tamper Detection', () => {
    it('detects unauthorized tampering with audit records', async () => {
      // First, verify baseline chain is valid
      const initial = await verifyAuditChain();
      expect(initial.valid).toBe(true);

      const store = getStore();
      expect(store.audit.length).toBeGreaterThan(0);

      // Tamper with the details of the first event without recomputing event_hash
      const originalActorId = store.audit[0].actor_id;
      const originalDetails = { ...store.audit[0].details_jsonb };
      await mutateStore((s) => {
        s.audit[0].actor_id = 'usr-malicious-adversary';
        s.audit[0].details_jsonb = { forged: true, exfiltrated: true };
      });

      const tamperedCheck = await verifyAuditChain();
      expect(tamperedCheck.valid).toBe(false);
      expect(tamperedCheck.mismatches.length).toBeGreaterThan(0);
      expect(tamperedCheck.mismatches[0].id).toBe(store.audit[0].id);

      // Restore to authentic state
      await mutateStore((s) => {
        s.audit[0].actor_id = originalActorId;
        s.audit[0].details_jsonb = originalDetails;
      });
      const restoredCheck = await verifyAuditChain();
      expect(restoredCheck.valid).toBe(true);
    });

    it('generates reproducible cryptographic proof signatures', () => {
      const certId = 'TV-CERT-DEMO-001';
      const docId = 'demo-doc-1';
      const checksum = '7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069';
      const headHash = '35e4d773df0d463b2cf7fae44621c0ad146e273f5fffe7c9171f11a87de7e01d';
      const issuedAt = '2026-10-20T12:00:00.000Z';

      const sig1 = sha256(
        JSON.stringify({
          certId,
          documentId: docId,
          checksum,
          headHash,
          issuedAt,
          eventsCount: 5,
        })
      );

      const sig2 = sha256(
        JSON.stringify({
          certId,
          documentId: docId,
          checksum,
          headHash,
          issuedAt,
          eventsCount: 5,
        })
      );

      expect(sig1).toBe(sig2);
      expect(sig1).toHaveLength(64);
    });
  });
});
