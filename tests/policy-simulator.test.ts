import { describe, it, expect, beforeEach } from 'vitest';
import { simulatePolicyChange } from '@/lib/policy-simulator';
import { DEMO_IDS, getStore } from '@/lib/local-db';

describe('Access Policy Simulator', () => {
  beforeEach(() => {
    // Ensure store is loaded
    getStore();
  });

  it('simulates granting read permission to a viewer', () => {
    const store = getStore();
    const doc = store.documents[0];

    const result = simulatePolicyChange(
      {
        targetUserId: DEMO_IDS.viewer,
        documentId: doc.id,
        proposedPermissionLevel: 'read',
        expiresInHours: 24,
      },
      DEMO_IDS.admin
    );

    expect(result.simulationId).toMatch(/^sim-/);
    expect(result.targetUser.email).toBe('viewer@example.com');
    expect(result.projectedAccess).toBe('read');
    expect(result.accessDelta).toBeDefined();
    expect(result.projectedOutcome).toBe('ALLOW');
  });

  it('identifies risk when elevating a viewer to edit permissions', () => {
    const store = getStore();
    const doc = store.documents[0];

    const result = simulatePolicyChange(
      {
        targetUserId: DEMO_IDS.viewer,
        documentId: doc.id,
        proposedPermissionLevel: 'edit',
      },
      DEMO_IDS.admin
    );

    expect(result.projectedAccess).toBe('edit');
    expect(result.potentialRisks.some((r) => r.includes('Viewer role elevated to edit'))).toBe(true);
  });

  it('identifies risk when granting indefinite access without expiration', () => {
    const store = getStore();
    const doc = store.documents[0];

    const result = simulatePolicyChange(
      {
        targetUserId: DEMO_IDS.viewer,
        documentId: doc.id,
        proposedPermissionLevel: 'read',
        expiresInHours: null,
      },
      DEMO_IDS.admin
    );

    expect(result.potentialRisks.some((r) => r.includes('indefinite access'))).toBe(true);
  });

  it('rejects simulation for non-existent document or user', () => {
    expect(() =>
      simulatePolicyChange(
        {
          targetUserId: 'usr-nonexistent',
          documentId: 'doc-nonexistent',
          proposedPermissionLevel: 'read',
        },
        DEMO_IDS.admin
      )
    ).toThrow();
  });
});
