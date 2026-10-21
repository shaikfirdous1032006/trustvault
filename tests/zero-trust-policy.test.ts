import { describe, it, expect, beforeEach } from 'vitest';
import {
  evaluateZeroTrustPolicy,
  applyTemporaryRestriction,
  clearTemporaryRestriction,
  getActiveRestriction,
} from '@/lib/policy-engine';

describe('Adaptive Zero-Trust Policy Engine', () => {
  const baseContext = {
    userId: 'usr-alice',
    userRole: 'viewer' as const,
    isActive: true,
    documentId: 'doc-test-1',
    documentOwnerId: 'usr-bob',
    documentSensitivity: 'internal' as const,
    isDeleted: false,
    requiredLevel: 'read' as const,
    action: 'preview' as const,
  };

  beforeEach(() => {
    clearTemporaryRestriction('usr-alice');
    clearTemporaryRestriction('usr-attacker');
  });

  it('denies access immediately when the user account is inactive', () => {
    const decision = evaluateZeroTrustPolicy({
      ...baseContext,
      isActive: false,
    });

    expect(decision.outcome).toBe('DENY');
    expect(decision.allowed).toBe(false);
    expect(decision.reasonCode).toBe('ACCOUNT_DEACTIVATED');
    expect(decision.riskScore).toBe(100);
  });

  it('denies access when the target document is deleted', () => {
    const decision = evaluateZeroTrustPolicy({
      ...baseContext,
      isDeleted: true,
    });

    expect(decision.outcome).toBe('DENY');
    expect(decision.allowed).toBe(false);
    expect(decision.reasonCode).toBe('DOCUMENT_DELETED');
  });

  it('allows access unconditionally for the document owner', () => {
    const decision = evaluateZeroTrustPolicy({
      ...baseContext,
      userId: 'usr-bob',
      documentOwnerId: 'usr-bob',
      userRole: 'owner',
    });

    expect(decision.outcome).toBe('ALLOW');
    expect(decision.allowed).toBe(true);
    expect(decision.reasonCode).toBe('ACCESS_GRANTED');
    expect(decision.riskScore).toBe(0);
  });

  it('allows access when a valid unexpired grant exists', () => {
    const grants = [
      {
        user_id: 'usr-alice',
        permission_level: 'read',
        revoked_at: null,
        expires_at: new Date(Date.now() + 3600_000).toISOString(),
      },
    ];

    const decision = evaluateZeroTrustPolicy(baseContext, grants);

    expect(decision.outcome).toBe('ALLOW');
    expect(decision.allowed).toBe(true);
  });

  it('triggers a temporary restriction when repeated unauthorized probing is detected', () => {
    const decision = evaluateZeroTrustPolicy({
      ...baseContext,
      userId: 'usr-attacker',
      recentDeniedCount: 5,
      documentSensitivity: 'confidential',
    }, []);

    expect(decision.outcome).toBe('TEMPORARILY_RESTRICT');
    expect(decision.allowed).toBe(false);
    expect(decision.reasonCode).toBe('PROBING_TRIGGERED_RESTRICTION');
    expect(decision.riskScore).toBeGreaterThanOrEqual(75);

    // Verify restriction is persisted in memory store
    const active = getActiveRestriction('usr-attacker');
    expect(active).not.toBeNull();
  });

  it('blocks access when an active restriction is in place', () => {
    applyTemporaryRestriction('usr-alice', 'Suspicious exfiltration activity', 10, 95);

    const decision = evaluateZeroTrustPolicy(baseContext);

    expect(decision.outcome).toBe('TEMPORARILY_RESTRICT');
    expect(decision.allowed).toBe(false);
    expect(decision.reasonCode).toBe('TEMPORARILY_RESTRICTED');
  });

  it('restores normal evaluation when an administrator clears the restriction', () => {
    applyTemporaryRestriction('usr-alice', 'Investigating alert', 10);
    expect(getActiveRestriction('usr-alice')).not.toBeNull();

    clearTemporaryRestriction('usr-alice');
    expect(getActiveRestriction('usr-alice')).toBeNull();

    const grants = [
      {
        user_id: 'usr-alice',
        permission_level: 'read',
        revoked_at: null,
        expires_at: null,
      },
    ];
    const decision = evaluateZeroTrustPolicy(baseContext, grants);
    expect(decision.outcome).toBe('ALLOW');
  });

  it('requires review when authorized user exhibits an abnormal download burst', () => {
    const grants = [
      {
        user_id: 'usr-alice',
        permission_level: 'read',
        revoked_at: null,
        expires_at: null,
      },
    ];

    const decision = evaluateZeroTrustPolicy({
      ...baseContext,
      recentDownloadBurst: 10,
      documentSensitivity: 'restricted',
    }, grants);

    expect(decision.outcome).toBe('REQUIRE_REVIEW');
    expect(decision.allowed).toBe(false);
    expect(decision.riskFactors.some((f) => f.includes('Abnormal download burst'))).toBe(true);
  });
});
