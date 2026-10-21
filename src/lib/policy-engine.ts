import { randomUUID } from 'node:crypto';
import type {
  ZeroTrustEvaluationContext,
  ZeroTrustDecision,
  PolicyOutcome,
  DocumentSensitivity,
} from '@/lib/types';
import { evaluateDocumentPermission } from '@/lib/permission';

export const POLICY_ENGINE_VERSION = '2.4.0-zt';

/**
 * Temporary restriction store for actors who have tripped high-risk thresholds.
 * In a distributed setup this would be Redis/DB backed; here it is memory-managed with TTL.
 */
interface ActiveRestriction {
  userId: string;
  reason: string;
  restrictedUntil: number; // timestamp ms
  riskScore: number;
}

const activeRestrictions = new Map<string, ActiveRestriction>();

/**
 * Applies or updates a temporary restriction on an actor.
 */
export function applyTemporaryRestriction(
  userId: string,
  reason: string,
  durationMinutes: number = 15,
  riskScore: number = 85
): ActiveRestriction {
  const restriction: ActiveRestriction = {
    userId,
    reason,
    restrictedUntil: Date.now() + durationMinutes * 60_000,
    riskScore,
  };
  activeRestrictions.set(userId, restriction);
  return restriction;
}

/**
 * Clears a temporary restriction (recovery procedure).
 */
export function clearTemporaryRestriction(userId: string): boolean {
  return activeRestrictions.delete(userId);
}

/**
 * Gets active restriction if not expired.
 */
export function getActiveRestriction(userId: string): ActiveRestriction | null {
  const restriction = activeRestrictions.get(userId);
  if (!restriction) return null;
  if (Date.now() > restriction.restrictedUntil) {
    activeRestrictions.delete(userId);
    return null;
  }
  return restriction;
}

/**
 * Adaptive Zero-Trust Policy Engine
 *
 * Enforces least-privilege deterministic authorization combined with
 * dynamic behavioral risk evaluation. Every decision is logged with a unique
 * decision identifier and reason code.
 */
export function evaluateZeroTrustPolicy(
  context: ZeroTrustEvaluationContext,
  documentGrants: Array<{
    user_id: string;
    permission_level: string;
    revoked_at: string | null;
    expires_at: string | null;
    max_access_count?: number | null;
    access_count?: number;
  }> = []
): ZeroTrustDecision {
  const decisionId = `dec-${randomUUID()}`;
  const now = context.now ?? new Date();
  const sensitivity: DocumentSensitivity = context.documentSensitivity ?? 'internal';
  const riskFactors: string[] = [];
  let riskScore = 0;

  // 1. Account active check
  if (!context.isActive) {
    return {
      decisionId,
      outcome: 'DENY',
      allowed: false,
      reasonCode: 'ACCOUNT_DEACTIVATED',
      explanation: 'User account has been deactivated by an administrator.',
      policyVersion: POLICY_ENGINE_VERSION,
      riskScore: 100,
      riskFactors: ['Inactive account attempted resource access'],
      timestamp: now.toISOString(),
      evaluatedContext: {
        userId: context.userId,
        action: context.action,
        documentId: context.documentId,
        sensitivity,
      },
    };
  }

  // 2. Active security restrictions check
  const existingRestriction = getActiveRestriction(context.userId);
  if (existingRestriction || context.hasActiveRestriction) {
    const reason = existingRestriction?.reason || 'Account under temporary security restriction';
    return {
      decisionId,
      outcome: 'TEMPORARILY_RESTRICT',
      allowed: false,
      reasonCode: 'TEMPORARILY_RESTRICTED',
      explanation: `Access blocked: ${reason}.`,
      policyVersion: POLICY_ENGINE_VERSION,
      riskScore: existingRestriction?.riskScore || 90,
      riskFactors: [`Temporary restriction in effect until ${existingRestriction ? new Date(existingRestriction.restrictedUntil).toLocaleTimeString() : 'review'}`],
      timestamp: now.toISOString(),
      evaluatedContext: {
        userId: context.userId,
        action: context.action,
        documentId: context.documentId,
        sensitivity,
      },
    };
  }

  // 3. Document deletion check
  if (context.isDeleted) {
    return {
      decisionId,
      outcome: 'DENY',
      allowed: false,
      reasonCode: 'DOCUMENT_DELETED',
      explanation: 'Requested document has been moved to trash or deleted.',
      policyVersion: POLICY_ENGINE_VERSION,
      riskScore: 15,
      riskFactors: ['Access attempt on deleted entity'],
      timestamp: now.toISOString(),
      evaluatedContext: {
        userId: context.userId,
        action: context.action,
        documentId: context.documentId,
        sensitivity,
      },
    };
  }

  // 4. Deterministic permission evaluation (Base Layer)
  let basePermissionAllowed = false;
  let baseReason = 'No active permission grant found';

  if (context.documentOwnerId && context.documentOwnerId === context.userId) {
    basePermissionAllowed = true;
    baseReason = 'Document owner';
  } else if (context.documentId) {
    const permResult = evaluateDocumentPermission({
      document: {
        id: context.documentId,
        owner_id: context.documentOwnerId || '',
        is_deleted: Boolean(context.isDeleted),
      },
      grants: documentGrants,
      userId: context.userId,
      requiredLevel: context.requiredLevel,
      now,
    });
    basePermissionAllowed = permResult.allowed;
    baseReason = permResult.reason;
  }

  if (!basePermissionAllowed) {
    // If not allowed, risk scoring accounts for probing activity
    if (context.recentDeniedCount && context.recentDeniedCount >= 3) {
      riskScore += 35;
      riskFactors.push(`Repeated denied access pattern (${context.recentDeniedCount} recent denials)`);
    }

    if (sensitivity === 'confidential' || sensitivity === 'restricted') {
      riskScore += 25;
      riskFactors.push(`Unauthorized probe targeted ${sensitivity} sensitivity document`);
    }

    // Check if probing requires auto-temporary restriction
    if (riskScore >= 60 || (context.recentDeniedCount && context.recentDeniedCount >= 5)) {
      applyTemporaryRestriction(
        context.userId,
        'High frequency unauthorized probing against sensitive documents',
        10,
        riskScore
      );
      return {
        decisionId,
        outcome: 'TEMPORARILY_RESTRICT',
        allowed: false,
        reasonCode: 'PROBING_TRIGGERED_RESTRICTION',
        explanation: 'Repeated unauthorized access attempts triggered a temporary automated restriction.',
        policyVersion: POLICY_ENGINE_VERSION,
        riskScore: Math.min(100, riskScore + 30),
        riskFactors: [...riskFactors, 'Automated risk policy threshold exceeded'],
        timestamp: now.toISOString(),
        evaluatedContext: {
          userId: context.userId,
          action: context.action,
          documentId: context.documentId,
          sensitivity,
        },
      };
    }

    return {
      decisionId,
      outcome: 'DENY',
      allowed: false,
      reasonCode: 'INSUFFICIENT_PERMISSION',
      explanation: baseReason,
      policyVersion: POLICY_ENGINE_VERSION,
      riskScore: Math.min(100, riskScore + 10),
      riskFactors,
      timestamp: now.toISOString(),
      evaluatedContext: {
        userId: context.userId,
        action: context.action,
        documentId: context.documentId,
        sensitivity,
      },
    };
  }

  // 5. Dynamic Behavioral Risk Evaluation on Authorized Requests
  // Even with valid permission, evaluate exfiltration risk or anomalous access
  if (context.recentDownloadBurst && context.recentDownloadBurst >= 8) {
    riskScore += context.recentDownloadBurst >= 10 ? 60 : 45;
    riskFactors.push(`Abnormal download burst detected (${context.recentDownloadBurst} recent downloads)`);
  }

  if (sensitivity === 'restricted' && context.userRole === 'viewer') {
    riskScore += 15;
    riskFactors.push('Viewer accessing restricted-tier document');
  }

  if (context.action === 'delete' && context.userRole !== 'admin' && context.documentOwnerId !== context.userId) {
    riskScore += 50;
    riskFactors.push('Non-owner delete attempt on shared resource');
  }

  // Evaluate risk outcomes
  let outcome: PolicyOutcome = 'ALLOW';
  let explanation = 'Access permitted under authoritative policy';
  let reasonCode = 'ACCESS_GRANTED';

  if (riskScore >= 75) {
    outcome = 'REQUIRE_REVIEW';
    explanation = 'Access requires security verification due to anomalous activity patterns.';
    reasonCode = 'RISK_THRESHOLD_EXCEEDED';
  } else if (riskScore >= 45) {
    explanation = 'Access granted with elevated security logging.';
    reasonCode = 'ACCESS_GRANTED_ELEVATED_LOGGING';
  }

  return {
    decisionId,
    outcome,
    allowed: outcome === 'ALLOW',
    reasonCode,
    explanation,
    policyVersion: POLICY_ENGINE_VERSION,
    riskScore,
    riskFactors,
    timestamp: now.toISOString(),
    evaluatedContext: {
      userId: context.userId,
      action: context.action,
      documentId: context.documentId,
      sensitivity,
    },
  };
}
