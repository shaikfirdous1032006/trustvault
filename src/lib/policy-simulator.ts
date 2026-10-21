import { randomUUID } from 'node:crypto';
import type {
  PolicySimulationRequest,
  PolicySimulationResult,
  DocumentSensitivity,
  PermissionLevel,
} from '@/lib/types';
import { getStore, findUserById } from '@/lib/local-db';
import { evaluateZeroTrustPolicy } from '@/lib/policy-engine';

/**
 * Access Policy Simulator
 *
 * Simulates the impact of permission additions, elevations, or revocations
 * without mutating actual database state. Uses the authoritative Zero-Trust
 * policy engine for evaluation.
 */
export function simulatePolicyChange(
  request: PolicySimulationRequest,
  actingAdminId: string
): PolicySimulationResult {
  void actingAdminId;
  const store = getStore();
  const targetUser = findUserById(request.targetUserId);

  if (!targetUser) {
    throw new Error(`Target user '${request.targetUserId}' not found`);
  }

  const document = store.documents.find((d) => d.id === request.documentId);
  if (!document) {
    throw new Error(`Document '${request.documentId}' not found`);
  }

  const docCategory = (document.category || 'internal').toLowerCase();
  const sensitivity: DocumentSensitivity =
    docCategory === 'confidential'
      ? 'confidential'
      : docCategory === 'restricted'
      ? 'restricted'
      : docCategory === 'public'
      ? 'public'
      : 'internal';

  // 1. Determine current access level
  const existingGrants = store.permissions.filter(
    (p) => p.document_id === document.id && p.user_id === targetUser.id && p.revoked_at === null
  );

  let previousAccess: PermissionLevel | 'none' = 'none';
  if (document.owner_id === targetUser.id) {
    previousAccess = 'edit';
  } else if (existingGrants.some((g) => g.permission_level === 'edit')) {
    previousAccess = 'edit';
  } else if (existingGrants.some((g) => g.permission_level === 'read')) {
    previousAccess = 'read';
  }

  // 2. Projected access level
  const projectedAccess = request.proposedPermissionLevel;

  // 3. Compute delta
  let accessDelta: PolicySimulationResult['accessDelta'] = 'unchanged';
  if (previousAccess === 'none' && projectedAccess !== 'none') {
    accessDelta = 'granted';
  } else if (previousAccess === 'read' && projectedAccess === 'edit') {
    accessDelta = 'elevated';
  } else if (previousAccess === 'edit' && projectedAccess === 'read') {
    accessDelta = 'downgraded';
  } else if (previousAccess !== 'none' && projectedAccess === 'none') {
    accessDelta = 'revoked';
  }

  // 4. Construct hypothetical grants state for policy evaluation
  const simulatedGrants = store.permissions
    .filter((p) => p.document_id === document.id && p.user_id !== targetUser.id && p.revoked_at === null)
    .map((p) => ({
      user_id: p.user_id,
      permission_level: p.permission_level,
      revoked_at: p.revoked_at,
      expires_at: p.expires_at,
      access_count: p.access_count,
      max_access_count: p.max_access_count,
    }));

  if (projectedAccess !== 'none') {
    simulatedGrants.push({
      user_id: targetUser.id,
      permission_level: projectedAccess,
      revoked_at: null,
      expires_at: request.expiresInHours
        ? new Date(Date.now() + request.expiresInHours * 3600_000).toISOString()
        : null,
      access_count: 0,
      max_access_count: null,
    });
  }

  // 5. Evaluate through authoritative policy engine
  const decision = evaluateZeroTrustPolicy(
    {
      userId: targetUser.id,
      userRole: targetUser.role,
      isActive: targetUser.is_active,
      documentId: document.id,
      documentOwnerId: document.owner_id,
      documentSensitivity: sensitivity,
      isDeleted: document.is_deleted,
      requiredLevel: projectedAccess === 'edit' ? 'edit' : 'read',
      action: projectedAccess === 'edit' ? 'edit' : 'preview',
    },
    simulatedGrants
  );

  // 6. Identify potential security risks & unintended consequences
  const potentialRisks: string[] = [];

  if (!targetUser.is_active) {
    potentialRisks.push('Target user account is currently deactivated.');
  }

  if (projectedAccess === 'edit' && targetUser.role === 'viewer') {
    potentialRisks.push('Viewer role elevated to edit privileges on document.');
  }

  if (
    (sensitivity === 'confidential' || sensitivity === 'restricted') &&
    projectedAccess !== 'none' &&
    targetUser.role === 'viewer'
  ) {
    potentialRisks.push(`Granting ${sensitivity}-tier access to a viewer role.`);
  }

  if (accessDelta === 'revoked' && document.owner_id === targetUser.id) {
    potentialRisks.push('Warning: Revoking permissions does not remove document ownership rights.');
  }

  if (projectedAccess !== 'none' && !request.expiresInHours) {
    potentialRisks.push('Grant lacks an expiration time (indefinite access).');
  }

  return {
    simulationId: `sim-${randomUUID()}`,
    targetUser: {
      id: targetUser.id,
      email: targetUser.email,
      role: targetUser.role,
    },
    document: {
      id: document.id,
      title: document.title,
      sensitivity,
      ownerId: document.owner_id,
    },
    previousAccess,
    projectedAccess,
    accessDelta,
    projectedOutcome: decision.outcome,
    potentialRisks,
    affectedDocumentsCount: 1,
    simulatedAt: new Date().toISOString(),
  };
}
