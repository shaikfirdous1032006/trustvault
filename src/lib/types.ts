export type UserRole = 'admin' | 'owner' | 'viewer';
export type PermissionLevel = 'read' | 'edit';
export type AuditAction =
  | 'upload'
  | 'download'
  | 'preview'
  | 'update'
  | 'delete'
  | 'restore'
  | 'permission_grant'
  | 'permission_revoke'
  | 'permission_update'
  | 'login'
  | 'login_failure'
  | 'logout'
  | 'register'
  | 'register_failure'
  | 'user_created'
  | 'role_change'
  | 'account_activated'
  | 'account_deactivated'
  | 'admin_action'
  | 'security_alert'
  | 'profile_update'
  | 'search'
  | 'version_upload'
  | 'ai_suggestion'
  | 'ai_suggestion_confirmed'
  | 'share_link_created'
  | 'share_link_viewed'
  | 'share_link_denied'
  | 'share_link_revoked'
  | 'ai_assistant_query';

export type AuditResult = 'allowed' | 'denied';

export interface ActivityFeedItem {
  id: string;
  action: AuditAction | string;
  result: AuditResult | string;
  occurred_at: string;
  actor_id: string | null;
  actor_email: string | null;
  document_id: string | null;
  document_title?: string | null;
  description: string;
  target_resource_type?: string;
  target_resource_id?: string | null;
  details: Record<string, unknown>;
}

export interface User {
  id: string;
  email: string;
  full_name: string | null;
  role: UserRole;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface Document {
  id: string;
  owner_id: string;
  title: string;
  description: string | null;
  category: string;
  storage_path: string;
  file_name: string;
  file_size: number;
  mime_type: string;
  checksum: string;
  current_version: number;
  is_deleted: boolean;
  deleted_at: string | null;
  deleted_by: string | null;
  created_at: string;
  updated_at: string;
  // Joined fields
  owner?: User;
}

export interface DocumentPermission {
  id: string;
  document_id: string;
  user_id: string;
  permission_level: PermissionLevel;
  granted_by: string;
  granted_at: string;
  revoked_at: string | null;
  revoked_by: string | null;
  expires_at: string | null;
  max_access_count?: number | null;
  access_count?: number;
  watermark_enabled?: boolean;
  // Joined fields
  user?: User;
  grantor?: User;
}

/**
 * A bearer credential for a single document. The bearer is anonymous: it holds a
 * 256-bit token that the server only ever stores as a SHA-256 digest, so a dump of
 * the store cannot mint or enumerate links.
 *
 * Links are read-only. Editing a document still requires a named platform account
 * with an edit grant, because an anonymous write path would have to trust a token
 * for identity, which is exactly what this feature is meant to avoid.
 */
export interface ShareLink {
  id: string;
  document_id: string;
  token_hash: string;
  label: string | null;
  created_by: string;
  created_at: string;
  expires_at: string;
  revoked_at: string | null;
  revoked_by: string | null;
  access_count: number;
  max_access_count: number | null;
  last_accessed_at: string | null;
  allow_download: boolean;
  watermark_enabled: boolean;
  // Joined fields
  creator?: User;
  document?: Document;
}

export interface DocumentVersion {
  id: string;
  document_id: string;
  version_number: number;
  storage_path: string;
  file_name: string;
  file_size: number;
  mime_type: string;
  checksum: string;
  uploaded_by: string;
  change_notes: string | null;
  created_at: string;
  // Joined fields
  uploader?: User;
}

export interface AuditEvent {
  id: string;
  occurred_at: string;
  actor_id: string | null;
  actor_email: string | null;
  document_id: string | null;
  action: AuditAction;
  result: AuditResult;
  ip_hash: string | null;
  user_agent_hash: string | null;
  request_id: string | null;
  details_jsonb: Record<string, unknown>;
  prev_hash: string | null;
  event_hash: string;
}

// API response types
export interface ApiResponse<T = unknown> {
  success: boolean;
  data?: T;
  error?: string;
  message?: string;
}

export interface PaginatedResponse<T> extends ApiResponse<T[]> {
  total: number;
  page: number;
  pageSize: number;
}

// Request types
export interface UploadDocumentRequest {
  title: string;
  description?: string;
  category: string;
  file: File;
}

export interface GrantPermissionRequest {
  user_email: string;
  permission_level: PermissionLevel;
  expires_at?: string;
  max_access_count?: number;
  burn_after_read?: boolean;
  watermark_enabled?: boolean;
}

export interface UpdateDocumentRequest {
  title?: string;
  description?: string;
  category?: string;
}

export interface UploadVersionRequest {
  file: File;
  change_notes?: string;
}

// Zero-Trust Adaptive Policy Engine Types
export type PolicyOutcome = 'ALLOW' | 'DENY' | 'REQUIRE_REVIEW' | 'TEMPORARILY_RESTRICT';
export type DocumentSensitivity = 'public' | 'internal' | 'confidential' | 'restricted';

export interface ZeroTrustEvaluationContext {
  userId: string;
  userRole: UserRole;
  isActive: boolean;
  documentId?: string | null;
  documentOwnerId?: string | null;
  documentSensitivity?: DocumentSensitivity;
  isDeleted?: boolean;
  requiredLevel: PermissionLevel;
  action: 'preview' | 'download' | 'edit' | 'delete' | 'share' | 'version_upload';
  ipAddress?: string | null;
  sessionAgeSeconds?: number;
  recentDeniedCount?: number;
  recentDownloadBurst?: number;
  hasActiveRestriction?: boolean;
  now?: Date;
}

export interface ZeroTrustDecision {
  decisionId: string;
  outcome: PolicyOutcome;
  allowed: boolean;
  reasonCode: string;
  explanation: string;
  policyVersion: string;
  riskScore: number; // 0 - 100
  riskFactors: string[];
  timestamp: string;
  evaluatedContext: {
    userId: string;
    action: string;
    documentId?: string | null;
    sensitivity: DocumentSensitivity;
  };
}

// AI Privacy Shield Types
export type SensitiveEntityType =
  | 'SSN'
  | 'CREDIT_CARD'
  | 'API_KEY'
  | 'EMAIL'
  | 'PHONE'
  | 'PASSWORD'
  | 'IP_ADDRESS'
  | 'JWT_TOKEN'
  | 'SECRET_KEY';

export interface PrivacyFinding {
  id: string;
  entityType: SensitiveEntityType;
  text: string;
  startOffset: number;
  endOffset: number;
  confidence: number; // 0.0 - 1.0
  proposedReplacement: string;
  approved?: boolean;
}

export interface PrivacyScanResult {
  documentId: string;
  documentTitle: string;
  totalFindings: number;
  findingsByType: Record<SensitiveEntityType, number>;
  findings: PrivacyFinding[];
  detectorVersion: string;
  scannedAt: string;
}

// Policy Simulation Types
export interface PolicySimulationRequest {
  targetUserId: string;
  documentId: string;
  proposedPermissionLevel: PermissionLevel | 'none'; // 'none' means revocation
  expiresInHours?: number | null;
}

export interface PolicySimulationResult {
  simulationId: string;
  targetUser: {
    id: string;
    email: string;
    role: UserRole;
  };
  document: {
    id: string;
    title: string;
    sensitivity: DocumentSensitivity;
    ownerId: string;
  };
  previousAccess: PermissionLevel | 'none';
  projectedAccess: PermissionLevel | 'none';
  accessDelta: 'granted' | 'elevated' | 'downgraded' | 'revoked' | 'unchanged';
  projectedOutcome: PolicyOutcome;
  potentialRisks: string[];
  affectedDocumentsCount: number;
  simulatedAt: string;
}

