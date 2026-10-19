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
  | 'login'
  | 'login_failure'
  | 'logout'
  | 'admin_action'
  | 'search'
  | 'version_upload'
  | 'ai_suggestion'
  | 'ai_suggestion_confirmed';

export type AuditResult = 'allowed' | 'denied';

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
  // Joined fields
  user?: User;
  grantor?: User;
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
