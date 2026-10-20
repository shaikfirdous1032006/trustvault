import type { PermissionLevel } from '@/lib/types';
import { randomUUID } from 'crypto';

export interface PermissionDecisionInput {
  document: {
    id: string;
    owner_id: string;
    is_deleted: boolean;
  } | null;
  grants: Array<{
    user_id: string;
    permission_level: string;
    revoked_at: string | null;
    expires_at: string | null;
  }>;
  userId: string;
  requiredLevel: PermissionLevel;
  now?: Date;
}

/**
 * Pure authorization decision. Used by the API and by tests.
 * Removing or weakening this function is what the mutation-style tests catch.
 */
export function evaluateDocumentPermission(
  input: PermissionDecisionInput
): { allowed: boolean; reason: string } {
  const { document, grants, userId, requiredLevel } = input;
  const now = input.now ?? new Date();

  if (!document) {
    return { allowed: false, reason: 'Document not found' };
  }

  if (document.is_deleted) {
    return { allowed: false, reason: 'Document has been deleted' };
  }

  if (document.owner_id === userId) {
    return { allowed: true, reason: 'Document owner' };
  }

  const valid = grants.find((p) => {
    if (p.user_id !== userId) return false;
    if (p.revoked_at) return false;
    if (p.expires_at && new Date(p.expires_at) <= now) return false;
    if (requiredLevel === 'edit') {
      return p.permission_level === 'edit';
    }
    return p.permission_level === 'read' || p.permission_level === 'edit';
  });

  if (!valid) {
    const hadGrant = grants.some((p) => p.user_id === userId);
    if (!hadGrant) {
      return { allowed: false, reason: 'No permission grant exists' };
    }
    return { allowed: false, reason: 'Permission expired or insufficient level' };
  }

  return { allowed: true, reason: `Has ${valid.permission_level} permission` };
}

export const ALLOWED_MIME_TYPES = [
  'application/pdf',
  'application/msword',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'application/vnd.ms-excel',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  'application/vnd.ms-powerpoint',
  'application/vnd.openxmlformats-officedocument.presentationml.presentation',
  'text/plain',
  'text/csv',
  'image/png',
  'image/jpeg',
  'image/gif',
  'image/webp',
] as const;

export const MAX_FILE_SIZE = 52_428_800; // 50MB

/**
 * Sanitizes a filename, strips path traversal components, and detects malicious traversal attempts.
 */
export function sanitizeFilename(rawName: string): { safeName: string; isMalicious: boolean } {
  if (!rawName || typeof rawName !== 'string') {
    return { safeName: 'unnamed_document', isMalicious: false };
  }

  // Detect path traversal patterns or control characters
  const hasTraversal =
    rawName.includes('..') ||
    rawName.includes('/') ||
    rawName.includes('\\') ||
    rawName.includes('\0') ||
    /[\x00-\x1f\x7f]/.test(rawName);

  // Extract base name only (strip any directory parts)
  const baseName = rawName.replace(/^.*[\\\/]/, '').trim();
  // Strip dangerous characters, keep only alphanumerics, dots, hyphens, and underscores
  const safeBase = baseName.replace(/[^a-zA-Z0-9._-]/g, '_');
  const safeName = safeBase.length > 0 ? safeBase.slice(0, 255) : 'unnamed_document';

  return {
    safeName,
    isMalicious: hasTraversal,
  };
}

/**
 * Verifies magic bytes / file signatures to prevent MIME-type spoofing attacks.
 */
export function validateMagicBytes(
  buffer: Uint8Array | Buffer,
  declaredMimeType: string
): { valid: boolean; reason?: string } {
  if (!buffer || buffer.length === 0) {
    return { valid: false, reason: 'File buffer is empty' };
  }

  // Check for executable signatures regardless of declared MIME (prevent polyglot executables)
  if (buffer.length >= 2) {
    // Windows PE / DOS executable ('MZ')
    if (buffer[0] === 0x4d && buffer[1] === 0x5a) {
      return { valid: false, reason: 'Executable PE binaries are strictly forbidden' };
    }
  }
  if (buffer.length >= 4) {
    // Linux ELF executable ('\x7fELF')
    if (buffer[0] === 0x7f && buffer[1] === 0x45 && buffer[2] === 0x4c && buffer[3] === 0x46) {
      return { valid: false, reason: 'Executable ELF binaries are strictly forbidden' };
    }
  }

  // Verify against declared safe types
  switch (declaredMimeType) {
    case 'application/pdf':
      // PDF magic bytes: '%PDF-' (0x25, 0x50, 0x44, 0x46)
      if (
        buffer.length >= 4 &&
        buffer[0] === 0x25 &&
        buffer[1] === 0x50 &&
        buffer[2] === 0x44 &&
        buffer[3] === 0x46
      ) {
        return { valid: true };
      }
      return { valid: false, reason: 'File does not match authentic PDF signature (%PDF-)' };

    case 'image/png':
      // PNG magic bytes: 0x89, 0x50, 0x4e, 0x47
      if (
        buffer.length >= 4 &&
        buffer[0] === 0x89 &&
        buffer[1] === 0x50 &&
        buffer[2] === 0x4e &&
        buffer[3] === 0x47
      ) {
        return { valid: true };
      }
      return { valid: false, reason: 'File does not match authentic PNG signature' };

    case 'image/jpeg':
      // JPEG magic bytes: 0xff, 0xd8, 0xff
      if (buffer.length >= 3 && buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) {
        return { valid: true };
      }
      return { valid: false, reason: 'File does not match authentic JPEG signature' };

    case 'image/gif':
      // GIF magic bytes: 'GIF87a' or 'GIF89a' (0x47, 0x49, 0x46, 0x38)
      if (
        buffer.length >= 4 &&
        buffer[0] === 0x47 &&
        buffer[1] === 0x49 &&
        buffer[2] === 0x46 &&
        buffer[3] === 0x38
      ) {
        return { valid: true };
      }
      return { valid: false, reason: 'File does not match authentic GIF signature' };

    case 'application/vnd.openxmlformats-officedocument.wordprocessingml.document':
    case 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet':
    case 'application/vnd.openxmlformats-officedocument.presentationml.presentation':
      // DOCX/XLSX/PPTX are Zip archives: 'PK\x03\x04' (0x50, 0x4b, 0x03, 0x04)
      if (
        buffer.length >= 4 &&
        buffer[0] === 0x50 &&
        buffer[1] === 0x4b &&
        buffer[2] === 0x03 &&
        buffer[3] === 0x04
      ) {
        return { valid: true };
      }
      return { valid: false, reason: 'Office document does not match authentic OpenXML signature (PK)' };

    case 'text/plain':
    case 'text/csv':
      // For text files, ensure no binary null bytes in first 1024 bytes
      const checkLength = Math.min(buffer.length, 1024);
      for (let i = 0; i < checkLength; i++) {
        if (buffer[i] === 0x00) {
          return { valid: false, reason: 'Plain text file contains invalid binary null bytes' };
        }
      }
      return { valid: true };

    default:
      return { valid: true };
  }
}

/**
 * Validates file upload metadata and contents.
 */
export function validateUpload(file: {
  type: string;
  size: number;
  name?: string;
  buffer?: Uint8Array | Buffer;
}): string | null {
  if (file.size === 0) {
    return 'File is empty';
  }
  if (file.size > MAX_FILE_SIZE) {
    return 'File size exceeds 50MB limit';
  }
  if (!ALLOWED_MIME_TYPES.includes(file.type as (typeof ALLOWED_MIME_TYPES)[number])) {
    return `File type "${file.type || 'unknown'}" is not allowed`;
  }
  if (file.name) {
    const { isMalicious } = sanitizeFilename(file.name);
    if (isMalicious) {
      return 'Filename contains invalid or dangerous path traversal characters';
    }
  }
  if (file.buffer) {
    const signatureCheck = validateMagicBytes(file.buffer, file.type);
    if (!signatureCheck.valid) {
      return signatureCheck.reason || 'File signature does not match declared MIME type';
    }
  }
  return null;
}

/**
 * Generates an unpredictable, opaque storage key on the server.
 * Never constructs filesystem paths from untrusted user filenames.
 */
export function generateStorageKey(ownerId: string, ext?: string): string {
  const safeOwner = ownerId.replace(/[^a-zA-Z0-9_-]/g, '');
  const opaqueId = randomUUID();
  const cleanExt = ext ? ext.replace(/[^a-zA-Z0-9]/g, '').toLowerCase() : '';
  return `${safeOwner}/${opaqueId}${cleanExt ? `.${cleanExt}` : ''}`;
}
