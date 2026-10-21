
import type { PermissionLevel } from '@/lib/types';
import { randomUUID } from 'node:crypto';

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
    max_access_count?: number | null;
    access_count?: number;
  }>;
  userId: string;
  requiredLevel: PermissionLevel;
  now?: Date;
}

type PermissionDecision = {
  allowed: boolean;
  reason: string;
};

/**
 * Evaluates whether a user may access a document.
 * Owners can read and edit their own non-deleted documents.
 * Other users need an active, unexpired grant with sufficient permission.
 */
export function evaluateDocumentPermission(
  input: PermissionDecisionInput
): PermissionDecision {
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

  const userGrants = grants.filter((grant) => grant.user_id === userId);

  if (userGrants.length === 0) {
    return {
      allowed: false,
      reason: 'No permission grant exists',
    };
  }

  const hasSufficientPermission = (permissionLevel: string): boolean => {
    if (requiredLevel === 'edit') {
      return permissionLevel === 'edit';
    }

    return permissionLevel === 'read' || permissionLevel === 'edit';
  };

  const isActiveGrant = (
    grant: PermissionDecisionInput['grants'][number]
  ): boolean => {
    if (grant.revoked_at !== null) {
      return false;
    }

    if (grant.expires_at !== null) {
      const expiryTime = Date.parse(grant.expires_at);

      if (Number.isNaN(expiryTime) || expiryTime <= now.getTime()) {
        return false;
      }
    }

    if (
      grant.max_access_count != null &&
      (grant.access_count ?? 0) >= grant.max_access_count
    ) {
      return false;
    }

    return true;
  };

  // Any valid grant with sufficient permission is enough.
  // A revoked or expired grant must not override another valid grant.
  const validGrant = userGrants.find(
    (grant) =>
      isActiveGrant(grant) &&
      hasSufficientPermission(grant.permission_level)
  );

  if (validGrant) {
    return {
      allowed: true,
      reason: `Has ${validGrant.permission_level} permission`,
    };
  }

  const hasAccessLimitReached = userGrants.some(
    (grant) =>
      grant.max_access_count != null &&
      (grant.access_count ?? 0) >= grant.max_access_count
  );

  if (
    userGrants.every(
      (grant) =>
        grant.max_access_count != null &&
        (grant.access_count ?? 0) >= grant.max_access_count
    )
  ) {
    return {
      allowed: false,
      reason: 'Single-use / access count limit reached',
    };
  }

  if (hasAccessLimitReached) {
    return {
      allowed: false,
      reason: 'No active grant with sufficient permission',
    };
  }

  return {
    allowed: false,
    reason: 'Permission expired or insufficient level',
  };
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

export const MAX_FILE_SIZE = 52_428_800; // 50 MiB (50 MB limit)

/**
 * Sanitizes a filename and detects path traversal attempts.
 * Storage keys must never be built from an untrusted filename.
 */
export function sanitizeFilename(
  rawName: string
): { safeName: string; isMalicious: boolean } {
  if (typeof rawName !== 'string' || rawName.length === 0) {
    return {
      safeName: 'unnamed_document',
      isMalicious: false,
    };
  }

  const hasTraversal =
    rawName.includes('..') ||
    rawName.includes('/') ||
    rawName.includes('\\') ||
    /[\x00-\x1f\x7f]/.test(rawName);

  const baseName = rawName.replace(/^.*[\\/]/, '').trim();
  const safeBase = baseName.replace(/[^a-zA-Z0-9._-]/g, '_');
  const safeName =
    safeBase.length > 0
      ? safeBase.slice(0, 255)
      : 'unnamed_document';

  return {
    safeName,
    isMalicious: hasTraversal,
  };
}

/**
 * Checks file signatures against declared MIME types.
 * This is an additional validation layer, not a substitute for
 * antivirus scanning or safe document processing.
 */
export function validateMagicBytes(
  buffer: Uint8Array | Buffer,
  declaredMimeType: string
): { valid: boolean; reason?: string } {
  if (!buffer || buffer.length === 0) {
    return { valid: false, reason: 'File buffer is empty' };
  }

  const startsWith = (...bytes: number[]): boolean =>
    buffer.length >= bytes.length &&
    bytes.every((byte, index) => buffer[index] === byte);

  const asciiAt = (offset: number, value: string): boolean =>
    buffer.length >= offset + value.length &&
    [...value].every(
      (character, index) =>
        buffer[offset + index] === character.charCodeAt(0)
    );

  // Reject common executable signatures regardless of declared MIME.
  if (startsWith(0x4d, 0x5a)) {
    return {
      valid: false,
      reason: 'Executable PE binaries are strictly forbidden',
    };
  }

  if (startsWith(0x7f, 0x45, 0x4c, 0x46)) {
    return {
      valid: false,
      reason: 'Executable ELF binaries are strictly forbidden',
    };
  }

  switch (declaredMimeType) {
    case 'application/pdf':
      if (startsWith(0x25, 0x50, 0x44, 0x46)) {
        return { valid: true };
      }
      return {
        valid: false,
        reason: 'File does not match the PDF signature',
      };

    case 'image/png':
      if (startsWith(0x89, 0x50, 0x4e, 0x47)) {
        return { valid: true };
      }
      return {
        valid: false,
        reason: 'File does not match the PNG signature',
      };

    case 'image/jpeg':
      if (startsWith(0xff, 0xd8, 0xff)) {
        return { valid: true };
      }
      return {
        valid: false,
        reason: 'File does not match the JPEG signature',
      };

    case 'image/gif':
      if (asciiAt(0, 'GIF87a') || asciiAt(0, 'GIF89a')) {
        return { valid: true };
      }
      return {
        valid: false,
        reason: 'File does not match the GIF signature',
      };

    case 'image/webp':
      if (asciiAt(0, 'RIFF') && asciiAt(8, 'WEBP')) {
        return { valid: true };
      }
      return {
        valid: false,
        reason: 'File does not match the WebP signature',
      };

    case 'application/msword':
    case 'application/vnd.ms-excel':
    case 'application/vnd.ms-powerpoint':
      // Legacy Microsoft Office documents use the OLE Compound File format.
      if (
        startsWith(
          0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1
        )
      ) {
        return { valid: true };
      }
      return {
        valid: false,
        reason: 'Legacy Office file does not match its expected signature',
      };

    case 'application/vnd.openxmlformats-officedocument.wordprocessingml.document':
    case 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet':
    case 'application/vnd.openxmlformats-officedocument.presentationml.presentation':
      // DOCX, XLSX and PPTX are ZIP-based formats.
      if (startsWith(0x50, 0x4b, 0x03, 0x04)) {
        return { valid: true };
      }
      return {
        valid: false,
        reason: 'Office Open XML file does not match the ZIP signature',
      };

    case 'text/plain':
    case 'text/csv': {
      const checkLength = Math.min(buffer.length, 1024);

      for (let index = 0; index < checkLength; index++) {
        if (buffer[index] === 0x00) {
          return {
            valid: false,
            reason: 'Text file contains binary null bytes',
          };
        }
      }

      return { valid: true };
    }

    default:
      return {
        valid: false,
        reason: 'Unsupported MIME type',
      };
  }
}

/**
 * Validates upload size, MIME type, filename and optional file contents.
 * Returns null when validation succeeds, otherwise an error message.
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

  if (!Number.isFinite(file.size) || file.size < 0) {
    return 'File is empty or has an invalid size';
  }

  if (file.size > MAX_FILE_SIZE) {
    return 'File size exceeds 50MB limit';
  }

  if (
    !ALLOWED_MIME_TYPES.includes(
      file.type as (typeof ALLOWED_MIME_TYPES)[number]
    )
  ) {
    return `File type "${file.type || 'unknown'}" is not allowed`;
  }

  if (file.name) {
    const { isMalicious } = sanitizeFilename(file.name);

    if (isMalicious) {
      return 'Filename contains invalid or dangerous path traversal characters';
    }
  }

  if (file.buffer !== undefined) {
    if (file.buffer.length !== file.size) {
      return 'File buffer size does not match declared file size';
    }

    const signatureCheck = validateMagicBytes(file.buffer, file.type);

    if (!signatureCheck.valid) {
      return (
        signatureCheck.reason ||
        'File signature does not match declared MIME type'
      );
    }
  }

  return null;
}

/**
 * Generates an unpredictable storage key.
 * The original filename must never be used as a storage path.
 */
export function generateStorageKey(ownerId: string, ext?: string): string {
  const safeOwner = ownerId.replace(/[^a-zA-Z0-9_-]/g, '');

  if (!safeOwner) {
    throw new Error('A valid owner ID is required to generate a storage key');
  }

  const opaqueId = randomUUID();
  const cleanExt = ext
    ? ext.replace(/[^a-zA-Z0-9]/g, '').toLowerCase()
    : '';

  return `${safeOwner}/${opaqueId}${cleanExt ? `.${cleanExt}` : ''}`;
}
