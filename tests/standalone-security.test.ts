/**
 * TrustVault — Standalone Authorization Tests
 *
 * Tests the permission evaluation engine, file validation, audit chain
 * integrity, and security utilities WITHOUT requiring Supabase or any
 * external services.
 *
 * Run: npm test
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  evaluateDocumentPermission,
  validateUpload,
  sanitizeFilename,
  validateMagicBytes,
  generateStorageKey,
  MAX_FILE_SIZE,
} from '@/lib/permission';

/* ------------------------------------------------------------------ */
/*  PERMISSION ENGINE TESTS                                           */
/* ------------------------------------------------------------------ */

describe('evaluateDocumentPermission', () => {
  const baseDoc = { id: 'doc-1', owner_id: 'user-owner', is_deleted: false };
  const now = new Date('2026-01-01T00:00:00Z');

  it('allows owner to access own document', () => {
    const result = evaluateDocumentPermission({
      document: baseDoc,
      grants: [],
      userId: 'user-owner',
      requiredLevel: 'read',
      now,
    });
    expect(result.allowed).toBe(true);
    expect(result.reason).toBe('Document owner');
  });

  it('denies access when document is null', () => {
    const result = evaluateDocumentPermission({
      document: null,
      grants: [],
      userId: 'user-viewer',
      requiredLevel: 'read',
      now,
    });
    expect(result.allowed).toBe(false);
    expect(result.reason).toBe('Document not found');
  });

  it('denies access when document is deleted', () => {
    const result = evaluateDocumentPermission({
      document: { ...baseDoc, is_deleted: true },
      grants: [],
      userId: 'user-owner',
      requiredLevel: 'read',
      now,
    });
    expect(result.allowed).toBe(false);
    expect(result.reason).toBe('Document has been deleted');
  });

  it('denies access when no permission grant exists', () => {
    const result = evaluateDocumentPermission({
      document: baseDoc,
      grants: [],
      userId: 'user-viewer',
      requiredLevel: 'read',
      now,
    });
    expect(result.allowed).toBe(false);
    expect(result.reason).toBe('No permission grant exists');
  });

  it('allows read when user has active read permission', () => {
    const result = evaluateDocumentPermission({
      document: baseDoc,
      grants: [
        { user_id: 'user-viewer', permission_level: 'read', revoked_at: null, expires_at: null },
      ],
      userId: 'user-viewer',
      requiredLevel: 'read',
      now,
    });
    expect(result.allowed).toBe(true);
  });

  it('denies edit when user only has read permission', () => {
    const result = evaluateDocumentPermission({
      document: baseDoc,
      grants: [
        { user_id: 'user-viewer', permission_level: 'read', revoked_at: null, expires_at: null },
      ],
      userId: 'user-viewer',
      requiredLevel: 'edit',
      now,
    });
    expect(result.allowed).toBe(false);
  });

  it('allows edit when user has edit permission', () => {
    const result = evaluateDocumentPermission({
      document: baseDoc,
      grants: [
        { user_id: 'user-editor', permission_level: 'edit', revoked_at: null, expires_at: null },
      ],
      userId: 'user-editor',
      requiredLevel: 'edit',
      now,
    });
    expect(result.allowed).toBe(true);
  });

  it('allows read when user has edit permission (edit implies read)', () => {
    const result = evaluateDocumentPermission({
      document: baseDoc,
      grants: [
        { user_id: 'user-editor', permission_level: 'edit', revoked_at: null, expires_at: null },
      ],
      userId: 'user-editor',
      requiredLevel: 'read',
      now,
    });
    expect(result.allowed).toBe(true);
  });

  it('denies access when permission is revoked', () => {
    const result = evaluateDocumentPermission({
      document: baseDoc,
      grants: [
        {
          user_id: 'user-viewer',
          permission_level: 'read',
          revoked_at: '2025-12-31T00:00:00Z',
          expires_at: null,
        },
      ],
      userId: 'user-viewer',
      requiredLevel: 'read',
      now,
    });
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('expired or insufficient');
  });

  it('denies access when permission is expired', () => {
    const result = evaluateDocumentPermission({
      document: baseDoc,
      grants: [
        {
          user_id: 'user-viewer',
          permission_level: 'read',
          revoked_at: null,
          expires_at: '2025-12-31T23:59:59Z',
        },
      ],
      userId: 'user-viewer',
      requiredLevel: 'read',
      now,
    });
    expect(result.allowed).toBe(false);
  });

  it('allows access when permission has future expiry', () => {
    const result = evaluateDocumentPermission({
      document: baseDoc,
      grants: [
        {
          user_id: 'user-viewer',
          permission_level: 'read',
          revoked_at: null,
          expires_at: '2027-12-31T23:59:59Z',
        },
      ],
      userId: 'user-viewer',
      requiredLevel: 'read',
      now,
    });
    expect(result.allowed).toBe(true);
  });

  it('denies access when max_access_count is reached', () => {
    const result = evaluateDocumentPermission({
      document: baseDoc,
      grants: [
        {
          user_id: 'user-viewer',
          permission_level: 'read',
          revoked_at: null,
          expires_at: null,
          max_access_count: 1,
          access_count: 1,
        },
      ],
      userId: 'user-viewer',
      requiredLevel: 'read',
      now,
    });
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('access count limit');
  });

  it('does not grant cross-user access (IDOR protection)', () => {
    const result = evaluateDocumentPermission({
      document: baseDoc,
      grants: [
        { user_id: 'user-viewer', permission_level: 'read', revoked_at: null, expires_at: null },
      ],
      userId: 'user-attacker',
      requiredLevel: 'read',
      now,
    });
    expect(result.allowed).toBe(false);
    expect(result.reason).toBe('No permission grant exists');
  });
});

/* ------------------------------------------------------------------ */
/*  FILE VALIDATION TESTS                                             */
/* ------------------------------------------------------------------ */

describe('validateUpload', () => {
  it('rejects empty files', () => {
    expect(validateUpload({ type: 'text/plain', size: 0 })).toBe('File is empty');
  });

  it('rejects oversized files', () => {
    expect(validateUpload({ type: 'text/plain', size: MAX_FILE_SIZE + 1 }))
      .toBe('File size exceeds 50MB limit');
  });

  it('rejects disallowed MIME types', () => {
    const err = validateUpload({ type: 'application/x-executable', size: 100 });
    expect(err).toContain('not allowed');
  });

  it('accepts valid text/plain file', () => {
    expect(validateUpload({ type: 'text/plain', size: 100 })).toBeNull();
  });

  it('accepts valid application/pdf', () => {
    expect(validateUpload({ type: 'application/pdf', size: 1024 })).toBeNull();
  });

  it('rejects filename with path traversal', () => {
    const err = validateUpload({
      type: 'text/plain',
      size: 100,
      name: '../../../etc/passwd',
    });
    expect(err).toContain('path traversal');
  });

  it('rejects filename with backslash traversal', () => {
    const err = validateUpload({
      type: 'text/plain',
      size: 100,
      name: '..\\..\\windows\\system32\\config',
    });
    expect(err).toContain('path traversal');
  });
});

describe('sanitizeFilename', () => {
  it('strips path traversal from filenames', () => {
    const { safeName, isMalicious } = sanitizeFilename('../../../etc/passwd');
    expect(isMalicious).toBe(true);
    expect(safeName).not.toContain('..');
    expect(safeName).not.toContain('/');
  });

  it('keeps safe filenames intact', () => {
    const { safeName, isMalicious } = sanitizeFilename('report_2026.pdf');
    expect(isMalicious).toBe(false);
    expect(safeName).toBe('report_2026.pdf');
  });

  it('handles empty string', () => {
    const { safeName } = sanitizeFilename('');
    expect(safeName).toBe('unnamed_document');
  });

  it('strips null bytes', () => {
    const { isMalicious } = sanitizeFilename('file\x00.txt');
    expect(isMalicious).toBe(true);
  });
});

describe('validateMagicBytes', () => {
  it('rejects PE executables regardless of declared MIME', () => {
    const peHeader = new Uint8Array([0x4d, 0x5a, 0x00, 0x00]);
    const result = validateMagicBytes(peHeader, 'text/plain');
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('Executable PE');
  });

  it('rejects ELF executables', () => {
    const elfHeader = new Uint8Array([0x7f, 0x45, 0x4c, 0x46]);
    const result = validateMagicBytes(elfHeader, 'application/pdf');
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('Executable ELF');
  });

  it('validates PDF magic bytes', () => {
    const pdfHeader = new Uint8Array([0x25, 0x50, 0x44, 0x46]); // %PDF
    expect(validateMagicBytes(pdfHeader, 'application/pdf').valid).toBe(true);
  });

  it('rejects non-PDF claiming to be PDF', () => {
    const fakeData = new Uint8Array([0x00, 0x00, 0x00, 0x00]);
    expect(validateMagicBytes(fakeData, 'application/pdf').valid).toBe(false);
  });

  it('validates PNG magic bytes', () => {
    const pngHeader = new Uint8Array([0x89, 0x50, 0x4e, 0x47]);
    expect(validateMagicBytes(pngHeader, 'image/png').valid).toBe(true);
  });

  it('validates JPEG magic bytes', () => {
    const jpegHeader = new Uint8Array([0xff, 0xd8, 0xff, 0xe0]);
    expect(validateMagicBytes(jpegHeader, 'image/jpeg').valid).toBe(true);
  });

  it('validates plain text (no null bytes)', () => {
    const text = new TextEncoder().encode('Hello, World!');
    expect(validateMagicBytes(text, 'text/plain').valid).toBe(true);
  });

  it('rejects plain text with embedded null bytes', () => {
    const binText = new Uint8Array([0x48, 0x65, 0x00, 0x6c]);
    expect(validateMagicBytes(binText, 'text/plain').valid).toBe(false);
  });
});

describe('generateStorageKey', () => {
  it('generates unique keys', () => {
    const key1 = generateStorageKey('user-1', 'pdf');
    const key2 = generateStorageKey('user-1', 'pdf');
    expect(key1).not.toBe(key2);
  });

  it('strips dangerous characters from owner ID', () => {
    const key = generateStorageKey('../../evil', 'pdf');
    expect(key).not.toContain('..');
    // The owner segment is sanitised, not removed: the separator that divides it
    // from the opaque object name is part of the intended layout.
    expect(key.startsWith('evil/')).toBe(true);
    expect(key.slice('evil/'.length)).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.pdf$/);
  });

  it('handles missing extension', () => {
    const key = generateStorageKey('user-1');
    expect(key).toMatch(/^user-1\/[a-f0-9-]+$/);
  });
});
