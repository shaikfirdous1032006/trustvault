import { describe, it, expect } from 'vitest';
import {
  scanTextForPrivacyEntities,
  applyPrivacyRedactions,
  validateLuhn,
} from '@/lib/privacy-shield';

describe('AI Privacy Shield', () => {
  describe('validateLuhn algorithm', () => {
    it('validates authentic card numbers', () => {
      expect(validateLuhn('4532015112830366')).toBe(true);
    });

    it('rejects numbers that fail the checksum', () => {
      expect(validateLuhn('4532015112830367')).toBe(false);
      expect(validateLuhn('1234567890123456')).toBe(false);
    });
  });

  describe('scanTextForPrivacyEntities', () => {
    it('detects SSNs accurately', () => {
      const text = 'Employee tax ID is 987-65-4320.';
      const res = scanTextForPrivacyEntities(text);
      expect(res.totalFindings).toBe(1);
      expect(res.findings[0].entityType).toBe('SSN');
      expect(res.findings[0].proposedReplacement).toBe('[REDACTED_SSN_••••4320]');
    });

    it('detects AWS API keys and OpenAI tokens', () => {
      const text = 'Deploy using AKIAIOSFODNN7EXAMPLE or sk-abcdef12345678901234567890123456';
      const res = scanTextForPrivacyEntities(text);
      expect(res.totalFindings).toBe(2);
      expect(res.findings.every((f) => f.entityType === 'API_KEY')).toBe(true);
    });

    it('detects plaintext passwords', () => {
      const text = 'Database settings: password = "MySecretPassword2026!"';
      const res = scanTextForPrivacyEntities(text);
      expect(res.totalFindings).toBe(1);
      expect(res.findings[0].entityType).toBe('PASSWORD');
    });

    it('detects email addresses and formats privacy-preserving replacements', () => {
      const text = 'Send reports to confidential@company.com';
      const res = scanTextForPrivacyEntities(text);
      expect(res.totalFindings).toBe(1);
      expect(res.findings[0].entityType).toBe('EMAIL');
      expect(res.findings[0].proposedReplacement).toContain('@company.com');
    });

    it('avoids false alarms on non-card 13-digit numbers', () => {
      const text = 'Order sequence number is 1234567890123 with no card involved.';
      const res = scanTextForPrivacyEntities(text);
      expect(res.totalFindings).toBe(0);
    });
  });

  describe('applyPrivacyRedactions', () => {
    it('redacts approved findings and keeps original text unchanged', () => {
      const original = 'Client Jane Doe (SSN 123-45-6789) paid via 4532015112830366.';
      const scan = scanTextForPrivacyEntities(original);

      expect(scan.totalFindings).toBe(2);

      const redacted = applyPrivacyRedactions(original, scan.findings);

      expect(redacted).not.toContain('123-45-6789');
      expect(redacted).not.toContain('4532015112830366');
      expect(redacted).toContain('[REDACTED_SSN_••••6789]');
      expect(redacted).toContain('[REDACTED_CARD_••••0366]');

      // Original string variable remains completely unmodified
      expect(original).toContain('123-45-6789');
    });
  });
});
