import { randomUUID } from 'node:crypto';
import type {
  SensitiveEntityType,
  PrivacyFinding,
  PrivacyScanResult,
} from '@/lib/types';

export const PRIVACY_SHIELD_VERSION = '1.2.0-presidio-rules';

/**
 * Validates a candidate card number using the standard Luhn algorithm.
 */
export function validateLuhn(cardNumber: string): boolean {
  const digits = cardNumber.replace(/\D/g, '');
  if (digits.length < 13 || digits.length > 19) return false;

  let sum = 0;
  let alternate = false;

  for (let i = digits.length - 1; i >= 0; i--) {
    let n = parseInt(digits.charAt(i), 10);
    if (alternate) {
      n *= 2;
      if (n > 9) n = (n % 10) + 1;
    }
    sum += n;
    alternate = !alternate;
  }

  return sum % 10 === 0;
}

interface PatternRule {
  type: SensitiveEntityType;
  regex: RegExp;
  confidence: number;
  maskGenerator: (match: string) => string;
  validator?: (match: string) => boolean;
}

const PATTERN_RULES: PatternRule[] = [
  // US Social Security Number (SSN)
  {
    type: 'SSN',
    regex: /\b(?!000|666)\d{3}[-\s](?!00)\d{2}[-\s](?!0000)\d{4}\b/g,
    confidence: 0.98,
    maskGenerator: (match) => {
      const clean = match.replace(/\D/g, '');
      const last4 = clean.slice(-4);
      return `[REDACTED_SSN_••••${last4}]`;
    },
  },
  // Credit / Debit Card Numbers (with Luhn check)
  {
    type: 'CREDIT_CARD',
    regex: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b/g,
    confidence: 0.99,
    validator: (m) => validateLuhn(m),
    maskGenerator: (match) => {
      const clean = match.replace(/\D/g, '');
      const last4 = clean.slice(-4);
      return `[REDACTED_CARD_••••${last4}]`;
    },
  },
  // AWS Access Key ID
  {
    type: 'API_KEY',
    regex: /\b(AKIA[0-9A-Z]{16})\b/g,
    confidence: 1.0,
    maskGenerator: () => '[REDACTED_AWS_KEY]',
  },
  // OpenAI & Generic Bearer Keys
  {
    type: 'API_KEY',
    regex: /\b(sk-[a-zA-Z0-9]{32,}|ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{50,})\b/g,
    confidence: 0.99,
    maskGenerator: () => '[REDACTED_API_TOKEN]',
  },
  // Explicit API Key assignment: apiKey: "...", api_key = "..."
  {
    type: 'API_KEY',
    regex: /(?:api[_-]?key|access[_-]?token|secret[_-]?token)\s*[:=]\s*['"]([a-zA-Z0-9_\-]{16,})['"]/gi,
    confidence: 0.95,
    maskGenerator: () => '[REDACTED_SECRET_KEY]',
  },
  // JWT Tokens
  {
    type: 'JWT_TOKEN',
    regex: /\b(eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})\b/g,
    confidence: 0.98,
    maskGenerator: () => '[REDACTED_JWT_TOKEN]',
  },
  // RSA / EC Private Keys
  {
    type: 'SECRET_KEY',
    regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
    confidence: 1.0,
    maskGenerator: () => '[REDACTED_PRIVATE_KEY_BLOCK]',
  },
  // Plaintext Password assignments: password = "..."
  {
    type: 'PASSWORD',
    regex: /(?:password|passwd|pwd)\s*[:=]\s*['"]([^'"]{6,})['"]/gi,
    confidence: 0.90,
    maskGenerator: () => '[REDACTED_PLAINTEXT_PASSWORD]',
  },
  // Email Address
  {
    type: 'EMAIL',
    regex: /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g,
    confidence: 0.95,
    maskGenerator: (match) => {
      const parts = match.split('@');
      const user = parts[0];
      const domain = parts[1] || '';
      const maskedUser = user.length <= 2 ? '••' : `${user[0]}•••${user[user.length - 1]}`;
      return `[REDACTED_EMAIL_${maskedUser}@${domain}]`;
    },
  },
  // Phone Number (US and International formats)
  {
    type: 'PHONE',
    regex: /(?<!\d)(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}(?!\d)/g,
    confidence: 0.88,
    validator: (m) => {
      const clean = m.replace(/\D/g, '');
      return clean.length === 10 || (clean.length === 11 && clean.startsWith('1'));
    },
    maskGenerator: (match) => {
      const clean = match.replace(/\D/g, '');
      const last4 = clean.slice(-4);
      return `[REDACTED_PHONE_•••${last4}]`;
    },
  },
];

/**
 * Scans text content for sensitive entities and returns findings.
 */
export function scanTextForPrivacyEntities(
  text: string,
  documentId: string = 'doc-preview',
  documentTitle: string = 'Untitled Document'
): PrivacyScanResult {
  const findings: PrivacyFinding[] = [];
  const findingsByType: Record<SensitiveEntityType, number> = {
    SSN: 0,
    CREDIT_CARD: 0,
    API_KEY: 0,
    EMAIL: 0,
    PHONE: 0,
    PASSWORD: 0,
    IP_ADDRESS: 0,
    JWT_TOKEN: 0,
    SECRET_KEY: 0,
  };

  for (const rule of PATTERN_RULES) {
    const regex = new RegExp(rule.regex.source, rule.regex.flags);
    let match: RegExpExecArray | null;

    while ((match = regex.exec(text)) !== null) {
      const matchedText = match[0];
      const startOffset = match.index;
      const endOffset = startOffset + matchedText.length;

      // Optional semantic validator (e.g. Luhn algorithm for cards)
      if (rule.validator && !rule.validator(matchedText)) {
        continue;
      }

      // Avoid overlapping duplicates
      const isOverlapping = findings.some(
        (f) =>
          (startOffset >= f.startOffset && startOffset < f.endOffset) ||
          (endOffset > f.startOffset && endOffset <= f.endOffset)
      );

      if (!isOverlapping) {
        findings.push({
          id: `find-${randomUUID().slice(0, 8)}`,
          entityType: rule.type,
          text: matchedText,
          startOffset,
          endOffset,
          confidence: rule.confidence,
          proposedReplacement: rule.maskGenerator(matchedText),
          approved: true, // Approved by default for owner review
        });
        findingsByType[rule.type] = (findingsByType[rule.type] || 0) + 1;
      }
    }
  }

  // Sort findings by position in document
  findings.sort((a, b) => a.startOffset - b.startOffset);

  return {
    documentId,
    documentTitle,
    totalFindings: findings.length,
    findingsByType,
    findings,
    detectorVersion: PRIVACY_SHIELD_VERSION,
    scannedAt: new Date().toISOString(),
  };
}

/**
 * Applies redactions to text based on approved findings.
 * Processes from end to start to maintain index validity.
 */
export function applyPrivacyRedactions(
  originalText: string,
  findingsToRedact: PrivacyFinding[]
): string {
  // Sort descending by start offset
  const sorted = [...findingsToRedact].sort((a, b) => b.startOffset - a.startOffset);

  let result = originalText;
  for (const finding of sorted) {
    const before = result.slice(0, finding.startOffset);
    const after = result.slice(finding.endOffset);
    result = before + finding.proposedReplacement + after;
  }

  return result;
}

/**
 * Extracts human-readable text from supported document buffers.
 */
export function extractTextFromBuffer(
  buffer: Buffer | Uint8Array,
  mimeType: string = 'text/plain'
): string {
  const rawString = Buffer.from(buffer).toString('utf-8');

  if (mimeType.includes('pdf')) {
    // For PDFs, extract plain text streams and metadata strings
    const streamRegex = /stream[\r\n]+([\s\S]*?)[\r\n]+endstream/g;
    let match: RegExpExecArray | null;
    const chunks: string[] = [];
    while ((match = streamRegex.exec(rawString)) !== null) {
      const cleaned = match[1].replace(/[^\x20-\x7E\r\n]/g, ' ');
      if (cleaned.trim().length > 0) {
        chunks.push(cleaned.trim());
      }
    }
    if (chunks.length > 0) {
      return chunks.join('\n');
    }
    // Fallback: extract printable strings
    return rawString.replace(/[^\x20-\x7E\r\n]/g, ' ').replace(/\s{2,}/g, ' ');
  }

  return rawString;
}
