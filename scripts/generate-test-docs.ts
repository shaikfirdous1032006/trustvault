import * as fs from 'fs';
import * as path from 'path';

/**
 * Creates a minimal, standard-compliant PDF 1.4 buffer with custom title and body text.
 */
function createPdfBuffer(title: string, subtitle: string, paragraphs: string[]): Buffer {
  const contentLines: string[] = [
    'BT',
    '/F1 18 Tf',
    '50 740 Td',
    `(${escapePdf(title)}) Tj`,
    '/F1 12 Tf',
    '0 -24 Td',
    `(${escapePdf(subtitle)}) Tj`,
    '/F1 9 Tf',
    '0 -16 Td',
    '(*** SYNTHETIC TEST DOCUMENT - TRUSTVAULT SECURITY EVALUATION ONLY ***) Tj',
    '0 -20 Td',
  ];

  for (const para of paragraphs) {
    contentLines.push('/F1 10 Tf');
    contentLines.push('0 -16 Td');
    contentLines.push(`(${escapePdf(para)}) Tj`);
  }

  contentLines.push('ET');
  const streamData = contentLines.join('\n');
  const streamLength = Buffer.byteLength(streamData, 'utf8');

  const objects: string[] = [];
  objects[1] = '1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n';
  objects[2] = '2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n';
  objects[3] = '3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>\nendobj\n';
  objects[4] = '4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n';
  objects[5] = `5 0 obj\n<< /Length ${streamLength} >>\nstream\n${streamData}\nendstream\nendobj\n`;

  let pdfOutput = '%PDF-1.4\n';
  const offsets: number[] = [0];

  for (let i = 1; i <= 5; i++) {
    offsets[i] = Buffer.byteLength(pdfOutput, 'utf8');
    pdfOutput += objects[i];
  }

  const xrefOffset = Buffer.byteLength(pdfOutput, 'utf8');
  pdfOutput += 'xref\n0 6\n';
  pdfOutput += '0000000000 65535 f \n';
  for (let i = 1; i <= 5; i++) {
    pdfOutput += String(offsets[i]).padStart(10, '0') + ' 00000 n \n';
  }

  pdfOutput += 'trailer\n<< /Size 6 /Root 1 0 R >>\n';
  pdfOutput += 'startxref\n' + xrefOffset + '\n%%EOF\n';

  return Buffer.from(pdfOutput, 'utf8');
}

function escapePdf(text: string): string {
  return text.replace(/\\/g, '\\\\').replace(/\(/g, '\\(').replace(/\)/g, '\\)');
}

export function generateAllTestDocuments() {
  const targetDir = path.join(process.cwd(), 'test-documents');
  if (!fs.existsSync(targetDir)) {
    fs.mkdirSync(targetDir, { recursive: true });
  }

  // 1. Confidential Report PDF
  const doc1 = createPdfBuffer(
    'CONFIDENTIAL REPORT: Q3 SECURITY POSTURE & THREAT AUDIT',
    'Classification: STRICTLY CONFIDENTIAL // ACCESS RESTRICTED',
    [
      'Executive Summary: TrustVault zero-trust defense mechanisms were analyzed across all data ingress points.',
      'Cryptographic Controls: SHA-256 tamper-evident hash chaining verified with zero chain mutations.',
      'Access Policies: Dynamic attribute-based permission grants verified with strict owner-authorization guardrails.',
      'Finding 1: Authentication rate limits successfully mitigated simulated credential stuffing.',
      'Finding 2: Real-time event propagation maintained sub-second latency across distributed sessions.',
      'Attestation: This synthetic test artifact validates document ingestion, permission enforcement, and access audits.',
    ]
  );
  fs.writeFileSync(path.join(targetDir, '1_Confidential_Report.pdf'), doc1);

  // 2. Project Proposal PDF
  const doc2 = createPdfBuffer(
    'PROJECT PROPOSAL: ENTERPRISE DATA PRIVACY SHIELD',
    'Prepared For: TrustVault Governance Council',
    [
      'Objective: Implement automated PII redaction and synthetic token replacement for AI assistant queries.',
      'Scope: Scanning document uploads for SSNs, credit cards, emails, and API keys before external disclosure.',
      'Timeline: Phased implementation covering client preview, worker redaction, and owner attestation.',
      'Budget and Resource Allocation: Zero additional dependencies, utilizing native cryptographic primitives.',
      'Success Metrics: 100% detection rate on high-risk patterns with zero false-negative credential leaks.',
      'Attestation: Synthetic proposal document for workflow validation and permissions testing.',
    ]
  );
  fs.writeFileSync(path.join(targetDir, '2_Project_Proposal.pdf'), doc2);

  // 3. User Guide PDF
  const doc3 = createPdfBuffer(
    'TRUSTVAULT USER GUIDE: SECURE DISCLOSURE & COLLABORATION',
    'Standard Operating Procedure // Version 2.4',
    [
      'Welcome to TrustVault: The enterprise platform for zero-trust document sharing and verification.',
      '1. Uploading Files: Navigate to Vault Upload, select your file, categorize it, and verify checksum.',
      '2. Managing Permissions: Open document details, choose Permissions tab, and grant granular Read or Edit rights.',
      '3. Generating Share Links: Create anonymous, single-use, or expiring public links with recipient watermarking.',
      '4. Verifying Audit Logs: All access and modification events are permanently written to an immutable SHA-256 log.',
      'Attestation: Synthetic user documentation artifact used to test preview, download, and multi-user access.',
    ]
  );
  fs.writeFileSync(path.join(targetDir, '3_User_Guide.pdf'), doc3);

  // 4. Synthetic Customer Data CSV
  const csvContent = [
    'customer_id,full_name,email_address,account_tier,country_code,balance_usd,risk_status,synthetic_flag',
    'CUST-1001,Johnathan Doe,j.doe.synthetic@trustvault-test.internal,Enterprise,US,145200.50,LOW,TRUE_TEST_DATA',
    'CUST-1002,Jane M. Smith,j.smith.synthetic@trustvault-test.internal,Professional,GB,89400.00,LOW,TRUE_TEST_DATA',
    'CUST-1003,Carlos Garcia,c.garcia.synthetic@trustvault-test.internal,Standard,ES,23150.75,MEDIUM,TRUE_TEST_DATA',
    'CUST-1004,Aiko Tanaka,a.tanaka.synthetic@trustvault-test.internal,Enterprise,JP,310450.00,LOW,TRUE_TEST_DATA',
    'CUST-1005,Fatima Al-Mansoor,f.mansoor.synthetic@trustvault-test.internal,Government,AE,540000.25,LOW,TRUE_TEST_DATA',
    'CUST-1006,Liam O\'Connor,l.oconnor.synthetic@trustvault-test.internal,Standard,IE,12400.00,MEDIUM,TRUE_TEST_DATA',
    'CUST-1007,Elena Rostova,e.rostova.synthetic@trustvault-test.internal,Professional,DE,67890.10,LOW,TRUE_TEST_DATA',
    'CUST-1008,Kowalski Piotr,p.kowalski.synthetic@trustvault-test.internal,Standard,PL,18900.50,HIGH,TRUE_TEST_DATA',
    'CUST-1009,Mei Ling Chen,m.chen.synthetic@trustvault-test.internal,Enterprise,SG,425100.00,LOW,TRUE_TEST_DATA',
    'CUST-1010,Sarah Jenkins,s.jenkins.synthetic@trustvault-test.internal,Professional,AU,95300.80,LOW,TRUE_TEST_DATA',
  ].join('\n');
  fs.writeFileSync(path.join(targetDir, '4_Synthetic_Customer_Data.csv'), csvContent, 'utf8');

  // 5. Approval Letter PDF
  const doc5 = createPdfBuffer(
    'FORMAL APPROVAL LETTER: SYSTEM GO-LIVE & COMPLIANCE SIGN-OFF',
    'Reference: TV-AUDIT-2026-OCT // Regulatory Clearance',
    [
      'To: TrustVault Security Operations & Release Engineering Team',
      'From: Chief Compliance & Information Security Officer',
      'Subject: Formal Authorization for Production Readiness and Live Deployment',
      'This document confirms that TrustVault has satisfied all automated test suites and audit integrity checks.',
      'Verification Summary: 254 vitest test cases passed, ESLint clean, Next.js Turbopack build verified.',
      'Sign-off Status: APPROVED FOR PRODUCTION DEPLOYMENT.',
      'Attestation: Synthetic clearance artifact testing owner approval and digital verification workflows.',
    ]
  );
  fs.writeFileSync(path.join(targetDir, '5_Approval_Letter.pdf'), doc5);

  console.log('Successfully generated all 5 synthetic test documents in test-documents/');
}

if (require.main === module) {
  generateAllTestDocuments();
}
