/**
 * TrustVault — Privacy Shield Benchmark & Evaluation Script
 *
 * Evaluates the sensitivity detector against a labeled text corpus containing
 * authentic and negative PII / credential patterns.
 *
 * Metrics: Precision, Recall, F1-Score, Detection Latency.
 */

import { scanTextForPrivacyEntities, validateLuhn } from '../src/lib/privacy-shield';

interface LabeledSample {
  text: string;
  expectedEntities: Array<{
    type: string;
    value: string;
  }>;
}

const BENCHMARK_SAMPLES: LabeledSample[] = [
  {
    text: 'Employee record: Jane Doe with SSN 123-45-6789 and phone (555) 234-5678.',
    expectedEntities: [
      { type: 'SSN', value: '123-45-6789' },
      { type: 'PHONE', value: '(555) 234-5678' },
    ],
  },
  {
    text: 'Customer credit payment used card 4532015112830366 expiring 12/28.', // Valid Visa Luhn
    expectedEntities: [
      { type: 'CREDIT_CARD', value: '4532015112830366' },
    ],
  },
  {
    text: 'AWS deployment credentials: AKIAIOSFODNN7EXAMPLE stored in repository.',
    expectedEntities: [
      { type: 'API_KEY', value: 'AKIAIOSFODNN7EXAMPLE' },
    ],
  },
  {
    text: 'Contact support at security-lead@trustvault.internal for inquiries.',
    expectedEntities: [
      { type: 'EMAIL', value: 'security-lead@trustvault.internal' },
    ],
  },
  {
    text: 'Config line: db_password = "SuperSecretP@ssword2026!" must be redacted.',
    expectedEntities: [
      { type: 'PASSWORD', value: 'SuperSecretP@ssword2026!' },
    ],
  },
  // Negative samples (should NOT be detected as credit cards or SSNs)
  {
    text: 'Order confirmation # 1234567890123 placed on 2026-10-21 with total $49.99.',
    expectedEntities: [],
  },
  {
    text: 'Invoice ID INV-9988-7766 shipped with tracking code 123456789.',
    expectedEntities: [],
  },
];

export function runPrivacyEvaluation() {
  console.log('===============================================================');
  console.log(' TRUSTVAULT — AI PRIVACY SHIELD BENCHMARK & EVALUATION REPORT  ');
  console.log('===============================================================\n');

  let tp = 0;
  let fp = 0;
  let fn = 0;
  let totalEvaluated = 0;
  const startTime = Date.now();

  for (const sample of BENCHMARK_SAMPLES) {
    const scan = scanTextForPrivacyEntities(sample.text);
    totalEvaluated += sample.expectedEntities.length;

    // Check matches
    const detectedValues = scan.findings.map((f) => f.text);

    for (const expected of sample.expectedEntities) {
      if (detectedValues.some((d) => d.includes(expected.value) || expected.value.includes(d))) {
        tp++;
        console.log(`  [PASS - TP] Found expected ${expected.type}: "${expected.value}"`);
      } else {
        fn++;
        console.log(`  [FAIL - FN] Missed expected ${expected.type}: "${expected.value}"`);
      }
    }

    // Check for unexpected extra detections
    for (const finding of scan.findings) {
      const isExpected = sample.expectedEntities.some(
        (exp) => exp.value.includes(finding.text) || finding.text.includes(exp.value)
      );
      if (!isExpected) {
        fp++;
        console.log(`  [FAIL - FP] False positive detection ${finding.entityType}: "${finding.text}"`);
      }
    }

    if (sample.expectedEntities.length === 0 && scan.findings.length === 0) {
      console.log(`  [PASS - TN] Correctly produced 0 false alarms on benign sample: "${sample.text.slice(0, 45)}..."`);
    }
  }

  const durationMs = Date.now() - startTime;
  const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
  const recall = tp + fn > 0 ? tp / (tp + fn) : 0;
  const f1 = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;

  console.log('\n---------------------------------------------------------------');
  console.log(' PRIVACY DETECTOR ACCURACY & PERFORMANCE METRICS               ');
  console.log('---------------------------------------------------------------');
  console.log(` True Positives (TP):  ${tp}`);
  console.log(` False Positives (FP): ${fp}`);
  console.log(` False Negatives (FN): ${fn}`);
  console.log('---------------------------------------------------------------');
  console.log(` Precision:            ${(precision * 100).toFixed(1)}%`);
  console.log(` Recall:               ${(recall * 100).toFixed(1)}%`);
  console.log(` F1 Score:             ${(f1 * 100).toFixed(1)}%`);
  console.log(` Execution Latency:    ${durationMs}ms`);
  console.log('===============================================================\n');

  return { tp, fp, fn, precision, recall, f1, durationMs };
}

if (require.main === module || process.argv[1]?.endsWith('evaluate-privacy-shield.ts')) {
  runPrivacyEvaluation();
}
