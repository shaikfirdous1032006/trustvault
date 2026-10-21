/**
 * TrustVault — Threat Detection Benchmark & Evaluation Script
 *
 * Evaluates the deterministic security-alert detection rules on a labeled
 * synthetic audit event dataset containing both benign operational traffic
 * and targeted attack vectors.
 *
 * Metrics computed:
 * - True Positives (TP)
 * - False Positives (FP)
 * - True Negatives (TN)
 * - False Negatives (FN)
 * - Precision, Recall, F1-Score
 */

import { detectSuspiciousActivity } from '../src/lib/security-alerts';
import type { AuditEvent } from '../src/lib/types';

interface TestScenario {
  name: string;
  isAttack: boolean;
  expectedRuleId?: string;
  events: AuditEvent[];
}

function makeEvent(
  action: AuditEvent['action'],
  result: AuditEvent['result'],
  actorId: string | null,
  actorEmail: string | null,
  documentId: string | null = null,
  minutesAgo: number = 1
): AuditEvent {
  const date = new Date(Date.now() - minutesAgo * 60_000);
  return {
    id: `eval-${Math.random().toString(36).slice(2, 9)}`,
    occurred_at: date.toISOString(),
    actor_id: actorId,
    actor_email: actorEmail,
    document_id: documentId,
    action,
    result,
    ip_hash: 'hash-client-1',
    user_agent_hash: 'hash-ua-1',
    request_id: `req-${Math.random().toString(36).slice(2, 8)}`,
    details_jsonb: {},
    prev_hash: null,
    event_hash: 'eval-hash',
  };
}

function buildEvaluationDataset(): TestScenario[] {
  return [
    // 1. Benign: Single failed login then success
    {
      name: 'Benign User Login Mistyped Password',
      isAttack: false,
      events: [
        makeEvent('login_failure', 'denied', null, 'alice@example.com', null, 5),
        makeEvent('login', 'allowed', 'usr-alice', 'alice@example.com', null, 4),
      ],
    },
    // 2. Attack: Brute Force Login (6 failed logins in 5 min)
    {
      name: 'Credential Stuffing / Brute Force Attack',
      isAttack: true,
      expectedRuleId: 'repeated_login_failures',
      events: Array.from({ length: 6 }, (_, i) =>
        makeEvent('login_failure', 'denied', null, 'victim@example.com', null, i)
      ),
    },
    // 3. Benign: Normal document reading
    {
      name: 'Normal Document Reading Workflow',
      isAttack: false,
      events: [
        makeEvent('preview', 'allowed', 'usr-bob', 'bob@example.com', 'doc-1', 4),
        makeEvent('download', 'allowed', 'usr-bob', 'bob@example.com', 'doc-1', 2),
      ],
    },
    // 4. Attack: IDOR / Repeated Denied Document Access
    {
      name: 'Repeated Denied Document Access Probe',
      isAttack: true,
      expectedRuleId: 'repeated_denied_access',
      events: Array.from({ length: 6 }, (_, i) =>
        makeEvent('preview', 'denied', 'usr-attacker', 'attacker@example.com', 'doc-confidential', i)
      ),
    },
    // 5. Attack: Abnormal Download Burst (12 downloads in 3 minutes)
    {
      name: 'Mass Data Exfiltration Download Burst',
      isAttack: true,
      expectedRuleId: 'bulk_download_burst',
      events: Array.from({ length: 12 }, (_, i) =>
        makeEvent('download', 'allowed', 'usr-insider', 'insider@example.com', `doc-${i}`, 1)
      ),
    },
    // 6. Attack: Multi-Document Access Probing
    {
      name: 'Multi-Document Enumeration Probing',
      isAttack: true,
      expectedRuleId: 'multi_document_probing',
      events: Array.from({ length: 6 }, (_, i) =>
        makeEvent('preview', 'denied', 'usr-scanner', 'scanner@example.com', `target-doc-${i}`, i)
      ),
    },
    // 7. Benign: Multiple different users downloading separate files normally
    {
      name: 'Multiple Normal Users Active Concurrently',
      isAttack: false,
      events: [
        makeEvent('download', 'allowed', 'usr-user1', 'u1@example.com', 'doc-a', 3),
        makeEvent('download', 'allowed', 'usr-user2', 'u2@example.com', 'doc-b', 3),
        makeEvent('download', 'allowed', 'usr-user3', 'u3@example.com', 'doc-c', 2),
      ],
    },
  ];
}

export function runThreatEvaluation() {
  console.log('===============================================================');
  console.log(' TRUSTVAULT — THREAT DETECTION BENCHMARK & EVALUATION REPORT  ');
  console.log('===============================================================\n');

  const dataset = buildEvaluationDataset();
  let tp = 0;
  let fp = 0;
  let tn = 0;
  let fn = 0;

  console.log(`Running evaluation on ${dataset.length} synthetic scenarios...\n`);

  for (const scenario of dataset) {
    const alerts = detectSuspiciousActivity(scenario.events);
    const alertTriggered = alerts.length > 0;

    if (scenario.isAttack) {
      if (alertTriggered) {
        tp++;
        console.log(`  [PASS - TP] ${scenario.name}: correctly triggered alert (${alerts[0].rule})`);
      } else {
        fn++;
        console.log(`  [FAIL - FN] ${scenario.name}: failed to trigger alert`);
      }
    } else {
      if (!alertTriggered) {
        tn++;
        console.log(`  [PASS - TN] ${scenario.name}: correctly produced 0 alerts`);
      } else {
        fp++;
        console.log(`  [FAIL - FP] ${scenario.name}: falsely triggered alert (${alerts[0].rule})`);
      }
    }
  }

  const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
  const recall = tp + fn > 0 ? tp / (tp + fn) : 0;
  const f1 = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;
  const accuracy = (tp + tn) / dataset.length;

  console.log('\n---------------------------------------------------------------');
  console.log(' CONFUSION MATRIX & BENCHMARK METRICS                          ');
  console.log('---------------------------------------------------------------');
  console.log(` True Positives (TP):  ${tp}`);
  console.log(` False Positives (FP): ${fp}`);
  console.log(` True Negatives (TN):  ${tn}`);
  console.log(` False Negatives (FN): ${fn}`);
  console.log('---------------------------------------------------------------');
  console.log(` Precision:            ${(precision * 100).toFixed(1)}%`);
  console.log(` Recall:               ${(recall * 100).toFixed(1)}%`);
  console.log(` F1 Score:             ${(f1 * 100).toFixed(1)}%`);
  console.log(` Accuracy:             ${(accuracy * 100).toFixed(1)}%`);
  console.log('===============================================================\n');

  return { tp, fp, tn, fn, precision, recall, f1, accuracy };
}

if (require.main === module || process.argv[1]?.endsWith('evaluate-threat-detection.ts')) {
  runThreatEvaluation();
}
