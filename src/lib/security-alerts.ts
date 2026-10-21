/**
 * TrustVault — Rule-based Suspicious Activity Detection
 *
 * Analyzes recent audit events against configurable detection rules.
 * No AI/ML dependencies — transparent rule-based logic.
 *
 * Limitations:
 * - In-memory analysis of the local store; not a streaming engine.
 * - Detection depends on audit event completeness.
 * - Rules use fixed thresholds; adjust for your organization's baseline.
 */

import type { AuditEvent } from '@/lib/types';

export type AlertSeverity = 'low' | 'medium' | 'high' | 'critical';

export interface SecurityAlert {
  id: string;
  severity: AlertSeverity;
  rule: string;
  title: string;
  description: string;
  affected_actor_email: string | null;
  affected_actor_id: string | null;
  detected_at: string;
  event_count: number;
  time_window_minutes: number;
  related_event_ids: string[];
}

interface DetectionRule {
  id: string;
  title: string;
  description: string;
  severity: AlertSeverity;
  /** Filter events that match this rule */
  match: (event: AuditEvent) => boolean;
  /** Max events in the time window before alerting */
  threshold: number;
  /** Time window in minutes */
  windowMinutes: number;
  /** Group events by this key for counting */
  groupBy: (event: AuditEvent) => string;
}

const DETECTION_RULES: DetectionRule[] = [
  {
    id: 'repeated_denied_access',
    title: 'Repeated Denied Document Access',
    description: 'Multiple denied document access attempts from the same actor — possible unauthorized access or IDOR probing.',
    severity: 'high',
    match: (e) =>
      e.result === 'denied' &&
      ['preview', 'download', 'update', 'delete'].includes(e.action) &&
      e.actor_id !== null,
    threshold: 5,
    windowMinutes: 10,
    groupBy: (e) => e.actor_id || 'unknown',
  },
  {
    id: 'repeated_login_failures',
    title: 'Repeated Login Failures',
    description: 'Multiple failed login attempts — possible credential stuffing or brute-force attack.',
    severity: 'high',
    match: (e) => e.action === 'login_failure' && e.result === 'denied',
    threshold: 5,
    windowMinutes: 10,
    groupBy: (e) => e.actor_email || e.ip_hash || 'unknown',
  },
  {
    id: 'bulk_download_burst',
    title: 'Unusual Download Burst',
    description: 'Abnormally high number of document downloads in a short period — possible data exfiltration.',
    severity: 'medium',
    match: (e) => e.action === 'download' && e.result === 'allowed',
    threshold: 10,
    windowMinutes: 5,
    groupBy: (e) => e.actor_id || 'unknown',
  },
  {
    id: 'multi_document_probing',
    title: 'Multi-Document Access Probing',
    description: 'Denied access attempts across multiple distinct documents — possible enumeration attack.',
    severity: 'critical',
    match: (e) =>
      e.result === 'denied' &&
      ['preview', 'download'].includes(e.action) &&
      e.document_id !== null &&
      e.actor_id !== null,
    threshold: 5,
    windowMinutes: 15,
    groupBy: (e) => e.actor_id || 'unknown',
  },
];

/**
 * Analyze a set of audit events and return any triggered security alerts.
 */
export function detectSuspiciousActivity(events: AuditEvent[]): SecurityAlert[] {
  const alerts: SecurityAlert[] = [];
  const now = new Date();

  for (const rule of DETECTION_RULES) {
    const windowStart = new Date(now.getTime() - rule.windowMinutes * 60_000);

    // Filter events that match this rule within the time window
    const matching = events.filter(
      (e) =>
        rule.match(e) &&
        new Date(e.occurred_at) >= windowStart
    );

    // Group by the rule's groupBy key
    const groups = new Map<string, AuditEvent[]>();
    for (const event of matching) {
      const key = rule.groupBy(event);
      const group = groups.get(key) || [];
      group.push(event);
      groups.set(key, group);
    }

    // Check each group against threshold
    for (const [groupKey, groupEvents] of groups) {
      let effectiveCount = groupEvents.length;

      // For multi-document probing, count distinct documents instead of total events
      if (rule.id === 'multi_document_probing') {
        const distinctDocs = new Set(groupEvents.map((e) => e.document_id).filter(Boolean));
        effectiveCount = distinctDocs.size;
      }

      if (effectiveCount >= rule.threshold) {
        const representativeEvent = groupEvents[0];
        alerts.push({
          id: `alert-${rule.id}-${groupKey}-${Date.now()}`,
          severity: rule.severity,
          rule: rule.id,
          title: rule.title,
          description: rule.description,
          affected_actor_email: representativeEvent?.actor_email || null,
          affected_actor_id: representativeEvent?.actor_id || null,
          detected_at: now.toISOString(),
          event_count: effectiveCount,
          time_window_minutes: rule.windowMinutes,
          related_event_ids: groupEvents.map((e) => e.id),
        });
      }
    }
  }

  // Sort by severity (critical first)
  const severityOrder: Record<AlertSeverity, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
  };
  alerts.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  return alerts;
}

export { DETECTION_RULES };
