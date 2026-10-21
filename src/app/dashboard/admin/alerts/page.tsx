"use client";

import { useState, useEffect } from "react";
import {
  ShieldAlert,
  CheckCircle2,
  Clock,
  Loader2,
  RefreshCw,
  Search,
  Filter,
  UserX,
  Eye,
  Check,
} from "lucide-react";
import type { SecurityAlert } from "@/lib/security-alerts";

export default function AdminAlertsPage() {
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [loading, setLoading] = useState(true);
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [actionLoading, setActionLoading] = useState(false);
  const [actionMessage, setActionMessage] = useState<string | null>(null);
  const [refreshCount, setRefreshCount] = useState(0);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        const res = await fetch("/api/admin/alerts");
        const json = await res.json();
        if (json.success && !cancelled) {
          setAlerts(json.data || []);
        }
      } catch (e) {
        console.error("Failed to load alerts:", e);
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    }
    void load();
    return () => {
      cancelled = true;
    };
  }, [refreshCount]);

  async function handleAlertAction(
    alert: SecurityAlert,
    action: "investigate" | "resolve" | "dismiss" | "restrict_actor"
  ) {
    setActionLoading(true);
    setActionMessage(null);
    try {
      const res = await fetch("/api/admin/alerts/action", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          alertId: alert.id,
          action,
          actorId: alert.affected_actor_id,
          notes: `Action '${action}' executed by security administrator`,
        }),
      });
      const data = await res.json();
      if (data.success) {
        setActionMessage(
          action === "restrict_actor"
            ? `Actor ${alert.affected_actor_email || alert.affected_actor_id} temporarily restricted for 15 minutes.`
            : `Alert marked as ${action}.`
        );
        setRefreshCount((c) => c + 1);
      } else {
        setActionMessage(data.error || "Action failed");
      }
    } catch {
      setActionMessage("Network error performing alert action");
    } finally {
      setActionLoading(false);
    }
  }

  const filteredAlerts = alerts.filter((alert) => {
    if (severityFilter !== "all" && alert.severity !== severityFilter) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchEmail = alert.affected_actor_email?.toLowerCase().includes(q);
      const matchTitle = alert.title.toLowerCase().includes(q);
      const matchRule = alert.rule.toLowerCase().includes(q);
      if (!matchEmail && !matchTitle && !matchRule) return false;
    }
    return true;
  });

  const criticalCount = alerts.filter((a) => a.severity === "critical").length;
  const highCount = alerts.filter((a) => a.severity === "high").length;
  const mediumCount = alerts.filter((a) => a.severity === "medium").length;

  return (
    <div className="space-y-8 p-6 lg:p-8 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-[var(--card-border)] pb-6">
        <div>
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-red-500/10 text-red-500">
              <ShieldAlert className="w-6 h-6" />
            </div>
            <h1 className="text-2xl font-bold tracking-tight">Threat Detection & Security Alerts</h1>
          </div>
          <p className="mt-1 text-sm text-[var(--muted)]">
            Explainable audit anomaly detection and active incident response.
          </p>
        </div>
        <button
          onClick={() => setRefreshCount((c) => c + 1)}
          disabled={loading}
          className="btn btn-secondary flex items-center gap-2"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
          Refresh
        </button>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="card p-5 border-l-4 border-l-red-500">
          <span className="text-xs font-semibold uppercase tracking-wider text-[var(--muted)]">
            Critical Threats
          </span>
          <div className="mt-2 text-3xl font-extrabold text-red-500">{criticalCount}</div>
          <p className="mt-1 text-xs text-[var(--muted)]">Multi-document probing & IDOR attacks</p>
        </div>

        <div className="card p-5 border-l-4 border-l-amber-500">
          <span className="text-xs font-semibold uppercase tracking-wider text-[var(--muted)]">
            High Severity
          </span>
          <div className="mt-2 text-3xl font-extrabold text-amber-500">{highCount}</div>
          <p className="mt-1 text-xs text-[var(--muted)]">Brute force & unauthorized denial spikes</p>
        </div>

        <div className="card p-5 border-l-4 border-l-blue-500">
          <span className="text-xs font-semibold uppercase tracking-wider text-[var(--muted)]">
            Medium Severity
          </span>
          <div className="mt-2 text-3xl font-extrabold text-blue-400">{mediumCount}</div>
          <p className="mt-1 text-xs text-[var(--muted)]">Rapid download bursts & unusual volume</p>
        </div>

        <div className="card p-5 border-l-4 border-l-emerald-500">
          <span className="text-xs font-semibold uppercase tracking-wider text-[var(--muted)]">
            Detection Pipeline
          </span>
          <div className="mt-2 text-3xl font-extrabold text-emerald-500">Active</div>
          <p className="mt-1 text-xs text-[var(--muted)]">Zero-Trust rules engine monitoring events</p>
        </div>
      </div>

      {actionMessage && (
        <div className="p-4 rounded-xl border border-brand-500/30 bg-brand-500/10 text-sm flex items-center gap-3">
          <CheckCircle2 className="w-5 h-5 text-brand-400 shrink-0" />
          <span>{actionMessage}</span>
        </div>
      )}

      {/* Filter and Search Bar */}
      <div className="card p-4 flex flex-col sm:flex-row gap-4 justify-between items-center">
        <div className="relative w-full sm:w-80">
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-[var(--muted)]" />
          <input
            type="text"
            placeholder="Search by actor or rule..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="input pl-9 w-full text-sm"
          />
        </div>

        <div className="flex items-center gap-3 w-full sm:w-auto">
          <Filter className="w-4 h-4 text-[var(--muted)]" />
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="input text-sm py-1.5"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>
      </div>

      {/* Alerts List */}
      {loading ? (
        <div className="card p-12 text-center flex flex-col items-center justify-center gap-3">
          <Loader2 className="w-8 h-8 animate-spin text-brand-500" />
          <p className="text-sm text-[var(--muted)]">Scanning audit event stream for anomalies...</p>
        </div>
      ) : filteredAlerts.length === 0 ? (
        <div className="card p-12 text-center flex flex-col items-center justify-center gap-3">
          <div className="w-12 h-12 rounded-full bg-emerald-500/10 flex items-center justify-center text-emerald-500">
            <CheckCircle2 className="w-6 h-6" />
          </div>
          <h3 className="text-lg font-semibold">No Security Threats Detected</h3>
          <p className="text-sm text-[var(--muted)] max-w-md">
            All audit events are within normal operational thresholds. No suspicious brute-force, IDOR, or exfiltration patterns detected.
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          {filteredAlerts.map((alert) => {
            const severityColor =
              alert.severity === "critical"
                ? "border-red-500/50 bg-red-500/5 text-red-400"
                : alert.severity === "high"
                ? "border-amber-500/50 bg-amber-500/5 text-amber-400"
                : "border-blue-500/50 bg-blue-500/5 text-blue-400";

            return (
              <div
                key={alert.id}
                className="card p-6 border transition hover:border-brand-500/50 space-y-4"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div className="flex items-center gap-3">
                    <span
                      className={`px-2.5 py-1 rounded-full text-xs font-bold uppercase tracking-wider border ${severityColor}`}
                    >
                      {alert.severity}
                    </span>
                    <h3 className="text-lg font-bold">{alert.title}</h3>
                  </div>

                  <span className="text-xs text-[var(--muted)] flex items-center gap-1.5">
                    <Clock className="w-3.5 h-3.5" />
                    Detected: {new Date(alert.detected_at).toLocaleTimeString()} ({alert.time_window_minutes}m window)
                  </span>
                </div>

                <p className="text-sm text-[var(--muted)]">{alert.description}</p>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 p-3 rounded-lg bg-[var(--background)] border border-[var(--card-border)] text-xs">
                  <div>
                    <span className="text-[var(--muted)]">Target Actor:</span>{" "}
                    <span className="font-mono font-medium">
                      {alert.affected_actor_email || alert.affected_actor_id || "Unauthenticated"}
                    </span>
                  </div>
                  <div>
                    <span className="text-[var(--muted)]">Anomaly Count:</span>{" "}
                    <span className="font-semibold text-brand-400">{alert.event_count} events</span>
                  </div>
                  <div>
                    <span className="text-[var(--muted)]">Rule ID:</span>{" "}
                    <span className="font-mono text-[var(--muted)]">{alert.rule}</span>
                  </div>
                </div>

                {/* Actions */}
                <div className="flex flex-wrap items-center gap-2 pt-2 border-t border-[var(--card-border)]">
                  <button
                    onClick={() => handleAlertAction(alert, "investigate")}
                    disabled={actionLoading}
                    className="btn btn-secondary btn-sm flex items-center gap-1.5"
                  >
                    <Eye className="w-3.5 h-3.5" />
                    Investigate
                  </button>

                  <button
                    onClick={() => handleAlertAction(alert, "resolve")}
                    disabled={actionLoading}
                    className="btn btn-secondary btn-sm text-emerald-400 flex items-center gap-1.5"
                  >
                    <Check className="w-3.5 h-3.5" />
                    Mark Resolved
                  </button>

                  <button
                    onClick={() => handleAlertAction(alert, "dismiss")}
                    disabled={actionLoading}
                    className="btn btn-secondary btn-sm text-[var(--muted)]"
                  >
                    Dismiss
                  </button>

                  {alert.affected_actor_id && (
                    <button
                      onClick={() => handleAlertAction(alert, "restrict_actor")}
                      disabled={actionLoading}
                      className="btn btn-danger btn-sm ml-auto flex items-center gap-1.5"
                    >
                      <UserX className="w-3.5 h-3.5" />
                      Restrict Actor Access
                    </button>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
