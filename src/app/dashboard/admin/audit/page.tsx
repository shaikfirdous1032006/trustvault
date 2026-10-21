"use client";

import { useState, useEffect, useCallback } from "react";
import {
  Activity,
  Filter,
  ChevronLeft,
  ChevronRight,
  CheckCircle2,
  AlertTriangle,
  Clock,
  Shield,
  Loader2,
  Key,
  ShieldAlert,
  RefreshCw,
  Download,
} from "lucide-react";

interface AuditEvent {
  id: string;
  occurred_at: string;
  actor_id: string | null;
  actor_email: string | null;
  document_id: string | null;
  action: string;
  result: string;
  ip_hash: string | null;
  request_id: string | null;
  details_jsonb: Record<string, unknown>;
  event_hash: string;
  prev_hash: string | null;
}

const ACTIONS = [
  "all",
  "upload",
  "download",
  "preview",
  "update",
  "delete",
  "restore",
  "permission_grant",
  "permission_revoke",
  "login",
  "login_failure",
  "logout",
  "search",
  "version_upload",
];

export default function AdminAuditPage() {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [actionFilter, setActionFilter] = useState("all");
  const [resultFilter, setResultFilter] = useState("all");
  const [verifying, setVerifying] = useState(false);
  const [tampering, setTampering] = useState(false);
  const [tamperStatus, setTamperStatus] = useState<string | null>(null);
  const [verificationResult, setVerificationResult] = useState<{
    valid: boolean;
    mismatches: Array<{ id: string; expected: string; actual: string }>;
    verified_at?: string;
  } | null>(null);
  const pageSize = 30;
  const [refreshTrigger, setRefreshTrigger] = useState(0);

  const refreshEvents = useCallback(() => {
    setRefreshTrigger((prev) => prev + 1);
  }, []);

  async function handleVerifyChain() {
    setVerifying(true);
    try {
      const res = await fetch("/api/admin/audit/verify", { method: "POST" });
      const data = await res.json();
      if (data.success) {
        setVerificationResult({
          valid: data.valid,
          mismatches: data.mismatches || [],
          verified_at: data.verified_at,
        });
      }
    } catch {
      /* ignored */
    } finally {
      setVerifying(false);
    }
  }

  async function handleSimulateTamper() {
    setTampering(true);
    try {
      const res = await fetch("/api/admin/audit/tamper", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "tamper" }),
      });
      const data = await res.json();
      if (data.success) {
        setTamperStatus("⚠️ Attack simulated: An audit record's payload was maliciously modified in storage without recalculating hash chain.");
        await handleVerifyChain();
        refreshEvents();
      }
    } catch {
      /* ignored */
    } finally {
      setTampering(false);
    }
  }

  async function handleRestoreTamper() {
    setTampering(true);
    try {
      const res = await fetch("/api/admin/audit/tamper", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "restore" }),
      });
      const data = await res.json();
      if (data.success) {
        setTamperStatus("✅ Chain healed: Tampered audit event restored to authentic state. Hash chain re-sealed.");
        await handleVerifyChain();
        refreshEvents();
      }
    } catch {
      /* ignored */
    } finally {
      setTampering(false);
    }
  }

  useEffect(() => {
    let cancelled = false;

    async function load() {
      setLoading(true);
      try {
        const params = new URLSearchParams();
        params.set("page", page.toString());
        params.set("pageSize", pageSize.toString());
        if (actionFilter !== "all") params.set("action", actionFilter);
        if (resultFilter !== "all") params.set("result", resultFilter);

        const res = await fetch(`/api/admin/audit?${params}`);
        const data = await res.json();
        if (data.success && !cancelled) {
          setEvents(data.data);
          setTotal(data.total);
        }
      } catch {
        /* ignored */
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
  }, [page, actionFilter, resultFilter, refreshTrigger, pageSize]);

  const totalPages = Math.ceil(total / pageSize);

  return (
    <div className="max-w-6xl mx-auto animate-fade-in">
      <div className="mb-6">
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <Activity className="w-6 h-6 text-brand-400" />
          Platform Audit Log
        </h1>
        <p className="text-[var(--muted)] text-sm mt-1">
          Tamper-evident, append-only audit trail with SHA-256 hash chain
        </p>
      </div>

      {/* Security info & Audit Chain Verification */}
      <div className="card-glass flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6 p-4">
        <div className="flex items-start gap-3">
          <Shield className="w-5 h-5 text-brand-700 flex-shrink-0 mt-0.5" />
          <div className="text-sm">
            <p className="font-semibold text-[var(--foreground)]">
              Tamper-Evident SHA-256 Audit Trail
            </p>
            <p className="text-[var(--muted)] text-xs mt-0.5">
              Events are cryptographically chained. Each record hashes its canonical data with its predecessor hash.
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2 flex-shrink-0">
          <a
            href="/api/admin/audit/export?download=true"
            className="btn btn-secondary btn-sm flex items-center gap-1.5"
            download
            id="export-signed-audit-btn"
          >
            <Download className="w-4 h-4" />
            Export Signed Report
          </a>
          <button
            onClick={handleVerifyChain}
            disabled={verifying}
            className="btn btn-primary btn-sm flex-shrink-0"
            id="verify-audit-chain-btn"
          >
            {verifying ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                Verifying Chain...
              </>
            ) : (
              <>
                <Key className="w-4 h-4" />
                Verify Hash Chain
              </>
            )}
          </button>
        </div>
      </div>

      {/* Verification result report */}
      {verificationResult && (
        <div
          className={`mb-6 p-4 rounded-xl border animate-fade-in ${
            verificationResult.valid
              ? "bg-success/5 border-success/30 text-success"
              : "bg-danger/5 border-danger/30 text-danger"
          }`}
          id="audit-verification-banner"
        >
          <div className="flex items-center gap-2 font-semibold text-sm">
            {verificationResult.valid ? (
              <>
                <CheckCircle2 className="w-5 h-5 text-success" />
                Audit Hash Chain Verified: 100% Cryptographically Sound
              </>
            ) : (
              <>
                <AlertTriangle className="w-5 h-5 text-danger" />
                Tampering Detected: Hash Chain Mismatches Found ({verificationResult.mismatches.length})
              </>
            )}
          </div>
          <p className="text-xs text-[var(--muted)] mt-1 ml-7">
            {verificationResult.valid
              ? `All ${total} logged events verify against their canonical SHA-256 hashes and previous hash pointers.`
              : `One or more audit events have altered event data, missing links, or forged hashes.`}
            {verificationResult.verified_at && ` (Verified at ${new Date(verificationResult.verified_at).toLocaleTimeString()})`}
          </p>
        </div>
      )}

      {/* Security Evaluator Tamper Demo Card */}
      <div className="card-glass border border-brand-700/20 p-4 mb-6 rounded-xl bg-surface-200">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <span className="badge badge-brand text-[10px] font-bold uppercase tracking-wider">
                Recruiter & Evaluator Demo
              </span>
              <span className="text-xs font-semibold text-[var(--foreground)]">
                Tamper Attack & Cryptographic Breach Simulator
              </span>
            </div>
            <p className="text-xs text-[var(--muted)] mt-1">
              Test TrustVault&apos;s live tamper detection. Modify an underlying audit record directly in storage, then observe the SHA-256 chain catch the violation.
            </p>
          </div>
          <div className="flex items-center gap-2 flex-wrap flex-shrink-0">
            <button
              onClick={handleSimulateTamper}
              disabled={tampering}
              className="btn btn-sm btn-danger flex items-center gap-1.5"
              id="simulate-tamper-btn"
            >
              {tampering ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <AlertTriangle className="w-3.5 h-3.5" />}
              Simulate Tamper Attack
            </button>
            <button
              onClick={handleRestoreTamper}
              disabled={tampering}
              className="btn btn-sm btn-secondary flex items-center gap-1.5"
              id="restore-tamper-btn"
            >
              {tampering ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <RefreshCw className="w-3.5 h-3.5 text-success" />}
              Restore Chain
            </button>
          </div>
        </div>
        {tamperStatus && (
          <div className="mt-3 text-xs p-2.5 rounded-lg bg-[var(--input-bg)] border border-[var(--card-border)] flex items-center gap-2 animate-fade-in">
            <ShieldAlert className="w-4 h-4 text-brand-700 flex-shrink-0" />
            <span>{tamperStatus}</span>
          </div>
        )}
      </div>

      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-3 mb-6">
        <div className="relative">
          <Filter className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[var(--muted)]" />
          <select
            value={actionFilter}
            onChange={(e) => {
              setActionFilter(e.target.value);
              setPage(1);
            }}
            className="input pl-10 pr-8 appearance-none cursor-pointer min-w-[180px]"
            id="audit-action-filter"
          >
            {ACTIONS.map((a) => (
              <option key={a} value={a}>
                {a === "all" ? "All Actions" : formatAction(a)}
              </option>
            ))}
          </select>
        </div>
        <div className="relative">
          <Filter className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[var(--muted)]" />
          <select
            value={resultFilter}
            onChange={(e) => {
              setResultFilter(e.target.value);
              setPage(1);
            }}
            className="input pl-10 pr-8 appearance-none cursor-pointer min-w-[140px]"
            id="audit-result-filter"
          >
            <option value="all">All Results</option>
            <option value="allowed">Allowed</option>
            <option value="denied">Denied</option>
          </select>
        </div>
        <div className="flex-1" />
        <div className="text-sm text-[var(--muted)] flex items-center gap-1">
          <Activity className="w-4 h-4" />
          {total} total events
        </div>
      </div>

      {/* Events Table */}
      {loading ? (
        <div className="card space-y-3">
          {Array.from({ length: 8 }).map((_, i) => (
            <div key={i} className="skeleton h-10 w-full" />
          ))}
        </div>
      ) : events.length > 0 ? (
        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Actor</th>
                <th>Action</th>
                <th>Result</th>
                <th>Document</th>
                <th>Details</th>
                <th className="hidden lg:table-cell">Hash</th>
              </tr>
            </thead>
            <tbody>
              {events.map((event) => (
                <tr key={event.id}>
                  <td className="whitespace-nowrap">
                    <div className="flex items-center gap-1.5 text-xs">
                      <Clock className="w-3 h-3 text-[var(--muted)]" />
                      {new Date(event.occurred_at).toLocaleString()}
                    </div>
                  </td>
                  <td className="text-xs">
                    {event.actor_email || (
                      <span className="text-[var(--muted)]">System</span>
                    )}
                  </td>
                  <td>
                    <span className="badge badge-neutral text-xs">
                      {formatAction(event.action)}
                    </span>
                  </td>
                  <td>
                    <span
                      className={`badge ${
                        event.result === "allowed"
                          ? "badge-success"
                          : "badge-danger"
                      }`}
                    >
                      {event.result === "allowed" ? (
                        <CheckCircle2 className="w-3 h-3 mr-1" />
                      ) : (
                        <AlertTriangle className="w-3 h-3 mr-1" />
                      )}
                      {event.result}
                    </span>
                  </td>
                  <td className="text-xs font-mono text-[var(--muted)]">
                    {event.document_id
                      ? event.document_id.substring(0, 8) + "..."
                      : "—"}
                  </td>
                  <td className="text-xs text-[var(--muted)] max-w-[200px] truncate">
                    {Object.keys(event.details_jsonb).length > 0
                      ? JSON.stringify(event.details_jsonb).substring(0, 60)
                      : "—"}
                  </td>
                  <td className="hidden lg:table-cell">
                    <code className="text-[10px] text-[var(--muted)] font-mono">
                      {event.event_hash.substring(0, 12)}...
                    </code>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="empty-state py-16">
          <Activity className="w-12 h-12 text-[var(--muted)] opacity-30" />
          <p className="text-lg font-medium mt-3">No audit events found</p>
          <p className="text-sm text-[var(--muted)] mt-1">
            Try adjusting your filters
          </p>
        </div>
      )}

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between mt-6">
          <p className="text-sm text-[var(--muted)]">
            Showing {(page - 1) * pageSize + 1}–
            {Math.min(page * pageSize, total)} of {total}
          </p>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setPage(page - 1)}
              disabled={page === 1}
              className="btn btn-secondary btn-sm"
            >
              <ChevronLeft className="w-4 h-4" /> Prev
            </button>
            <span className="text-sm">
              {page} / {totalPages}
            </span>
            <button
              onClick={() => setPage(page + 1)}
              disabled={page >= totalPages}
              className="btn btn-secondary btn-sm"
            >
              Next <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

function formatAction(action: string): string {
  const map: Record<string, string> = {
    upload: "Upload",
    download: "Download",
    preview: "View",
    update: "Update",
    delete: "Delete",
    restore: "Restore",
    permission_grant: "Grant Permission",
    permission_revoke: "Revoke Permission",
    login: "Login",
    login_failure: "Login Failed",
    logout: "Logout",
    search: "Search",
    version_upload: "New Version",
    admin_action: "Admin Action",
    ai_suggestion: "AI Suggestion",
    ai_suggestion_confirmed: "AI Confirmed",
  };
  return map[action] || action;
}
