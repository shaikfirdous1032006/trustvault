"use client";

import { useState, useEffect, useCallback } from "react";
import {
  Activity,
  Search,
  Filter,
  ChevronLeft,
  ChevronRight,
  CheckCircle2,
  AlertTriangle,
  Clock,
  Shield,
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
  const pageSize = 30;

  const fetchEvents = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      params.set("page", page.toString());
      params.set("pageSize", pageSize.toString());
      if (actionFilter !== "all") params.set("action", actionFilter);
      if (resultFilter !== "all") params.set("result", resultFilter);

      const res = await fetch(`/api/admin/audit?${params}`);
      const data = await res.json();
      if (data.success) {
        setEvents(data.data);
        setTotal(data.total);
      }
    } catch {
      /* ignored */
    } finally {
      setLoading(false);
    }
  }, [page, actionFilter, resultFilter]);

  useEffect(() => {
    fetchEvents();
  }, [fetchEvents]);

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

      {/* Security info */}
      <div className="card-glass flex items-start gap-3 mb-6 p-4">
        <Shield className="w-5 h-5 text-brand-400 flex-shrink-0 mt-0.5" />
        <div className="text-sm">
          <p className="font-medium text-brand-300">
            Immutable Audit Trail
          </p>
          <p className="text-[var(--muted)] text-xs mt-0.5">
            Events are hash-chained using SHA-256. Database triggers prevent
            UPDATE, DELETE, and TRUNCATE. Each event references its predecessor
            for tamper detection.
          </p>
        </div>
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
