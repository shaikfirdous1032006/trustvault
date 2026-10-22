"use client";

import { useState, useEffect, useCallback } from "react";
import {
  Activity,
  CheckCircle2,
  AlertTriangle,
  Clock,
  RefreshCw,
  LogIn,
  LogOut,
  Upload,
  Download,
  Eye,
  Key,
  FileText,
  Shield,
  Sparkles,
} from "lucide-react";

export interface ActivityEvent {
  id: string;
  action: string;
  result: string;
  occurred_at: string;
  actor_id?: string | null;
  actor_email?: string | null;
  document_id?: string | null;
  document_title?: string | null;
  details?: Record<string, unknown>;
}

function formatTimeAgo(isoString: string): string {
  const diffMs = Date.now() - new Date(isoString).getTime();
  const diffSec = Math.floor(diffMs / 1000);
  if (diffSec < 5) return "just now";
  if (diffSec < 60) return `${diffSec}s ago`;
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHours = Math.floor(diffMin / 60);
  if (diffHours < 24) return `${diffHours}h ago`;
  return `${Math.floor(diffHours / 24)}d ago`;
}

function getActionIcon(action: string) {
  switch (action) {
    case "login":
      return <LogIn className="w-4 h-4 text-emerald-400" />;
    case "logout":
      return <LogOut className="w-4 h-4 text-amber-400" />;
    case "download":
      return <Download className="w-4 h-4 text-blue-400" />;
    case "upload":
    case "version_upload":
      return <Upload className="w-4 h-4 text-purple-400" />;
    case "preview":
      return <Eye className="w-4 h-4 text-indigo-400" />;
    case "permission_grant":
    case "permission_revoke":
      return <Key className="w-4 h-4 text-amber-400" />;
    case "privacy_scan":
    case "privacy_redact":
      return <Sparkles className="w-4 h-4 text-brand-400" />;
    default:
      return <Activity className="w-4 h-4 text-emerald-400" />;
  }
}

function getActorBadge(email: string | null | undefined) {
  if (!email) return null;
  const lower = email.toLowerCase();
  if (lower.startsWith("viewer") || lower.includes("viewer")) {
    return (
      <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-blue-500/10 text-blue-400 border border-blue-500/20">
        Viewer
      </span>
    );
  }
  if (lower.startsWith("owner") || lower.includes("owner")) {
    return (
      <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-purple-500/10 text-purple-400 border border-purple-500/20">
        Owner
      </span>
    );
  }
  if (lower.startsWith("admin") || lower.includes("admin")) {
    return (
      <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/20">
        Admin
      </span>
    );
  }
  return (
    <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-neutral-500/10 text-[var(--muted)] border border-neutral-500/20">
      User
    </span>
  );
}

function renderActionDescription(event: ActivityEvent) {
  const actor = event.actor_email || "Someone";
  const docTitle = event.document_title || (event.details?.file_name as string) || (event.details?.title as string);

  switch (event.action) {
    case "login":
      return (
        <span>
          <strong className="text-[var(--foreground)]">{actor}</strong> signed in
        </span>
      );
    case "logout":
      return (
        <span>
          <strong className="text-[var(--foreground)]">{actor}</strong> signed out
        </span>
      );
    case "download":
      return (
        <span>
          <strong className="text-[var(--foreground)]">{actor}</strong> downloaded{" "}
          <strong className="text-brand-400">{docTitle || "a document"}</strong>
        </span>
      );
    case "upload":
    case "version_upload":
      return (
        <span>
          <strong className="text-[var(--foreground)]">{actor}</strong> uploaded{" "}
          <strong className="text-brand-400">{docTitle || "a document"}</strong>
        </span>
      );
    case "preview":
      return (
        <span>
          <strong className="text-[var(--foreground)]">{actor}</strong> previewed{" "}
          <strong className="text-brand-400">{docTitle || "a document"}</strong>
        </span>
      );
    case "permission_grant":
      return (
        <span>
          <strong className="text-[var(--foreground)]">{actor}</strong> granted access on{" "}
          <strong className="text-brand-400">{docTitle || "a document"}</strong>
        </span>
      );
    case "permission_revoke":
      return (
        <span>
          <strong className="text-[var(--foreground)]">{actor}</strong> revoked access on{" "}
          <strong className="text-brand-400">{docTitle || "a document"}</strong>
        </span>
      );
    case "privacy_scan":
      return (
        <span>
          <strong className="text-[var(--foreground)]">{actor}</strong> scanned{" "}
          <strong className="text-brand-400">{docTitle || "a document"}</strong> with AI Privacy Shield
        </span>
      );
    case "privacy_redact":
      return (
        <span>
          <strong className="text-[var(--foreground)]">{actor}</strong> generated redacted copy of{" "}
          <strong className="text-brand-400">{docTitle || "a document"}</strong>
        </span>
      );
    default:
      return (
        <span>
          <strong className="text-[var(--foreground)]">{actor}</strong> performed{" "}
          <span className="font-mono text-xs">{event.action}</span>
          {docTitle ? ` on ${docTitle}` : ""}
        </span>
      );
  }
}

export function DashboardRecentActivity({ initialEvents = [] }: { initialEvents?: ActivityEvent[] }) {
  const [events, setEvents] = useState<ActivityEvent[]>(initialEvents);
  const [refreshing, setRefreshing] = useState(false);
  const [, setLastUpdated] = useState<Date>(new Date());

  const fetchActivities = useCallback(async (isManual = false) => {
    if (isManual) setRefreshing(true);
    try {
      const res = await fetch("/api/dashboard/activity");
      const json = await res.json();
      if (json.success && Array.isArray(json.data)) {
        setEvents(json.data);
        setLastUpdated(new Date());
      }
    } catch {
      // ignore
    } finally {
      if (isManual) setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    // Initial fetch to sync with remote MongoDB
    void fetchActivities(false);

    // Auto-poll every 3.5 seconds for real-time live events
    const interval = setInterval(() => {
      void fetchActivities(false);
    }, 3500);

    return () => clearInterval(interval);
  }, [fetchActivities]);

  return (
    <div className="card h-full flex flex-col justify-between">
      <div>
        {/* Header with live feed indicator and refresh button */}
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <h2 className="text-lg font-semibold flex items-center gap-2 text-[var(--foreground)]">
              <Activity className="w-5 h-5 text-emerald-400" />
              Recent Activity
            </h2>
            <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
              Live Feed
            </span>
          </div>

          <button
            onClick={() => void fetchActivities(true)}
            disabled={refreshing}
            className="p-1.5 rounded-lg hover:bg-[var(--input-bg)] text-[var(--muted)] hover:text-[var(--foreground)] transition"
            title="Refresh activity feed"
          >
            <RefreshCw className={`w-4 h-4 ${refreshing ? "animate-spin text-brand-400" : ""}`} />
          </button>
        </div>

        {/* Activity list */}
        {events && events.length > 0 ? (
          <div className="space-y-3">
            {events.slice(0, 8).map((event) => (
              <div
                key={event.id}
                className="flex items-start gap-3 p-2.5 rounded-lg hover:bg-[var(--input-bg)] transition-all border border-transparent hover:border-white/5 group"
              >
                <div className="mt-0.5 p-1.5 rounded-md bg-[var(--input-bg)] flex-shrink-0">
                  {getActionIcon(event.action)}
                </div>

                <div className="flex-1 min-w-0 text-xs">
                  <div className="flex items-center gap-1.5 mb-1 flex-wrap">
                    {getActorBadge(event.actor_email)}
                    <span className="text-[10px] text-[var(--muted)] font-mono truncate">
                      {event.actor_email}
                    </span>
                  </div>

                  <p className="text-xs text-[var(--foreground)] leading-relaxed">
                    {renderActionDescription(event)}
                  </p>

                  <p className="text-[10px] text-[var(--muted)] flex items-center gap-1 mt-1 font-mono">
                    <Clock className="w-3 h-3 text-[var(--muted)]" />
                    {formatTimeAgo(event.occurred_at)}
                  </p>
                </div>

                <div className="flex-shrink-0">
                  {event.result === "allowed" ? (
                    <span className="badge badge-success text-[10px] py-0.5">
                      Allowed
                    </span>
                  ) : (
                    <span className="badge badge-danger text-[10px] py-0.5">
                      Denied
                    </span>
                  )}
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="empty-state py-8">
            <Activity className="w-10 h-10 text-[var(--muted)] opacity-30" />
            <p className="text-sm text-[var(--muted)] mt-2">No recent activity yet</p>
            <p className="text-xs text-[var(--muted)] opacity-70 mt-1">
              Actions like logins, uploads, and downloads will appear here live.
            </p>
          </div>
        )}
      </div>

      <div className="mt-4 pt-3 border-t border-[var(--sidebar-border)] flex items-center justify-between text-[11px] text-[var(--muted)]">
        <span>Auto-syncing with MongoDB Atlas</span>
        <span className="font-mono">Every 3.5s</span>
      </div>
    </div>
  );
}
