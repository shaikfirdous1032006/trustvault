"use client";

import { useState, useEffect, useCallback, useRef } from "react";
import {
  Activity,
  Clock,
  RefreshCw,
  LogIn,
  LogOut,
  Upload,
  Download,
  Eye,
  Key,
  FileText,
  Sparkles,
  Shield,
  ShieldAlert,
  Search,
  CheckCircle2,
  AlertTriangle,
  ChevronDown,
  UserCheck,
  UserX,
  Radio,
  WifiOff,
  Filter,
} from "lucide-react";
import { createClient, isSupabaseConfigured } from "@/lib/supabase/client";
import type { ActivityFeedItem } from "@/lib/types";

export type ActivityEvent = ActivityFeedItem;

type RealtimeState = "connecting" | "live" | "disconnected" | "local_sync";

function formatTimeAgo(isoString: string): string {
  if (!isoString) return "just now";
  const diffMs = Date.now() - new Date(isoString).getTime();
  const diffSec = Math.floor(diffMs / 1000);
  if (diffSec < 5) return "just now";
  if (diffSec < 60) return `${diffSec}s ago`;
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHours = Math.floor(diffMin / 60);
  if (diffHours < 24) return `${diffHours}h ago`;
  const diffDays = Math.floor(diffHours / 24);
  return `${diffDays}d ago`;
}

function getActionIcon(action: string, result: string) {
  if (result === "denied") {
    return <ShieldAlert className="w-4 h-4 text-rose-400" />;
  }

  switch (action) {
    case "login":
      return <LogIn className="w-4 h-4 text-emerald-400" />;
    case "login_failure":
      return <ShieldAlert className="w-4 h-4 text-rose-400" />;
    case "logout":
      return <LogOut className="w-4 h-4 text-amber-400" />;
    case "register":
      return <UserCheck className="w-4 h-4 text-emerald-400" />;
    case "register_failure":
      return <UserX className="w-4 h-4 text-rose-400" />;
    case "download":
      return <Download className="w-4 h-4 text-blue-400" />;
    case "upload":
    case "version_upload":
      return <Upload className="w-4 h-4 text-purple-400" />;
    case "preview":
      return <Eye className="w-4 h-4 text-indigo-400" />;
    case "permission_grant":
    case "permission_update":
      return <Key className="w-4 h-4 text-amber-400" />;
    case "permission_revoke":
      return <Key className="w-4 h-4 text-rose-400" />;
    case "share_link_created":
    case "share_link_viewed":
      return <FileText className="w-4 h-4 text-cyan-400" />;
    case "share_link_revoked":
    case "share_link_denied":
      return <ShieldAlert className="w-4 h-4 text-rose-400" />;
    case "role_change":
    case "account_activated":
    case "account_deactivated":
    case "admin_action":
      return <Shield className="w-4 h-4 text-brand-400" />;
    case "privacy_scan":
    case "privacy_redact":
      return <Sparkles className="w-4 h-4 text-brand-400" />;
    default:
      return <Activity className="w-4 h-4 text-emerald-400" />;
  }
}

function getActorBadge(email: string | null | undefined) {
  if (!email) {
    return (
      <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-neutral-500/10 text-[var(--muted)] border border-neutral-500/20">
        System
      </span>
    );
  }
  const lower = email.toLowerCase();
  if (lower.startsWith("admin") || lower.includes("admin")) {
    return (
      <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/20">
        Admin
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
  if (lower.startsWith("viewer") || lower.includes("viewer")) {
    return (
      <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-blue-500/10 text-blue-400 border border-blue-500/20">
        Viewer
      </span>
    );
  }
  return (
    <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-neutral-500/10 text-[var(--muted)] border border-neutral-500/20">
      User
    </span>
  );
}

interface DashboardRecentActivityProps {
  initialEvents?: Array<{
    id: string;
    action: string;
    result: string;
    occurred_at: string;
    actor_email: string | null;
    actor_id?: string | null;
    document_id?: string | null;
    document_title?: string | null;
    description?: string;
    target_resource_type?: string;
    target_resource_id?: string | null;
    details?: Record<string, unknown>;
  }>;
}

export function DashboardRecentActivity({ initialEvents = [] }: DashboardRecentActivityProps) {
  const [events, setEvents] = useState<ActivityEvent[]>(() =>
    initialEvents.map((e) => ({
      id: e.id,
      action: e.action,
      result: e.result,
      occurred_at: e.occurred_at,
      actor_id: e.actor_id || null,
      actor_email: e.actor_email || null,
      document_id: e.document_id || null,
      document_title: e.document_title || null,
      description: e.description || `${e.actor_email || "System"} performed ${e.action}`,
      target_resource_type: e.target_resource_type || (e.document_id ? "document" : "system"),
      target_resource_id: e.target_resource_id || e.document_id || null,
      details: e.details || {},
    }))
  );

  const [loading, setLoading] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [realtimeState, setRealtimeState] = useState<RealtimeState>(() =>
    !isSupabaseConfigured() ? "local_sync" : "connecting"
  );
  const [page, setPage] = useState(1);
  const [hasMore, setHasMore] = useState(false);
  const [totalCount, setTotalCount] = useState(0);

  // Database-backed filter states
  const [search, setSearch] = useState("");
  const [debouncedSearch, setDebouncedSearch] = useState("");
  const [category, setCategory] = useState<"all" | "auth" | "documents" | "permissions" | "admin" | "security">("all");
  const [resultFilter, setResultFilter] = useState<"all" | "allowed" | "denied">("all");
  const [dateFilter, setDateFilter] = useState<"all" | "today" | "7d" | "30d">("all");
  const [expandedEventId, setExpandedEventId] = useState<string | null>(null);

  // Debounce search
  useEffect(() => {
    const handler = setTimeout(() => {
      setDebouncedSearch(search);
      setPage(1);
    }, 350);
    return () => clearTimeout(handler);
  }, [search]);

  // Fetch activities from backend with database-level filtering
  const fetchActivities = useCallback(
    async (targetPage = 1, append = false, isManual = false) => {
      if (isManual) setRefreshing(true);
      else if (targetPage === 1 && !append) setLoading(true);
      else if (append) setLoadingMore(true);

      try {
        const params = new URLSearchParams();
        params.set("page", targetPage.toString());
        params.set("pageSize", "10");
        if (debouncedSearch) params.set("search", debouncedSearch);
        if (category !== "all") params.set("category", category);
        if (resultFilter !== "all") params.set("result", resultFilter);

        if (dateFilter === "today") {
          const startOfToday = new Date();
          startOfToday.setHours(0, 0, 0, 0);
          params.set("dateFrom", startOfToday.toISOString());
        } else if (dateFilter === "7d") {
          const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
          params.set("dateFrom", sevenDaysAgo.toISOString());
        } else if (dateFilter === "30d") {
          const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
          params.set("dateFrom", thirtyDaysAgo.toISOString());
        }

        const res = await fetch(`/api/dashboard/activity?${params.toString()}`);
        const json = await res.json();

        if (json.success && Array.isArray(json.data)) {
          setEvents((prev) => {
            if (append) {
              const existingIds = new Set(prev.map((e) => e.id));
              const newItems = json.data.filter((e: ActivityEvent) => !existingIds.has(e.id));
              return [...prev, ...newItems];
            }
            return json.data;
          });
          setTotalCount(json.total || json.data.length);
          setHasMore(Boolean(json.hasMore));
          setPage(targetPage);
        }
      } catch (err) {
        console.warn("[RecentActivity] Failed to fetch activities:", err);
      } finally {
        setLoading(false);
        setLoadingMore(false);
        if (isManual) setRefreshing(false);
      }
    },
    [debouncedSearch, category, resultFilter, dateFilter]
  );

  // Refetch when filters change
  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        const params = new URLSearchParams();
        params.set("page", "1");
        params.set("pageSize", "10");
        if (debouncedSearch) params.set("search", debouncedSearch);
        if (category !== "all") params.set("category", category);
        if (resultFilter !== "all") params.set("result", resultFilter);

        if (dateFilter === "today") {
          const startOfToday = new Date();
          startOfToday.setHours(0, 0, 0, 0);
          params.set("dateFrom", startOfToday.toISOString());
        } else if (dateFilter === "7d") {
          const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
          params.set("dateFrom", sevenDaysAgo.toISOString());
        } else if (dateFilter === "30d") {
          const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
          params.set("dateFrom", thirtyDaysAgo.toISOString());
        }

        const res = await fetch(`/api/dashboard/activity?${params.toString()}`);
        const json = await res.json();

        if (json.success && Array.isArray(json.data) && !cancelled) {
          setEvents(json.data);
          setTotalCount(json.total || json.data.length);
          setHasMore(Boolean(json.hasMore));
          setPage(1);
        }
      } catch (err) {
        console.warn("[RecentActivity] Failed to fetch activities:", err);
      }
    }

    void load();
    return () => {
      cancelled = true;
    };
  }, [debouncedSearch, category, resultFilter, dateFilter]);

  // Load older records
  const handleLoadMore = () => {
    if (loadingMore || !hasMore) return;
    void fetchActivities(page + 1, true, false);
  };

  // Real-time Subscription Setup with Supabase
  const reconnectRef = useRef<() => void>(() => {});

  useEffect(() => {
    if (!isSupabaseConfigured()) {
      // Graceful fallback interval for local-db / MongoDB mode
      const interval = setInterval(() => {
        void fetchActivities(1, false, false);
      }, 5000);
      return () => clearInterval(interval);
    }

    const supabase = createClient();

    const channelName = `realtime-audit-${Math.random().toString(36).slice(2, 8)}`;
    const channel = supabase
      .channel(channelName)
      .on(
        "postgres_changes",
        {
          event: "INSERT",
          schema: "public",
          table: "audit_events",
        },
        (payload) => {
          const newRow = payload.new as {
            id: string;
            action: string;
            result: string;
            occurred_at: string;
            actor_id: string | null;
            actor_email: string | null;
            document_id: string | null;
            details_jsonb?: Record<string, unknown>;
          };

          if (!newRow || !newRow.id) return;

          setEvents((prev) => {
            // Prevent duplicate entries
            if (prev.some((e) => e.id === newRow.id)) return prev;

            const details = newRow.details_jsonb || {};
            const docTitle = (details.file_name as string) || (details.title as string) || (details.document_title as string) || null;
            const description = (details.description as string) || `${newRow.actor_email || "System"} performed ${newRow.action}`;

            const newEvent: ActivityEvent = {
              id: newRow.id,
              action: newRow.action,
              result: newRow.result,
              occurred_at: newRow.occurred_at || new Date().toISOString(),
              actor_id: newRow.actor_id,
              actor_email: newRow.actor_email,
              document_id: newRow.document_id,
              document_title: docTitle,
              description,
              target_resource_type: (details.target_resource_type as string) || (newRow.document_id ? "document" : "system"),
              target_resource_id: (details.target_resource_id as string) || newRow.document_id || null,
              details,
            };

            // Check if matches active filters before prepending
            if (category !== "all") {
              const authActions = ["login", "logout", "login_failure", "register", "register_failure"];
              const docActions = ["upload", "download", "preview", "update", "delete", "restore", "version_upload"];
              const permActions = ["permission_grant", "permission_revoke", "permission_update", "share_link_created", "share_link_revoked", "share_link_viewed", "share_link_denied"];
              const adminActions = ["admin_action", "role_change", "account_activated", "account_deactivated"];
              const secActions = ["security_alert", "login_failure", "share_link_denied"];

              if (category === "auth" && !authActions.includes(newEvent.action)) return prev;
              if (category === "documents" && !docActions.includes(newEvent.action)) return prev;
              if (category === "permissions" && !permActions.includes(newEvent.action)) return prev;
              if (category === "admin" && !adminActions.includes(newEvent.action)) return prev;
              if (category === "security" && newEvent.result !== "denied" && !secActions.includes(newEvent.action)) return prev;
            }

            if (resultFilter !== "all" && newEvent.result !== resultFilter) return prev;

            return [newEvent, ...prev];
          });
        }
      )
      .subscribe((status) => {
        if (status === "SUBSCRIBED") {
          setRealtimeState("live");
        } else if (status === "TIMED_OUT" || status === "CLOSED" || status === "CHANNEL_ERROR") {
          setRealtimeState("disconnected");
        } else {
          setRealtimeState("connecting");
        }
      });

    reconnectRef.current = () => {
      setRealtimeState("connecting");
      void channel.subscribe();
      void fetchActivities(1, false, true);
    };

    return () => {
      void supabase.removeChannel(channel);
    };
  }, [category, resultFilter, fetchActivities]);

  return (
    <div className="card h-full flex flex-col justify-between">
      <div>
        {/* Header with live feed indicator and refresh button */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-3">
          <div className="flex items-center gap-2">
            <h2 className="text-lg font-semibold flex items-center gap-2 text-[var(--foreground)]">
              <Activity className="w-5 h-5 text-emerald-400" />
              Activity Feed
            </h2>

            {/* True Realtime Connection Status Indicator */}
            {realtimeState === "live" && (
              <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20" title="Connected to Supabase Realtime channel">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                Live Feed
              </span>
            )}
            {realtimeState === "connecting" && (
              <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/20" title="Connecting to Realtime stream...">
                <Radio className="w-2.5 h-2.5 animate-spin text-amber-400" />
                Connecting...
              </span>
            )}
            {realtimeState === "disconnected" && (
              <button
                onClick={() => reconnectRef.current()}
                className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/20 hover:bg-rose-500/20 transition cursor-pointer"
                title="Realtime disconnected. Click to reconnect"
              >
                <WifiOff className="w-2.5 h-2.5" />
                Disconnected (Retry)
              </button>
            )}
            {realtimeState === "local_sync" && (
              <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20" title="Live sync via database poller">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                Live Sync
              </span>
            )}
          </div>

          <div className="flex items-center gap-1.5 self-end sm:self-auto">
            {totalCount > 0 && (
              <span className="text-[11px] text-[var(--muted)] font-mono">
                {totalCount} total
              </span>
            )}
            <button
              onClick={() => void fetchActivities(1, false, true)}
              disabled={refreshing}
              className="p-1.5 rounded-lg hover:bg-[var(--input-bg)] text-[var(--muted)] hover:text-[var(--foreground)] transition cursor-pointer"
              title="Refresh activity feed"
              id="refresh-activity-feed-btn"
            >
              <RefreshCw className={`w-4 h-4 ${refreshing ? "animate-spin text-brand-400" : ""}`} />
            </button>
          </div>
        </div>

        {/* Database Search Input */}
        <div className="relative mb-3">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[var(--muted)]" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search activity by actor, action, or document..."
            className="input text-xs pl-8 py-1.5 w-full bg-[var(--input-bg)]"
            id="activity-feed-search"
          />
          {search && (
            <button
              onClick={() => setSearch("")}
              className="absolute right-2.5 top-1/2 -translate-y-1/2 text-xs text-[var(--muted)] hover:text-[var(--foreground)]"
            >
              ✕
            </button>
          )}
        </div>

        {/* Quick Category Filter Chips */}
        <div className="flex items-center gap-1 mb-2.5 overflow-x-auto pb-1 scrollbar-thin">
          <button
            onClick={() => {
              setCategory("all");
              setPage(1);
            }}
            className={`px-2 py-0.5 rounded text-[11px] font-semibold transition cursor-pointer whitespace-nowrap ${
              category === "all"
                ? "bg-brand-600 text-white"
                : "bg-[var(--input-bg)] text-[var(--muted)] hover:text-[var(--foreground)]"
            }`}
          >
            All
          </button>
          <button
            onClick={() => {
              setCategory("auth");
              setPage(1);
            }}
            className={`px-2 py-0.5 rounded text-[11px] font-semibold transition flex items-center gap-1 cursor-pointer whitespace-nowrap ${
              category === "auth"
                ? "bg-amber-500/20 text-amber-300 border border-amber-500/30"
                : "bg-[var(--input-bg)] text-[var(--muted)] hover:text-[var(--foreground)]"
            }`}
            id="filter-auth-history"
          >
            <LogIn className="w-3 h-3 text-emerald-400" />
            Auth & Logins
          </button>
          <button
            onClick={() => {
              setCategory("documents");
              setPage(1);
            }}
            className={`px-2 py-0.5 rounded text-[11px] font-semibold transition flex items-center gap-1 cursor-pointer whitespace-nowrap ${
              category === "documents"
                ? "bg-purple-500/20 text-purple-300 border border-purple-500/30"
                : "bg-[var(--input-bg)] text-[var(--muted)] hover:text-[var(--foreground)]"
            }`}
          >
            <FileText className="w-3 h-3 text-purple-400" />
            Documents
          </button>
          <button
            onClick={() => {
              setCategory("permissions");
              setPage(1);
            }}
            className={`px-2 py-0.5 rounded text-[11px] font-semibold transition flex items-center gap-1 cursor-pointer whitespace-nowrap ${
              category === "permissions"
                ? "bg-blue-500/20 text-blue-300 border border-blue-500/30"
                : "bg-[var(--input-bg)] text-[var(--muted)] hover:text-[var(--foreground)]"
            }`}
          >
            <Key className="w-3 h-3 text-blue-400" />
            Permissions
          </button>
          <button
            onClick={() => {
              setCategory("security");
              setPage(1);
            }}
            className={`px-2 py-0.5 rounded text-[11px] font-semibold transition flex items-center gap-1 cursor-pointer whitespace-nowrap ${
              category === "security"
                ? "bg-rose-500/20 text-rose-300 border border-rose-500/30"
                : "bg-[var(--input-bg)] text-[var(--muted)] hover:text-[var(--foreground)]"
            }`}
          >
            <ShieldAlert className="w-3 h-3 text-rose-400" />
            Security & Denied
          </button>
        </div>

        {/* Secondary Filter Controls: Result and Date filters */}
        <div className="flex items-center justify-between gap-2 mb-3 text-[11px] text-[var(--muted)]">
          <div className="flex items-center gap-1.5">
            <Filter className="w-3 h-3 text-[var(--muted)]" />
            <select
              value={resultFilter}
              onChange={(e) => {
                setResultFilter(e.target.value as "all" | "allowed" | "denied");
                setPage(1);
              }}
              className="bg-[var(--input-bg)] border border-[var(--card-border)] rounded px-1.5 py-0.5 text-[11px] text-[var(--foreground)] cursor-pointer"
              id="activity-result-filter"
            >
              <option value="all">All Outcomes</option>
              <option value="allowed">Allowed Only</option>
              <option value="denied">Denied Only</option>
            </select>
          </div>

          <div className="flex items-center gap-1.5">
            <select
              value={dateFilter}
              onChange={(e) => {
                setDateFilter(e.target.value as "all" | "today" | "7d" | "30d");
                setPage(1);
              }}
              className="bg-[var(--input-bg)] border border-[var(--card-border)] rounded px-1.5 py-0.5 text-[11px] text-[var(--foreground)] cursor-pointer"
              id="activity-date-filter"
            >
              <option value="all">All Time</option>
              <option value="today">Today</option>
              <option value="7d">Last 7 Days</option>
              <option value="30d">Last 30 Days</option>
            </select>
          </div>
        </div>

        {/* Activity Feed List */}
        {loading ? (
          <div className="space-y-2 py-4">
            {Array.from({ length: 5 }).map((_, i) => (
              <div key={i} className="skeleton h-12 w-full rounded-lg" />
            ))}
          </div>
        ) : events.length > 0 ? (
          <div className="space-y-2 max-h-[460px] overflow-y-auto pr-1 scrollbar-thin">
            {events.map((event) => {
              const isExpanded = expandedEventId === event.id;
              const hasMetadata = Object.keys(event.details || {}).length > 0;

              return (
                <div
                  key={event.id}
                  className="p-2.5 rounded-lg bg-[var(--card-bg)] hover:bg-[var(--input-bg)] transition-all border border-[var(--card-border)] hover:border-white/10 group"
                >
                  <div className="flex items-start gap-2.5">
                    <div className="mt-0.5 p-1.5 rounded-md bg-[var(--input-bg)] flex-shrink-0 border border-white/5">
                      {getActionIcon(event.action, event.result)}
                    </div>

                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-1.5 mb-0.5 flex-wrap">
                        {getActorBadge(event.actor_email)}
                        <span className="text-[10px] text-[var(--muted)] font-mono truncate">
                          {event.actor_email || "System"}
                        </span>
                        {event.document_title && (
                          <span className="text-[10px] px-1.5 py-0.2 rounded bg-brand-500/10 text-brand-400 font-mono border border-brand-500/20 truncate max-w-[130px]">
                            {event.document_title}
                          </span>
                        )}
                      </div>

                      <p className="text-xs text-[var(--foreground)] leading-relaxed">
                        {event.description}
                      </p>

                      <div className="flex items-center justify-between gap-2 mt-1">
                        <span
                          className="text-[10px] text-[var(--muted)] flex items-center gap-1 font-mono cursor-help"
                          title={new Date(event.occurred_at).toLocaleString()}
                        >
                          <Clock className="w-3 h-3 text-[var(--muted)]" />
                          {formatTimeAgo(event.occurred_at)}
                        </span>

                        <div className="flex items-center gap-1.5">
                          {hasMetadata && (
                            <button
                              onClick={() => setExpandedEventId(isExpanded ? null : event.id)}
                              className="text-[10px] text-[var(--muted)] hover:text-brand-400 flex items-center gap-0.5 cursor-pointer"
                              title="Toggle metadata view"
                            >
                              <span>Details</span>
                              <ChevronDown className={`w-2.5 h-2.5 transition-transform ${isExpanded ? "rotate-180" : ""}`} />
                            </button>
                          )}

                          <span
                            className={`badge text-[9px] py-0 px-1.5 font-semibold ${
                              event.result === "allowed" ? "badge-success" : "badge-danger"
                            }`}
                          >
                            {event.result === "allowed" ? (
                              <CheckCircle2 className="w-2.5 h-2.5 inline mr-0.5" />
                            ) : (
                              <AlertTriangle className="w-2.5 h-2.5 inline mr-0.5" />
                            )}
                            {event.result}
                          </span>
                        </div>
                      </div>

                      {/* Expandable Non-Sensitive Details Drawer */}
                      {isExpanded && (
                        <div className="mt-2 pt-2 border-t border-[var(--sidebar-border)] text-[10px] font-mono text-[var(--muted)] bg-[var(--input-bg)] p-2 rounded-md animate-fade-in">
                          <div className="grid grid-cols-2 gap-1 mb-1">
                            <div>Event ID: {event.id.slice(0, 8)}...</div>
                            <div>Action: {event.action}</div>
                            {event.target_resource_type && (
                              <div>Resource: {event.target_resource_type}</div>
                            )}
                            <div>Exact: {new Date(event.occurred_at).toISOString().replace("T", " ").slice(0, 19)} UTC</div>
                          </div>
                          {Object.keys(event.details).length > 0 && (
                            <pre className="text-[9px] text-[var(--foreground)] overflow-x-auto whitespace-pre-wrap bg-black/20 p-1.5 rounded mt-1">
                              {JSON.stringify(event.details, null, 2)}
                            </pre>
                          )}
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              );
            })}

            {/* Load older activities button */}
            {hasMore && (
              <div className="text-center pt-2">
                <button
                  onClick={handleLoadMore}
                  disabled={loadingMore}
                  className="btn btn-secondary btn-sm text-xs py-1 px-3 w-full cursor-pointer"
                  id="load-more-activity-btn"
                >
                  {loadingMore ? (
                    <span className="flex items-center justify-center gap-1.5">
                      <RefreshCw className="w-3 h-3 animate-spin" />
                      Loading older activities...
                    </span>
                  ) : (
                    "Load older activities"
                  )}
                </button>
              </div>
            )}
          </div>
        ) : (
          <div className="empty-state py-8">
            <Activity className="w-10 h-10 text-[var(--muted)] opacity-30 mx-auto" />
            <p className="text-sm text-[var(--muted)] mt-2">
              {search
                ? `No activities matching "${search}"`
                : category === "auth"
                ? "No authentication events recorded"
                : category === "documents"
                ? "No document activity recorded"
                : category === "security"
                ? "No security alerts or denied actions"
                : "No recent activity recorded yet"}
            </p>
            <p className="text-xs text-[var(--muted)] opacity-70 mt-1">
              Events will appear here in real time as they occur across the platform.
            </p>
          </div>
        )}
      </div>

      {/* Footer */}
      <div className="mt-4 pt-3 border-t border-[var(--sidebar-border)] flex items-center justify-between text-[11px] text-[var(--muted)]">
        <span className="flex items-center gap-1.5">
          <Shield className="w-3 h-3 text-brand-400" />
          SHA-256 Tamper-Evident Trail
        </span>
        <span className="font-mono text-[10px]">
          {realtimeState === "live" ? "Realtime Active" : realtimeState === "local_sync" ? "Local Live Sync" : "Syncing"}
        </span>
      </div>
    </div>
  );
}
