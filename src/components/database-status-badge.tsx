"use client";

import { useState, useEffect } from "react";
import { Database, CheckCircle2, RefreshCw, X, Server, Layers } from "lucide-react";

interface DatabaseStatus {
  configured: boolean;
  connected: boolean;
  cluster: string;
  dbName: string;
  latencyMs?: number;
  collections?: string[];
  counts?: Record<string, number>;
}

export function DatabaseStatusBadge({ collapsed = false }: { collapsed?: boolean }) {
  const [status, setStatus] = useState<DatabaseStatus | null>(null);
  const [showModal, setShowModal] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [syncMessage, setSyncMessage] = useState<string | null>(null);

  const fetchStatus = async () => {
    try {
      const res = await fetch("/api/database/status");
      const data = await res.json();
      if (data.success) {
        setStatus(data);
      }
    } catch {
      // offline fallback
    }
  };

  useEffect(() => {
    let mounted = true;
    const load = async () => {
      try {
        const res = await fetch("/api/database/status");
        const data = await res.json();
        if (mounted && data.success) {
          setStatus(data);
        }
      } catch {
        // offline fallback
      }
    };
    void load();
    const interval = setInterval(load, 30000);
    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, []);

  const handleSync = async () => {
    setSyncing(true);
    setSyncMessage(null);
    try {
      const res = await fetch("/api/database/status", { method: "POST" });
      const data = await res.json();
      if (data.success) {
        setSyncMessage("Synchronized with MongoDB Atlas successfully!");
        await fetchStatus();
      } else {
        setSyncMessage(data.error || "Sync failed");
      }
    } catch {
      setSyncMessage("Sync request error");
    } finally {
      setSyncing(false);
    }
  };

  if (!status?.configured) return null;

  return (
    <>
      <button
        onClick={() => setShowModal(true)}
        className={`w-full text-left px-3 py-2 rounded-lg transition-all border ${
          status.connected
            ? "bg-emerald-500/10 border-emerald-500/20 hover:border-emerald-500/40 text-emerald-400"
            : "bg-amber-500/10 border-amber-500/20 hover:border-amber-500/40 text-amber-400"
        } ${collapsed ? "flex justify-center" : "flex items-center justify-between"}`}
        title="MongoDB Atlas Connection Status"
      >
        <div className="flex items-center gap-2 min-w-0">
          <div className="relative flex items-center justify-center">
            <Database className="w-4 h-4 flex-shrink-0" />
            <span
              className={`absolute -top-1 -right-1 w-2 h-2 rounded-full ${
                status.connected ? "bg-emerald-400 animate-pulse" : "bg-amber-400"
              }`}
            />
          </div>
          {!collapsed && (
            <div className="truncate text-xs">
              <p className="font-semibold text-[var(--foreground)] truncate">MongoDB Atlas</p>
              <p className="text-[10px] text-[var(--muted)] truncate">
                {status.cluster || "Cluster0"} {status.latencyMs ? `• ${status.latencyMs}ms` : ""}
              </p>
            </div>
          )}
        </div>
        {!collapsed && (
          <span className="text-[10px] uppercase font-bold px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-400">
            Live
          </span>
        )}
      </button>

      {/* Database Details Modal */}
      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm animate-fade-in">
          <div className="bg-[var(--card-bg)] border border-[var(--card-border)] rounded-xl max-w-lg w-full p-6 shadow-2xl relative">
            <button
              onClick={() => setShowModal(false)}
              className="absolute top-4 right-4 text-[var(--muted)] hover:text-[var(--foreground)] transition"
            >
              <X className="w-5 h-5" />
            </button>

            <div className="flex items-center gap-3 mb-4">
              <div className="w-10 h-10 rounded-xl bg-emerald-500/20 text-emerald-400 flex items-center justify-center">
                <Database className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-lg font-bold text-[var(--foreground)]">MongoDB Atlas Database</h3>
                <p className="text-xs text-[var(--muted)]">Active Cloud Cluster Connection</p>
              </div>
            </div>

            <div className="space-y-3 mb-6">
              <div className="flex items-center justify-between p-3 rounded-lg bg-[var(--input-bg)] border border-[var(--sidebar-border)] text-sm">
                <span className="text-[var(--muted)] flex items-center gap-2">
                  <Server className="w-4 h-4 text-brand-400" /> Cluster Host
                </span>
                <span className="font-mono text-xs font-semibold text-[var(--foreground)]">
                  {status.cluster}
                </span>
              </div>

              <div className="flex items-center justify-between p-3 rounded-lg bg-[var(--input-bg)] border border-[var(--sidebar-border)] text-sm">
                <span className="text-[var(--muted)]">Database Name</span>
                <span className="font-mono text-xs font-semibold text-emerald-400">
                  {status.dbName}
                </span>
              </div>

              <div className="flex items-center justify-between p-3 rounded-lg bg-[var(--input-bg)] border border-[var(--sidebar-border)] text-sm">
                <span className="text-[var(--muted)]">Network Latency</span>
                <span className="font-mono text-xs font-semibold text-emerald-400">
                  {status.latencyMs ? `${status.latencyMs} ms` : "Connected"}
                </span>
              </div>

              {status.counts && (
                <div className="p-3 rounded-lg bg-[var(--input-bg)] border border-[var(--sidebar-border)] text-sm">
                  <span className="text-xs font-semibold text-[var(--muted)] mb-2 flex items-center gap-1.5">
                    <Layers className="w-3.5 h-3.5 text-brand-400" />
                    Atlas Collections & Record Counts:
                  </span>
                  <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 mt-2">
                    {Object.entries(status.counts).map(([col, cnt]) => (
                      <div
                        key={col}
                        className="p-2 rounded bg-black/20 border border-white/5 flex flex-col"
                      >
                        <span className="text-[10px] text-[var(--muted)] uppercase font-mono">{col}</span>
                        <span className="text-sm font-bold text-[var(--foreground)]">{cnt}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {syncMessage && (
              <div className="p-3 mb-4 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 flex-shrink-0" />
                {syncMessage}
              </div>
            )}

            <div className="flex items-center justify-end gap-3 pt-2 border-t border-[var(--sidebar-border)]">
              <button
                onClick={handleSync}
                disabled={syncing}
                className="btn btn-secondary btn-sm flex items-center gap-2"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${syncing ? "animate-spin" : ""}`} />
                {syncing ? "Syncing..." : "Sync Store to Atlas"}
              </button>
              <button onClick={() => setShowModal(false)} className="btn btn-primary btn-sm">
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
