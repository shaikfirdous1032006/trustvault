"use client";

import { useState, useEffect } from "react";
import {
  Sliders,
  Shield,
  AlertTriangle,
  ArrowRight,
  Loader2,
  Info,
} from "lucide-react";
import type { Document, User, PolicySimulationResult } from "@/lib/types";

export default function PolicySimulatorPage() {
  const [users, setUsers] = useState<User[]>([]);
  const [documents, setDocuments] = useState<Document[]>([]);
  const [loading, setLoading] = useState(true);

  const [targetUserId, setTargetUserId] = useState<string>("");
  const [documentId, setDocumentId] = useState<string>("");
  const [proposedLevel, setProposedLevel] = useState<"read" | "edit" | "none">("read");
  const [expiresInHours, setExpiresInHours] = useState<number | "">(24);

  const [simulating, setSimulating] = useState(false);
  const [result, setResult] = useState<PolicySimulationResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function initData() {
      try {
        const [uRes, dRes] = await Promise.all([
          fetch("/api/admin/users"),
          fetch("/api/documents"),
        ]);
        const uJson = await uRes.json();
        const dJson = await dRes.json();

        if (uJson.success && uJson.data) {
          setUsers(uJson.data);
          if (uJson.data.length > 0) setTargetUserId(uJson.data[0].id);
        }
        if (dJson.success && dJson.data) {
          setDocuments(dJson.data);
          if (dJson.data.length > 0) setDocumentId(dJson.data[0].id);
        }
      } catch (e) {
        console.error("Failed to load simulator dependencies:", e);
      } finally {
        setLoading(false);
      }
    }
    initData();
  }, []);

  async function handleSimulate(e: React.FormEvent) {
    e.preventDefault();
    if (!targetUserId || !documentId) return;

    setSimulating(true);
    setError(null);
    setResult(null);

    try {
      const res = await fetch("/api/admin/policy/simulate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          targetUserId,
          documentId,
          proposedPermissionLevel: proposedLevel,
          expiresInHours: expiresInHours === "" ? null : Number(expiresInHours),
        }),
      });

      const json = await res.json();
      if (json.success) {
        setResult(json.data);
      } else {
        setError(json.error || "Simulation failed");
      }
    } catch {
      setError("Network error running simulation");
    } finally {
      setSimulating(false);
    }
  }

  return (
    <div className="space-y-8 p-6 lg:p-8 max-w-5xl mx-auto">
      {/* Header */}
      <div className="border-b border-[var(--card-border)] pb-6">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-purple-500/10 text-purple-400">
            <Sliders className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-2xl font-bold tracking-tight">Access Policy Simulator</h1>
            <p className="text-sm text-[var(--muted)]">
              Simulate &quot;What-If&quot; permission changes and project Zero-Trust policy engine outcomes before deployment.
            </p>
          </div>
        </div>
      </div>

      {loading ? (
        <div className="card p-12 text-center flex flex-col items-center justify-center gap-3">
          <Loader2 className="w-8 h-8 animate-spin text-brand-500" />
          <p className="text-sm text-[var(--muted)]">Loading users and document catalog...</p>
        </div>
      ) : (
        <form onSubmit={handleSimulate} className="card p-6 space-y-6">
          <h2 className="text-lg font-semibold flex items-center gap-2">
            <Shield className="w-5 h-5 text-brand-400" />
            Configure Proposed Policy Change
          </h2>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Target User */}
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wider text-[var(--muted)] mb-2">
                Target User
              </label>
              <select
                value={targetUserId}
                onChange={(e) => setTargetUserId(e.target.value)}
                className="input w-full text-sm py-2"
                required
              >
                {users.map((u) => (
                  <option key={u.id} value={u.id}>
                    {u.full_name || u.email} ({u.email} — Role: {u.role})
                  </option>
                ))}
              </select>
            </div>

            {/* Target Document */}
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wider text-[var(--muted)] mb-2">
                Target Document
              </label>
              <select
                value={documentId}
                onChange={(e) => setDocumentId(e.target.value)}
                className="input w-full text-sm py-2"
                required
              >
                {documents.map((d) => (
                  <option key={d.id} value={d.id}>
                    {d.title} (Sensitivity: {d.category})
                  </option>
                ))}
              </select>
            </div>

            {/* Proposed Permission Level */}
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wider text-[var(--muted)] mb-2">
                Proposed Action
              </label>
              <select
                value={proposedLevel}
                onChange={(e) => setProposedLevel(e.target.value as "read" | "edit" | "none")}
                className="input w-full text-sm py-2"
              >
                <option value="read">Grant Read Access</option>
                <option value="edit">Elevate to Edit Access</option>
                <option value="none">Revoke All Access</option>
              </select>
            </div>

            {/* Expiration Hours */}
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wider text-[var(--muted)] mb-2">
                Access Expiration (Hours)
              </label>
              <input
                type="number"
                min="1"
                max="720"
                placeholder="Leave blank for indefinite"
                value={expiresInHours}
                onChange={(e) => setExpiresInHours(e.target.value === "" ? "" : Number(e.target.value))}
                className="input w-full text-sm py-2"
              />
              <span className="text-xs text-[var(--muted)] mt-1 block">
                Zero-Trust best practices recommend time-bound grants (e.g. 24h).
              </span>
            </div>
          </div>

          {error && (
            <div className="p-4 rounded-xl border border-red-500/30 bg-red-500/10 text-red-400 text-sm flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          <div className="flex justify-end pt-2 border-t border-[var(--card-border)]">
            <button
              type="submit"
              disabled={simulating}
              className="btn btn-primary flex items-center gap-2"
            >
              {simulating ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  Running Zero-Trust Policy Simulation...
                </>
              ) : (
                <>
                  <Sliders className="w-4 h-4" />
                  Simulate Policy Impact
                </>
              )}
            </button>
          </div>
        </form>
      )}

      {/* Simulation Result */}
      {result && (
        <div className="card p-6 space-y-6 border-l-4 border-l-purple-500">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-[var(--card-border)] pb-4">
            <div>
              <h2 className="text-lg font-bold">Simulation Results</h2>
              <p className="text-xs text-[var(--muted)]">
                Simulation ID: {result.simulationId} • Evaluated: {new Date(result.simulatedAt).toLocaleTimeString()}
              </p>
            </div>

            <div className="flex items-center gap-2">
              <span className="text-xs font-semibold uppercase tracking-wider text-[var(--muted)]">
                Access Delta:
              </span>
              <span
                className={`px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider ${
                  result.accessDelta === "granted"
                    ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                    : result.accessDelta === "elevated"
                    ? "bg-amber-500/10 text-amber-400 border border-amber-500/20"
                    : result.accessDelta === "revoked"
                    ? "bg-red-500/10 text-red-400 border border-red-500/20"
                    : "bg-surface-700 text-surface-200"
                }`}
              >
                {result.accessDelta}
              </span>
            </div>
          </div>

          {/* Before & After Comparison */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 p-4 rounded-xl bg-[var(--background)] border border-[var(--card-border)]">
            <div>
              <span className="text-xs text-[var(--muted)] block">Previous Access Level</span>
              <span className="text-base font-bold uppercase tracking-wider mt-1 block">
                {result.previousAccess}
              </span>
            </div>

            <div className="flex items-center justify-center text-[var(--muted)]">
              <ArrowRight className="w-5 h-5 hidden sm:block" />
            </div>

            <div>
              <span className="text-xs text-[var(--muted)] block">Projected Access Level</span>
              <span className="text-base font-bold uppercase tracking-wider text-brand-400 mt-1 block">
                {result.projectedAccess}
              </span>
            </div>
          </div>

          {/* Policy Decision Outcome */}
          <div className="p-4 rounded-xl border border-[var(--card-border)] bg-[var(--background)] flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <span className="text-xs text-[var(--muted)] block uppercase tracking-wider font-semibold">
                Projected Zero-Trust Decision
              </span>
              <span className="text-sm font-semibold mt-1 block">
                {result.projectedOutcome === "ALLOW"
                  ? "Access permitted under policy criteria"
                  : result.projectedOutcome === "DENY"
                  ? "Access blocked by authorization rules"
                  : result.projectedOutcome === "REQUIRE_REVIEW"
                  ? "Access flagged for secondary approval"
                  : "Access temporarily restricted due to risk scoring"}
              </span>
            </div>

            <span
              className={`px-3 py-1.5 rounded-lg text-xs font-bold uppercase tracking-wider self-start sm:self-auto ${
                result.projectedOutcome === "ALLOW"
                  ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/30"
                  : "bg-red-500/10 text-red-400 border border-red-500/30"
              }`}
            >
              Outcome: {result.projectedOutcome}
            </span>
          </div>

          {/* Potential Risks */}
          {result.potentialRisks.length > 0 && (
            <div className="space-y-3">
              <h3 className="text-sm font-bold flex items-center gap-2 text-amber-400">
                <AlertTriangle className="w-4 h-4" />
                Detected Security Risks & Unintended Consequences ({result.potentialRisks.length})
              </h3>

              <div className="space-y-2">
                {result.potentialRisks.map((risk, idx) => (
                  <div
                    key={idx}
                    className="p-3 rounded-lg border border-amber-500/20 bg-amber-500/5 text-xs text-amber-300 flex items-start gap-2"
                  >
                    <Info className="w-4 h-4 shrink-0 mt-0.5" />
                    <span>{risk}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
