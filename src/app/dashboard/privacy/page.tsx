"use client";

import { useState, useEffect } from "react";
import {
  Sparkles,
  FileText,
  AlertTriangle,
  CheckCircle2,
  Lock,
  Loader2,
  Eye,
} from "lucide-react";
import type { Document, PrivacyFinding, PrivacyScanResult } from "@/lib/types";
import Link from "next/link";

export default function PrivacyShieldPage() {
  const [documents, setDocuments] = useState<Document[]>([]);
  const [selectedDocId, setSelectedDocId] = useState<string>("");
  const [loadingDocs, setLoadingDocs] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState<PrivacyScanResult | null>(null);
  const [selectedFindings, setSelectedFindings] = useState<Record<string, boolean>>({});
  const [redacting, setRedacting] = useState(false);
  const [redactedDoc, setRedactedDoc] = useState<Document | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function loadDocuments() {
      try {
        const res = await fetch("/api/documents");
        const json = await res.json();
        if (json.success && json.data) {
          setDocuments(json.data);
          if (json.data.length > 0) {
            setSelectedDocId(json.data[0].id);
          }
        }
      } catch (e) {
        console.error("Failed to fetch documents", e);
      } finally {
        setLoadingDocs(false);
      }
    }
    loadDocuments();
  }, []);

  async function handleScan() {
    if (!selectedDocId) return;
    setScanning(true);
    setError(null);
    setScanResult(null);
    setRedactedDoc(null);

    try {
      const res = await fetch(`/api/documents/${selectedDocId}/privacy/scan`, {
        method: "POST",
      });
      const json = await res.json();
      if (json.success) {
        setScanResult(json.data);
        // Default select all findings
        const initialSelected: Record<string, boolean> = {};
        json.data.findings.forEach((f: PrivacyFinding) => {
          initialSelected[f.id] = true;
        });
        setSelectedFindings(initialSelected);
      } else {
        setError(json.error || "Failed to scan document");
      }
    } catch {
      setError("Network error running privacy scan");
    } finally {
      setScanning(false);
    }
  }

  function toggleFinding(id: string) {
    setSelectedFindings((prev) => ({
      ...prev,
      [id]: !prev[id],
    }));
  }

  async function handleRedact() {
    if (!selectedDocId || !scanResult) return;
    setRedacting(true);
    setError(null);

    const approvedIds = Object.keys(selectedFindings).filter((id) => selectedFindings[id]);

    try {
      const res = await fetch(`/api/documents/${selectedDocId}/privacy/redact`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ approvedFindingIds: approvedIds }),
      });
      const json = await res.json();
      if (json.success) {
        setRedactedDoc(json.data);
      } else {
        setError(json.error || "Failed to execute privacy redactions");
      }
    } catch {
      setError("Network error executing redaction");
    } finally {
      setRedacting(false);
    }
  }

  const selectedCount = Object.values(selectedFindings).filter(Boolean).length;

  return (
    <div className="space-y-8 p-6 lg:p-8 max-w-6xl mx-auto">
      {/* Header */}
      <div className="border-b border-[var(--card-border)] pb-6">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-brand-500/10 text-brand-400">
            <Sparkles className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-2xl font-bold tracking-tight">AI Privacy Shield</h1>
            <p className="text-sm text-[var(--muted)]">
              Automated sensitive data identification, owner-reviewed redaction, and safe asset generation.
            </p>
          </div>
        </div>
      </div>

      {/* Document Selection Card */}
      <div className="card p-6 space-y-4">
        <h2 className="text-lg font-semibold flex items-center gap-2">
          <FileText className="w-5 h-5 text-brand-400" />
          Select Document for Privacy Analysis
        </h2>

        {loadingDocs ? (
          <div className="flex items-center gap-2 text-sm text-[var(--muted)]">
            <Loader2 className="w-4 h-4 animate-spin" />
            Loading documents...
          </div>
        ) : documents.length === 0 ? (
          <div className="p-6 rounded-xl border border-[var(--card-border)] text-center text-sm text-[var(--muted)]">
            No documents found. <Link href="/dashboard/upload" className="text-brand-400 underline">Upload a document</Link> first.
          </div>
        ) : (
          <div className="flex flex-col sm:flex-row gap-4 items-center">
            <select
              value={selectedDocId}
              onChange={(e) => {
                setSelectedDocId(e.target.value);
                setScanResult(null);
                setRedactedDoc(null);
              }}
              className="input flex-1 text-sm py-2"
            >
              {documents.map((doc) => (
                <option key={doc.id} value={doc.id}>
                  {doc.title} ({doc.file_name} — {doc.category})
                </option>
              ))}
            </select>

            <button
              onClick={handleScan}
              disabled={scanning || !selectedDocId}
              className="btn btn-primary flex items-center gap-2 whitespace-nowrap"
            >
              {scanning ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  Scanning payload...
                </>
              ) : (
                <>
                  <Sparkles className="w-4 h-4" />
                  Scan for Sensitive Data
                </>
              )}
            </button>
          </div>
        )}

        {error && (
          <div className="p-4 rounded-xl border border-red-500/30 bg-red-500/10 text-red-400 text-sm flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}
      </div>

      {/* Scan Results View */}
      {scanResult && (
        <div className="space-y-6">
          <div className="card p-6 space-y-6">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-[var(--card-border)] pb-4">
              <div>
                <h3 className="text-lg font-bold">Privacy Findings</h3>
                <p className="text-xs text-[var(--muted)]">
                  Detector: {scanResult.detectorVersion} • Scanned: {new Date(scanResult.scannedAt).toLocaleTimeString()}
                </p>
              </div>

              <div className="flex items-center gap-3">
                <span className="text-sm font-semibold">
                  {scanResult.totalFindings === 0
                    ? "No sensitive patterns found"
                    : `${scanResult.totalFindings} sensitive item(s) detected`}
                </span>
                {scanResult.totalFindings > 0 && (
                  <span className="badge badge-brand">
                    {selectedCount} approved for redaction
                  </span>
                )}
              </div>
            </div>

            {/* Findings breakdown chips */}
            {scanResult.totalFindings > 0 && (
              <div className="flex flex-wrap gap-2">
                {Object.entries(scanResult.findingsByType).map(([type, count]) => {
                  if (count === 0) return null;
                  return (
                    <span
                      key={type}
                      className="px-3 py-1 rounded-lg text-xs font-semibold bg-[var(--background)] border border-[var(--card-border)] text-brand-400"
                    >
                      {type}: {count}
                    </span>
                  );
                })}
              </div>
            )}

            {/* Findings list */}
            {scanResult.findings.length === 0 ? (
              <div className="p-8 text-center text-sm text-[var(--muted)] flex flex-col items-center gap-2">
                <CheckCircle2 className="w-8 h-8 text-emerald-500" />
                <p>This document does not contain any detected SSNs, payment cards, API keys, or plaintext passwords.</p>
              </div>
            ) : (
              <div className="space-y-3">
                {scanResult.findings.map((finding) => (
                  <div
                    key={finding.id}
                    onClick={() => toggleFinding(finding.id)}
                    className={`p-4 rounded-xl border transition cursor-pointer flex flex-col sm:flex-row sm:items-center justify-between gap-3 ${
                      selectedFindings[finding.id]
                        ? "border-brand-500/50 bg-brand-500/5"
                        : "border-[var(--card-border)] opacity-60"
                    }`}
                  >
                    <div className="flex items-center gap-3">
                      <input
                        type="checkbox"
                        checked={Boolean(selectedFindings[finding.id])}
                        onChange={() => {}} // Handled by parent click
                        className="w-4 h-4 rounded text-brand-500 cursor-pointer"
                      />
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="px-2 py-0.5 rounded text-xs font-bold uppercase tracking-wider bg-red-500/10 text-red-400 border border-red-500/20">
                            {finding.entityType}
                          </span>
                          <span className="text-xs text-[var(--muted)]">
                            Confidence: {(finding.confidence * 100).toFixed(0)}%
                          </span>
                        </div>
                        <p className="mt-1 font-mono text-sm break-all">{finding.text}</p>
                      </div>
                    </div>

                    <div className="text-right sm:max-w-xs">
                      <span className="text-xs text-[var(--muted)] block">Proposed Replacement:</span>
                      <span className="font-mono text-xs text-emerald-400 break-all">
                        {finding.proposedReplacement}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            )}

            {scanResult.findings.length > 0 && (
              <div className="pt-4 border-t border-[var(--card-border)] flex flex-col sm:flex-row justify-between items-center gap-4">
                <p className="text-xs text-[var(--muted)]">
                  The original document will not be modified. A new, separate document with a protected access trail will be generated.
                </p>

                <button
                  onClick={handleRedact}
                  disabled={redacting || selectedCount === 0}
                  className="btn btn-primary flex items-center gap-2 whitespace-nowrap"
                >
                  {redacting ? (
                    <>
                      <Loader2 className="w-4 h-4 animate-spin" />
                      Generating redacted document...
                    </>
                  ) : (
                    <>
                      <Lock className="w-4 h-4" />
                      Generate Redacted Copy ({selectedCount})
                    </>
                  )}
                </button>
              </div>
            )}
          </div>

          {/* Success Banner */}
          {redactedDoc && (
            <div className="card p-6 border-l-4 border-l-emerald-500 space-y-4">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-full bg-emerald-500/10 flex items-center justify-center text-emerald-500">
                  <CheckCircle2 className="w-6 h-6" />
                </div>
                <div>
                  <h3 className="text-lg font-bold text-emerald-400">Redacted Copy Generated Successfully</h3>
                  <p className="text-xs text-[var(--muted)]">
                    Audit event recorded. Original file preserved. Protected asset is ready for sharing.
                  </p>
                </div>
              </div>

              <div className="p-4 rounded-xl bg-[var(--background)] border border-[var(--card-border)] flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-sm">
                <div>
                  <span className="font-semibold">{redactedDoc.title}</span>
                  <span className="text-xs text-[var(--muted)] block">{redactedDoc.file_name}</span>
                </div>

                <Link
                  href={`/dashboard/documents/${redactedDoc.id}`}
                  className="btn btn-secondary btn-sm flex items-center gap-1.5 self-start sm:self-auto"
                >
                  <Eye className="w-3.5 h-3.5" />
                  View Redacted Document
                </Link>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
