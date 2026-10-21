"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { useParams } from "next/navigation";
import { AlertTriangle, Download, FileText, Hash, Loader2, ShieldCheck, Clock } from "lucide-react";

interface ShareView {
  id: string;
  label: string | null;
  expires_at: string;
  access_count: number;
  max_access_count: number | null;
  allow_download: boolean;
  watermark_enabled: boolean;
  closed_after_view: boolean;
}

interface ShareDoc {
  id: string;
  title: string;
  file_name: string;
  mime_type: string;
  file_size: number;
  checksum: string;
  current_version: number;
}

interface SharePayload {
  document: ShareDoc;
  link: ShareView;
  preview: string | null;
  preview_truncated: boolean;
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function remaining(expiresAt: string): string {
  const ms = new Date(expiresAt).getTime() - Date.now();
  if (ms <= 0) return "expired";
  const minutes = Math.floor(ms / 60_000);
  if (minutes < 60) return `${minutes} min`;
  const hours = Math.floor(minutes / 60);
  if (hours < 48) return `${hours} h`;
  return `${Math.floor(hours / 24)} days`;
}

export default function SharePage() {
  const params = useParams<{ token: string }>();
  const token = params?.token ?? "";

  const [payload, setPayload] = useState<SharePayload | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`/api/public/share/${encodeURIComponent(token)}`, {
        cache: "no-store",
      });
      const data = await res.json().catch(() => null);
      if (!res.ok) {
        setPayload(null);
        setError(data?.error || `This link is not available (server returned ${res.status}).`);
        return;
      }
      setPayload(data.data as SharePayload);
    } catch {
      setError("Could not reach TrustVault. Check your connection and try again.");
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => {
    if (!token) return;
    let cancelled = false;

    async function load() {
      try {
        const res = await fetch(`/api/public/share/${encodeURIComponent(token)}`, {
          cache: "no-store",
        });
        const data = await res.json().catch(() => null);
        if (cancelled) return;
        if (!res.ok) {
          setPayload(null);
          setError(data?.error || `This link is not available (server returned ${res.status}).`);
          return;
        }
        setPayload(data.data as SharePayload);
      } catch {
        if (!cancelled) {
          setError("Could not reach TrustVault. Check your connection and try again.");
        }
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
  }, [token]);

  const downloadHref = useMemo(
    () => (payload?.link.allow_download ? `/api/public/share/${encodeURIComponent(token)}/download` : null),
    [payload?.link.allow_download, token]
  );

  const closed = Boolean(payload?.link.closed_after_view);

  return (
    <div className="min-h-screen bg-[var(--background)] text-[var(--foreground)] px-4 py-10">
      {/* React 19 hoists this into the document head: a disclosure page must not be
          archived or indexed by the first crawler that follows the link. */}
      <meta name="robots" content="noindex, nofollow, noarchive, nosnippet" />

      <div className="max-w-2xl mx-auto">
        <header className="flex items-center gap-3 mb-8">
          <div className="w-9 h-9 rounded-lg bg-brand-500/15 border border-brand-500/30 flex items-center justify-center">
            <ShieldCheck className="w-5 h-5 text-brand-500" />
          </div>
          <div>
            <div className="text-lg font-semibold leading-tight">TrustVault</div>
            <div className="text-xs text-[var(--muted)]">Secure document disclosure</div>
          </div>
        </header>

        {loading && (
          <div className="flex items-center gap-2 text-sm text-[var(--muted)] p-6">
            <Loader2 className="w-4 h-4 animate-spin" />
            Checking this link against the server…
          </div>
        )}

        {error && !loading && (
          <div
            role="alert"
            className="rounded-xl border border-red-500/30 bg-red-500/5 p-6 space-y-3"
          >
            <div className="flex items-center gap-2 text-red-500 font-medium">
              <AlertTriangle className="w-4 h-4" />
              This link cannot open the document
            </div>
            <p className="text-sm text-[var(--muted)]">{error}</p>
            <p className="text-xs text-[var(--muted)]">
              Access is decided on every request. If the owner revoked the link, or it passed its
              expiry, this page stops working from the next load onward.
            </p>
            <button
              onClick={load}
              className="text-sm px-3 py-1.5 rounded-lg border border-[var(--card-border)] hover:border-brand-500/40"
            >
              Re-check
            </button>
          </div>
        )}

        {payload && !loading && (
          <div className="space-y-4">
            <section className="rounded-xl border border-[var(--card-border)] bg-[var(--card)] p-6">
              <div className="flex items-start justify-between gap-4">
                <div className="min-w-0">
                  <h1 className="text-xl font-semibold truncate">{payload.document.title}</h1>
                  <p className="text-sm text-[var(--muted)] mt-1 truncate">
                    {payload.document.file_name} · {formatBytes(payload.document.file_size)} · v
                    {payload.document.current_version}
                  </p>
                </div>
                <FileText className="w-5 h-5 text-[var(--muted)] flex-shrink-0 mt-1" />
              </div>

              <dl className="grid grid-cols-2 gap-x-4 gap-y-3 mt-6 text-sm">
                <div>
                  <dt className="text-xs uppercase tracking-wide text-[var(--muted)]">Issued to</dt>
                  <dd className="mt-0.5 break-words">{payload.link.label || "unlabelled link"}</dd>
                </div>
                <div>
                  <dt className="text-xs uppercase tracking-wide text-[var(--muted)]">Expires</dt>
                  <dd className="mt-0.5 flex items-center gap-1.5">
                    <Clock className="w-3.5 h-3.5 text-[var(--muted)]" />
                    {new Date(payload.link.expires_at).toLocaleString()} ({remaining(payload.link.expires_at)})
                  </dd>
                </div>
                <div>
                  <dt className="text-xs uppercase tracking-wide text-[var(--muted)]">Views recorded</dt>
                  <dd className="mt-0.5">
                    {payload.link.access_count}
                    {payload.link.max_access_count !== null ? ` of ${payload.link.max_access_count}` : ""}
                  </dd>
                </div>
                <div>
                  <dt className="text-xs uppercase tracking-wide text-[var(--muted)]">File fingerprint</dt>
                  <dd className="mt-0.5 flex items-center gap-1.5 font-mono text-xs">
                    <Hash className="w-3.5 h-3.5 text-[var(--muted)]" />
                    {payload.document.checksum.slice(0, 16)}…
                  </dd>
                </div>
              </dl>

              {downloadHref && (
                <a
                  href={downloadHref}
                  className="mt-6 inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-brand-600 text-white text-sm font-medium hover:bg-brand-700 transition-colors"
                >
                  <Download className="w-4 h-4" />
                  Download file
                </a>
              )}

              {payload.link.watermark_enabled && (
                <p className="mt-4 text-xs text-[var(--muted)]">
                  Text files delivered through this link carry a forensic trace naming this link and
                  its view count. Binary formats are delivered unchanged — a trace cannot be injected
                  into a PDF or image without corrupting it, so for those the audit trail is the only
                  record.
                </p>
              )}
            </section>

            {payload.preview !== null && (
              <section className="rounded-xl border border-[var(--card-border)] bg-[var(--card)] overflow-hidden">
                <div className="px-4 py-2 border-b border-[var(--card-border)] text-xs uppercase tracking-wide text-[var(--muted)]">
                  Preview{payload.preview_truncated ? " (truncated)" : ""}
                </div>
                <pre className="p-4 text-xs leading-relaxed whitespace-pre-wrap break-words max-h-[32rem] overflow-auto font-mono">
                  {payload.preview}
                </pre>
              </section>
            )}

            {closed && (
              <div
                role="status"
                className="rounded-xl border border-amber-500/30 bg-amber-500/5 p-4 text-sm text-amber-600"
              >
                This was the last permitted view. The link is now closed and will not open again.
              </div>
            )}

            <p className="text-xs text-[var(--muted)]">
              Every view, refusal and revocation against this link is written to a hash-chained audit
              trail. Reloading re-asks the server; nothing here is cached.
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
