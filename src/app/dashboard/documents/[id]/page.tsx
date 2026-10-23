"use client";

import { useState, useEffect, useCallback } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import {
  ArrowLeft,
  FileText,
  Download,
  Trash2,
  Shield,
  Users,
  Clock,
  Activity,
  Plus,
  X,
  Loader2,
  CheckCircle2,
  AlertTriangle,
  Upload,
  Eye,
  Edit3,
  Calendar,
  Hash,
  HardDrive,
  User,
  Sparkles,
  Flame,
  ShieldCheck,
  Link2,
  Copy,
  Ban,
} from "lucide-react";

interface DocOwner {
  id: string;
  email: string;
  full_name: string | null;
}

interface Document {
  id: string;
  owner_id: string;
  title: string;
  description: string | null;
  category: string;
  storage_path: string;
  file_name: string;
  file_size: number;
  mime_type: string;
  checksum: string;
  current_version: number;
  is_deleted: boolean;
  created_at: string;
  updated_at: string;
  owner: DocOwner;
  access?: { is_owner: boolean; can_edit: boolean; can_delete: boolean };
}

interface Permission {
  id: string;
  document_id: string;
  user_id: string;
  permission_level: string;
  granted_by: string;
  granted_at: string;
  revoked_at: string | null;
  revoked_by: string | null;
  expires_at: string | null;
  max_access_count?: number | null;
  access_count?: number;
  watermark_enabled?: boolean;
  user: { id: string; email: string; full_name: string | null };
  grantor: { id: string; email: string; full_name: string | null };
}

interface Version {
  id: string;
  version_number: number;
  file_name: string;
  file_size: number;
  checksum: string;
  change_notes: string | null;
  created_at: string;
  uploader: { id: string; email: string; full_name: string | null };
}

interface AuditEvent {
  id: string;
  occurred_at: string;
  actor_email: string | null;
  action: string;
  result: string;
  details_jsonb: Record<string, unknown>;
}

interface ShareLinkView {
  id: string;
  document_id: string;
  label: string | null;
  created_at: string;
  expires_at: string;
  revoked_at: string | null;
  revoked_by: string | null;
  access_count: number;
  max_access_count: number | null;
  last_accessed_at: string | null;
  allow_download: boolean;
  watermark_enabled: boolean;
  is_active: boolean;
}

type Tab = "details" | "preview" | "permissions" | "share" | "versions" | "audit" | "ai_assistant";

export default function DocumentDetailPage({
  params: paramsPromise,
}: {
  params: Promise<{ id: string }>;
}) {
  const router = useRouter();
  const [params, setParams] = useState<{ id: string } | null>(null);
  const [doc, setDoc] = useState<Document | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [activeTab, setActiveTab] = useState<Tab>("details");

  // Permissions state
  const [permissions, setPermissions] = useState<Permission[]>([]);
  const [permLoading, setPermLoading] = useState(false);
  const [showGrantModal, setShowGrantModal] = useState(false);

  // Share link state
  const [shareLinks, setShareLinks] = useState<ShareLinkView[]>([]);
  const [shareLoading, setShareLoading] = useState(false);

  // Versions state
  const [versions, setVersions] = useState<Version[]>([]);
  const [verLoading, setVerLoading] = useState(false);

  // Audit state
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [auditLoading, setAuditLoading] = useState(false);

  // Download state
  const [downloading, setDownloading] = useState(false);
  const [me, setMe] = useState<{ id: string; role: string } | null>(null);

  // Delete state
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [deleting, setDeleting] = useState(false);

  useEffect(() => {
    paramsPromise.then(setParams);
    fetch("/api/auth/me")
      .then((r) => r.json())
      .then((data) => {
        if (data.success) setMe(data.data);
      })
      .catch(() => undefined);
  }, [paramsPromise]);

  const docId = params?.id;

  const fetchDocument = useCallback(async () => {
    if (!docId) return;
    setLoading(true);
    try {
      const res = await fetch(`/api/documents/${docId}`);
      const data = await res.json();
      if (data.success) {
        setDoc(data.data);
      } else {
        setError(data.error || "Failed to load document");
      }
    } catch {
      setError("Network error");
    } finally {
      setLoading(false);
    }
  }, [docId]);

  useEffect(() => {
    if (!docId) return;
    let cancelled = false;

    async function loadDoc() {
      try {
        const res = await fetch(`/api/documents/${docId}`);
        const data = await res.json();
        if (cancelled) return;
        if (data.success) {
          setDoc(data.data);
        } else {
          setError(data.error || "Failed to load document");
        }
      } catch {
        if (!cancelled) setError("Network error");
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    void loadDoc();
    return () => {
      cancelled = true;
    };
  }, [docId]);

  const fetchPermissions = useCallback(async () => {
    if (!docId) return;
    setPermLoading(true);
    try {
      const res = await fetch(`/api/documents/${docId}/permissions`);
      const data = await res.json();
      if (data.success) setPermissions(data.data);
    } catch {
      /* ignored */
    } finally {
      setPermLoading(false);
    }
  }, [docId]);

  const fetchShareLinks = useCallback(async () => {
    if (!docId) return;
    setShareLoading(true);
    try {
      const res = await fetch(`/api/documents/${docId}/share-links`);
      const data = await res.json();
      if (data.success) setShareLinks(data.data);
    } catch {
      /* ignored */
    } finally {
      setShareLoading(false);
    }
  }, [docId]);

  const fetchVersions = useCallback(async () => {
    if (!docId) return;
    setVerLoading(true);
    try {
      const res = await fetch(`/api/documents/${docId}/versions`);
      const data = await res.json();
      if (data.success) setVersions(data.data);
    } catch {
      /* ignored */
    } finally {
      setVerLoading(false);
    }
  }, [docId]);

  useEffect(() => {
    if (!docId) return;
    let cancelled = false;

    async function loadTabData() {
      if (activeTab === "permissions") {
        try {
          const res = await fetch(`/api/documents/${docId}/permissions`);
          const data = await res.json();
          if (data.success && !cancelled) setPermissions(data.data);
        } catch {
          /* ignored */
        } finally {
          if (!cancelled) setPermLoading(false);
        }
      } else if (activeTab === "share") {
        try {
          const res = await fetch(`/api/documents/${docId}/share-links`);
          const data = await res.json();
          if (data.success && !cancelled) setShareLinks(data.data);
        } catch {
          /* ignored */
        } finally {
          if (!cancelled) setShareLoading(false);
        }
      } else if (activeTab === "versions") {
        try {
          const res = await fetch(`/api/documents/${docId}/versions`);
          const data = await res.json();
          if (data.success && !cancelled) setVersions(data.data);
        } catch {
          /* ignored */
        } finally {
          if (!cancelled) setVerLoading(false);
        }
      } else if (activeTab === "audit") {
        try {
          const res = await fetch(`/api/documents/${docId}/audit`);
          const data = await res.json();
          if (data.success && !cancelled) setAuditEvents(data.data);
        } catch {
          /* ignored */
        } finally {
          if (!cancelled) setAuditLoading(false);
        }
      }
    }

    void loadTabData();
    return () => {
      cancelled = true;
    };
  }, [activeTab, docId]);

  async function handleDownload() {
    if (!docId) return;
    setDownloading(true);
    try {
      const res = await fetch(`/api/documents/${docId}/download`);
      if (!res.ok) {
        const data = await res.json().catch(() => ({ error: "Download failed" }));
        alert(data.error || "Download failed");
        return;
      }
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      const disposition = res.headers.get("Content-Disposition");
      const match = disposition?.match(/filename="([^"]+)"/);
      a.href = url;
      a.download = match?.[1] || doc?.file_name || "document";
      a.click();
      URL.revokeObjectURL(url);
    } catch {
      alert("Download failed");
    } finally {
      setDownloading(false);
    }
  }

  async function handleDelete() {
    if (!docId) return;
    setDeleting(true);
    try {
      const res = await fetch(`/api/documents/${docId}`, { method: "DELETE" });
      const data = await res.json();
      if (data.success) {
        router.push("/dashboard/documents");
      } else {
        alert(data.error || "Delete failed");
      }
    } catch {
      alert("Delete failed");
    } finally {
      setDeleting(false);
      setShowDeleteConfirm(false);
    }
  }

  async function handleRevokePermission(permId: string) {
    if (!docId) return;
    try {
      const res = await fetch(
        `/api/documents/${docId}/permissions/${permId}`,
        { method: "DELETE" }
      );
      const data = await res.json();
      if (data.success) {
        fetchPermissions();
      } else {
        alert(data.error || "Revoke failed");
      }
    } catch {
      alert("Revoke failed");
    }
  }

  if (loading) {
    return (
      <div className="max-w-5xl mx-auto animate-fade-in">
        <div className="skeleton h-8 w-64 mb-4" />
        <div className="card space-y-4">
          <div className="skeleton h-6 w-1/2" />
          <div className="skeleton h-4 w-full" />
          <div className="skeleton h-4 w-3/4" />
        </div>
      </div>
    );
  }

  if (error || !doc) {
    return (
      <div className="max-w-5xl mx-auto animate-fade-in">
        <div className="empty-state py-16">
          <AlertTriangle className="w-12 h-12 text-danger opacity-50" />
          <p className="text-lg font-medium mt-3">Access Denied</p>
          <p className="text-sm text-[var(--muted)] mt-1">
            {error || "Document not found or you don't have permission"}
          </p>
          <Link
            href="/dashboard/documents"
            className="btn btn-secondary btn-sm mt-4"
          >
            <ArrowLeft className="w-4 h-4" /> Back to Documents
          </Link>
        </div>
      </div>
    );
  }

  const isOwner = Boolean(doc.access?.is_owner || (me && me.id === doc.owner_id));
  const canDelete = Boolean(doc.access?.can_delete || isOwner);
  const canSeeAudit = isOwner || me?.role === "admin";

  const tabs: { key: Tab; label: string; icon: React.ReactNode }[] = [
    { key: "details", label: "Details", icon: <FileText className="w-4 h-4" /> },
    { key: "preview" as const, label: "Preview", icon: <Eye className="w-4 h-4" /> },
    ...(isOwner
      ? [
          {
            key: "permissions" as const,
            label: "Permissions",
            icon: <Shield className="w-4 h-4" />,
          },
          {
            key: "share" as const,
            label: "Share links",
            icon: <Link2 className="w-4 h-4" />,
          },
        ]
      : []),
    { key: "versions", label: "Versions", icon: <Clock className="w-4 h-4" /> },
    ...(canSeeAudit
      ? [
          {
            key: "audit" as const,
            label: "Audit Trail",
            icon: <Activity className="w-4 h-4" />,
          },
        ]
      : []),
    {
      key: "ai_assistant" as const,
      label: "AI Assistant",
      icon: <Sparkles className="w-4 h-4 text-brand-700" />,
    },
  ];

  return (
    <div className="max-w-5xl mx-auto animate-fade-in">
      {/* Back + Header */}
      <Link
        href="/dashboard/documents"
        className="inline-flex items-center gap-1 text-sm text-[var(--muted)] hover:text-[var(--foreground)] transition-colors mb-4"
      >
        <ArrowLeft className="w-4 h-4" /> Back to Documents
      </Link>

      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 mb-6">
        <div className="flex items-center gap-3">
          <div className="w-12 h-12 rounded-xl bg-brand-700/10 flex items-center justify-center flex-shrink-0">
            <FileText className="w-6 h-6 text-brand-700" />
          </div>
          <div>
            <h1 className="text-2xl font-bold">{doc.title}</h1>
            <div className="flex items-center gap-2 text-sm text-[var(--muted)]">
              <span className="badge badge-brand">{doc.category}</span>
              <span>v{doc.current_version}</span>
              <span>•</span>
              <span>{doc.file_name}</span>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setActiveTab("preview")}
            className="btn btn-secondary btn-sm"
            id="preview-document-btn"
          >
            <Eye className="w-4 h-4" />
            Preview
          </button>
          <button
            onClick={handleDownload}
            disabled={downloading}
            className="btn btn-primary btn-sm"
            id="download-document-btn"
          >
            {downloading ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <Download className="w-4 h-4" />
            )}
            Download
          </button>
          {canDelete && (
            <button
              onClick={() => setShowDeleteConfirm(true)}
              className="btn btn-danger btn-sm"
              id="delete-document-btn"
            >
              <Trash2 className="w-4 h-4" /> Delete
            </button>
          )}
        </div>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-[var(--card-border)] mb-6 overflow-x-auto">
        {tabs.map((tab) => (
          <button
            key={tab.key}
            onClick={() => setActiveTab(tab.key)}
            className={`flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-all whitespace-nowrap ${
              activeTab === tab.key
                ? "border-brand-700 text-brand-700 font-semibold"
                : "border-transparent text-[var(--muted)] hover:text-[var(--foreground)]"
            }`}
          >
            {tab.icon}
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      {activeTab === "details" && (
        <DetailsTab doc={doc} onRefresh={fetchDocument} />
      )}
      {activeTab === "preview" && (
        <PreviewTab doc={doc} />
      )}
      {activeTab === "permissions" && (
        <PermissionsTab
          permissions={permissions}
          loading={permLoading}
          isOwner={true}
          onRevoke={handleRevokePermission}
          onGrant={() => setShowGrantModal(true)}
        />
      )}
      {activeTab === "share" && (
        <ShareLinksTab
          links={shareLinks}
          loading={shareLoading}
          docId={doc.id}
          onRefresh={fetchShareLinks}
        />
      )}
      {activeTab === "versions" && (
        <VersionsTab versions={versions} loading={verLoading} docId={doc.id} onRefresh={fetchVersions} />
      )}
      {activeTab === "audit" && (
        <AuditTab events={auditEvents} loading={auditLoading} docId={doc.id} />
      )}
      {activeTab === "ai_assistant" && (
        <AIAssistantTab docId={doc.id} docTitle={doc.title} />
      )}

      {/* Grant Permission Modal */}
      {showGrantModal && (
        <GrantPermissionModal
          docId={doc.id}
          docTitle={doc.title}
          docCategory={doc.category}
          onClose={() => setShowGrantModal(false)}
          onSuccess={() => {
            setShowGrantModal(false);
            fetchPermissions();
          }}
        />
      )}

      {/* Delete Confirmation Modal */}
      {showDeleteConfirm && (
        <div className="modal-overlay" onClick={() => setShowDeleteConfirm(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <h3 className="text-lg font-bold flex items-center gap-2 mb-3">
              <AlertTriangle className="w-5 h-5 text-danger" />
              Delete Document
            </h3>
            <p className="text-sm text-[var(--muted)] mb-4">
              Are you sure you want to delete &quot;{doc.title}&quot;? This is a
              soft delete and can be restored by an admin.
            </p>
            <div className="flex justify-end gap-2">
              <button
                onClick={() => setShowDeleteConfirm(false)}
                className="btn btn-secondary btn-sm"
              >
                Cancel
              </button>
              <button
                onClick={handleDelete}
                disabled={deleting}
                className="btn btn-danger btn-sm"
              >
                {deleting ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  <Trash2 className="w-4 h-4" />
                )}
                Delete
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

/* === Tab Components === */

function PreviewTab({ doc }: { doc: Document }) {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [csvData, setCsvData] = useState<{ headers: string[]; rows: string[][] } | null>(null);
  const [textContent, setTextContent] = useState<string | null>(null);

  const isPdf = doc.mime_type === "application/pdf" || doc.file_name.toLowerCase().endsWith(".pdf");
  const isCsv = doc.mime_type === "text/csv" || doc.file_name.toLowerCase().endsWith(".csv");
  const isText = doc.mime_type.startsWith("text/") || doc.file_name.toLowerCase().endsWith(".txt") || doc.file_name.toLowerCase().endsWith(".json");
  const isImage = doc.mime_type.startsWith("image/");

  useEffect(() => {
    let cancelled = false;
    async function loadContent() {
      if (!isCsv && !isText) {
        setLoading(false);
        return;
      }
      setLoading(true);
      setError(null);
      try {
        const res = await fetch(`/api/documents/${doc.id}/preview`);
        if (!res.ok) {
          throw new Error("Unable to load preview");
        }
        const text = await res.text();
        if (cancelled) return;
        if (isCsv) {
          const lines = text.trim().split(/\r?\n/).filter(Boolean);
          if (lines.length > 0) {
            const headers = lines[0].split(",").map((h) => h.trim().replace(/^"|"$/g, ""));
            const rows = lines.slice(1).map((l) =>
              l.split(",").map((cell) => cell.trim().replace(/^"|"$/g, ""))
            );
            setCsvData({ headers, rows });
          }
        } else {
          setTextContent(text);
        }
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : "Failed to load document preview";
        if (!cancelled) setError(msg);
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    void loadContent();
    return () => {
      cancelled = true;
    };
  }, [doc.id, isCsv, isText]);

  return (
    <div className="space-y-4 animate-fade-in">
      <div className="card">
        <div className="flex items-center justify-between pb-4 border-b border-[var(--card-border)] mb-4">
          <div className="flex items-center gap-2">
            <Eye className="w-5 h-5 text-brand-700" />
            <h3 className="text-lg font-semibold">Secure In-App Preview</h3>
            <span className="badge badge-brand text-[10px]">Zero-Leak Streaming</span>
          </div>
          <div className="flex items-center gap-2">
            <a
              href={`/api/documents/${doc.id}/preview`}
              target="_blank"
              rel="noopener noreferrer"
              className="btn btn-secondary btn-sm"
              id="open-in-new-window-link"
            >
              Open in New Window
            </a>
          </div>
        </div>

        {isPdf && (
          <div className="relative rounded-lg overflow-hidden border border-[var(--card-border)] bg-surface-200">
            <iframe
              src={`/api/documents/${doc.id}/preview#toolbar=1`}
              className="w-full h-[680px] rounded-lg"
              title={doc.title}
            />
          </div>
        )}

        {isCsv && (
          <div className="space-y-3">
            {loading ? (
              <div className="flex items-center justify-center py-12">
                <Loader2 className="w-6 h-6 animate-spin text-brand-700" />
              </div>
            ) : error ? (
              <div className="p-4 bg-danger/10 text-danger rounded-lg text-sm">{error}</div>
            ) : csvData ? (
              <div className="overflow-x-auto rounded-lg border border-[var(--card-border)]">
                <table className="w-full text-left text-xs">
                  <thead className="bg-surface-200 border-b border-[var(--card-border)]">
                    <tr>
                      {csvData.headers.map((h, i) => (
                        <th key={i} className="p-3 font-semibold text-[var(--foreground)]">
                          {h}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[var(--card-border)] font-mono">
                    {csvData.rows.map((row, rIdx) => (
                      <tr key={rIdx} className="hover:bg-surface-100 transition-colors">
                        {row.map((cell, cIdx) => (
                          <td key={cIdx} className="p-3">
                            {cell}
                          </td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <p className="text-sm text-[var(--muted)]">No data found in CSV</p>
            )}
          </div>
        )}

        {isText && (
          <div>
            {loading ? (
              <div className="flex items-center justify-center py-12">
                <Loader2 className="w-6 h-6 animate-spin text-brand-700" />
              </div>
            ) : (
              <pre className="p-4 rounded-lg bg-surface-200 border border-[var(--card-border)] text-xs font-mono overflow-x-auto whitespace-pre-wrap max-h-[600px]">
                {textContent}
              </pre>
            )}
          </div>
        )}

        {isImage && (
          <div className="flex justify-center p-4 bg-surface-200 rounded-lg border border-[var(--card-border)]">
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img
              src={`/api/documents/${doc.id}/preview`}
              alt={doc.title}
              className="max-h-[600px] object-contain rounded"
            />
          </div>
        )}

        {!isPdf && !isCsv && !isText && !isImage && (
          <div className="py-12 text-center text-sm text-[var(--muted)]">
            <FileText className="w-12 h-12 mx-auto mb-3 opacity-30" />
            <p>
              Direct preview is not available for format: <code>{doc.mime_type}</code>
            </p>
            <p className="mt-1">
              Please use the Download button to view this file in its native application.
            </p>
          </div>
        )}
      </div>
    </div>
  );
}

function DetailsTab({
  doc,
  onRefresh,
}: {
  doc: Document;
  onRefresh: () => void;
}) {
  const [editing, setEditing] = useState(false);
  const [title, setTitle] = useState(doc.title);
  const [description, setDescription] = useState(doc.description || "");
  const [category, setCategory] = useState(doc.category);
  const [saving, setSaving] = useState(false);

  async function handleSave() {
    setSaving(true);
    try {
      const res = await fetch(`/api/documents/${doc.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ title, description, category }),
      });
      const data = await res.json();
      if (data.success) {
        setEditing(false);
        onRefresh();
      } else {
        alert(data.error || "Update failed");
      }
    } catch {
      alert("Update failed");
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="card space-y-6 animate-fade-in">
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-semibold">Document Information</h3>
        {!editing && (
          <button
            onClick={() => setEditing(true)}
            className="btn btn-secondary btn-sm"
          >
            <Edit3 className="w-4 h-4" /> Edit
          </button>
        )}
      </div>

      {editing ? (
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium mb-1 text-[var(--muted)]">
              Title
            </label>
            <input
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              className="input"
            />
          </div>
          <div>
            <label className="block text-sm font-medium mb-1 text-[var(--muted)]">
              Description
            </label>
            <textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              className="input min-h-[80px]"
            />
          </div>
          <div>
            <label className="block text-sm font-medium mb-1 text-[var(--muted)]">
              Category
            </label>
            <select
              value={category}
              onChange={(e) => setCategory(e.target.value)}
              className="input"
            >
              {["general", "legal", "financial", "technical", "hr", "marketing", "other"].map(
                (c) => (
                  <option key={c} value={c}>
                    {c.charAt(0).toUpperCase() + c.slice(1)}
                  </option>
                )
              )}
            </select>
          </div>
          <div className="flex gap-2">
            <button
              onClick={handleSave}
              disabled={saving}
              className="btn btn-primary btn-sm"
            >
              {saving ? <Loader2 className="w-4 h-4 animate-spin" /> : null}
              Save Changes
            </button>
            <button
              onClick={() => {
                setEditing(false);
                setTitle(doc.title);
                setDescription(doc.description || "");
                setCategory(doc.category);
              }}
              className="btn btn-secondary btn-sm"
            >
              Cancel
            </button>
          </div>
        </div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <InfoRow
            icon={<FileText className="w-4 h-4" />}
            label="File Name"
            value={doc.file_name}
          />
          <InfoRow
            icon={<HardDrive className="w-4 h-4" />}
            label="File Size"
            value={formatFileSize(doc.file_size)}
          />
          <InfoRow
            icon={<Hash className="w-4 h-4" />}
            label="Checksum (SHA-256)"
            value={doc.checksum.substring(0, 16) + "..."}
            mono
          />
          <InfoRow
            icon={<User className="w-4 h-4" />}
            label="Owner"
            value={doc.owner?.full_name || doc.owner?.email}
          />
          <InfoRow
            icon={<Calendar className="w-4 h-4" />}
            label="Created"
            value={new Date(doc.created_at).toLocaleString()}
          />
          <InfoRow
            icon={<Clock className="w-4 h-4" />}
            label="Last Updated"
            value={new Date(doc.updated_at).toLocaleString()}
          />
          {doc.description && (
            <div className="sm:col-span-2">
              <p className="text-xs text-[var(--muted)] mb-1">Description</p>
              <p className="text-sm">{doc.description}</p>
            </div>
          )}

          {/* Forensic Disclosure Watermark Preview Box */}
          <div className="sm:col-span-2 mt-4 relative overflow-hidden p-4 rounded-xl border border-brand-700/25 bg-surface-200">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-brand-700" />
                <span className="text-xs font-bold uppercase tracking-wider text-brand-700">
                  Forensic Watermark Protection Active
                </span>
              </div>
              <span className="badge badge-brand text-[10px]">Tamper-Proof Disclosure</span>
            </div>

            <div className="relative p-4 rounded-lg bg-[var(--card-bg)] border border-[var(--card-border)] overflow-hidden">
              <div className="absolute inset-0 pointer-events-none select-none flex items-center justify-center opacity-10 rotate-[-15deg] text-xs font-mono font-bold uppercase tracking-widest text-center whitespace-pre-wrap leading-loose">
                {`TRUSTVAULT SECURE DISCLOSURE • ${doc.checksum.slice(0, 16)} • RECIPIENT TRACED`}
              </div>

              <div className="relative z-10 font-mono text-xs text-[var(--foreground)] opacity-90 space-y-1.5">
                <div className="text-[11px] text-[var(--muted)] border-b border-[var(--card-border)] pb-2 flex items-center justify-between">
                  <span>Container: {doc.file_name}</span>
                  <span>SHA-256: {doc.checksum.slice(0, 12)}...</span>
                </div>
                <p className="text-[11px] text-brand-800">
                  🛡️ Forensic Attribution: Download stream automatically stamps recipient identity, UTC timestamp, and leak-tracing cryptographic fingerprint.
                </p>
                <p className="text-[11px] text-[var(--muted)]">
                  Cryptographic Integrity Root: <span className="font-mono text-brand-700">{doc.checksum}</span>
                </p>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function InfoRow({
  icon,
  label,
  value,
  mono,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div>
      <p className="text-xs text-[var(--muted)] flex items-center gap-1 mb-1">
        {icon} {label}
      </p>
      <p className={`text-sm ${mono ? "font-mono" : ""}`}>{value}</p>
    </div>
  );
}

function PermissionsTab({
  permissions,
  loading,
  isOwner,
  onRevoke,
  onGrant,
}: {
  permissions: Permission[];
  loading: boolean;
  isOwner: boolean;
  onRevoke: (id: string) => void;
  onGrant: () => void;
}) {
  const activePermissions = permissions.filter((p) => !p.revoked_at);
  const revokedPermissions = permissions.filter((p) => p.revoked_at);

  if (loading) {
    return (
      <div className="card space-y-3">
        <div className="skeleton h-6 w-48" />
        <div className="skeleton h-12 w-full" />
        <div className="skeleton h-12 w-full" />
      </div>
    );
  }

  return (
    <div className="space-y-4 animate-fade-in">
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold flex items-center gap-2">
            <Shield className="w-5 h-5 text-brand-700" />
            Active Permissions ({activePermissions.length})
          </h3>
          {isOwner && (
            <button onClick={onGrant} className="btn btn-primary btn-sm" id="grant-permission-btn">
              <Plus className="w-4 h-4" /> Grant Access
            </button>
          )}
        </div>

        {activePermissions.length > 0 ? (
          <div className="space-y-2">
            {activePermissions.map((perm) => (
              <div
                key={perm.id}
                className="flex items-center justify-between p-3 rounded-lg bg-[var(--input-bg)]"
              >
                <div className="flex items-center gap-3">
                  <div className="w-8 h-8 rounded-full bg-brand-700/10 flex items-center justify-center text-brand-700 text-xs font-bold">
                    {perm.user?.full_name?.[0] || perm.user?.email?.[0]}
                  </div>
                  <div>
                    <p className="text-sm font-medium">
                      {perm.user?.full_name || perm.user?.email}
                    </p>
                    <p className="text-xs text-[var(--muted)]">
                      {perm.user?.email}
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-2 flex-wrap">
                  <span
                    className={`badge ${
                      perm.permission_level === "edit"
                        ? "badge-warning"
                        : "badge-success"
                    }`}
                  >
                    {perm.permission_level === "edit" ? (
                      <Edit3 className="w-3 h-3 mr-1" />
                    ) : (
                      <Eye className="w-3 h-3 mr-1" />
                    )}
                    {perm.permission_level}
                  </span>

                  {perm.max_access_count === 1 && (
                    <span className="badge badge-warning text-[10px] inline-flex items-center gap-1 font-medium">
                      <Flame className="w-3 h-3 text-amber-600" />
                      Single-Use ({perm.access_count || 0}/1)
                    </span>
                  )}

                  {Boolean(perm.max_access_count && perm.max_access_count > 1) && (
                    <span className="badge badge-neutral text-[10px]">
                      Access: {perm.access_count || 0}/{perm.max_access_count}
                    </span>
                  )}

                  {perm.watermark_enabled !== false && (
                    <span className="badge badge-brand text-[10px] inline-flex items-center gap-1">
                      <ShieldCheck className="w-3 h-3 text-brand-700" />
                      Watermarked
                    </span>
                  )}

                  {perm.expires_at && (
                    <span className="text-xs text-[var(--muted)]">
                      Expires {new Date(perm.expires_at).toLocaleDateString()}
                    </span>
                  )}
                  {isOwner && (
                    <button
                      onClick={() => onRevoke(perm.id)}
                      className="btn btn-ghost btn-sm text-danger hover:bg-danger/10"
                    >
                      <X className="w-4 h-4" />
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="empty-state py-6">
            <Users className="w-8 h-8 text-[var(--muted)] opacity-30" />
            <p className="text-sm text-[var(--muted)] mt-2">
              No active permissions. Only the owner can access this document.
            </p>
          </div>
        )}
      </div>

      {revokedPermissions.length > 0 && (
        <div className="card opacity-75">
          <h3 className="text-sm font-semibold text-[var(--muted)] mb-3">
            Revoked Permissions ({revokedPermissions.length})
          </h3>
          <div className="space-y-2">
            {revokedPermissions.map((perm) => (
              <div
                key={perm.id}
                className="flex items-center justify-between p-2 rounded-lg text-sm"
              >
                <span className="text-[var(--muted)]">
                  {perm.user?.full_name || perm.user?.email} —{" "}
                  {perm.permission_level}
                </span>
                <span className="badge badge-danger">Revoked</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function toLocalInputValue(date: Date): string {
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(
    date.getHours()
  )}:${pad(date.getMinutes())}`;
}

function ShareLinksTab({
  links,
  loading,
  docId,
  onRefresh,
}: {
  links: ShareLinkView[];
  loading: boolean;
  docId: string;
  onRefresh: () => void;
}) {
  const [label, setLabel] = useState("");
  const [expiresAt, setExpiresAt] = useState(() => {
    const target = new Date();
    target.setDate(target.getDate() + 7);
    return toLocalInputValue(target);
  });
  const [maxViews, setMaxViews] = useState("");
  const [allowDownload, setAllowDownload] = useState(true);
  const [watermark, setWatermark] = useState(true);
  const [creating, setCreating] = useState(false);
  const [formError, setFormError] = useState("");
  const [issued, setIssued] = useState<{ id: string; url: string } | null>(null);
  const [notice, setNotice] = useState("");
  const [revokingId, setRevokingId] = useState<string | null>(null);

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    setFormError("");
    setNotice("");

    const expiryMs = Date.parse(expiresAt);
    if (!Number.isFinite(expiryMs)) {
      setFormError("Choose when this link should stop working.");
      return;
    }
    if (expiryMs <= Date.now()) {
      setFormError("The expiry must be in the future.");
      return;
    }

    setCreating(true);
    try {
      const res = await fetch(`/api/documents/${docId}/share-links`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          label: label.trim() || null,
          expires_at: new Date(expiryMs).toISOString(),
          max_views: maxViews.trim() ? Number(maxViews) : null,
          allow_download: allowDownload,
          watermark_enabled: watermark,
        }),
      });
      const data = await res.json().catch(() => null);
      if (!res.ok || !data?.success) {
        setFormError(data?.error || `Could not create the link (server returned ${res.status}).`);
        return;
      }
      setIssued({ id: data.data.link.id, url: data.data.url });
      setLabel("");
      setMaxViews("");
      onRefresh();
    } catch {
      setFormError("Network error — the link was not created.");
    } finally {
      setCreating(false);
    }
  }

  async function handleRevoke(id: string) {
    setRevokingId(id);
    setNotice("");
    try {
      const res = await fetch(`/api/documents/${docId}/share-links/${id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "revoke" }),
      });
      const data = await res.json().catch(() => null);
      if (!res.ok || !data?.success) {
        setNotice(data?.error || "Revocation failed.");
      } else {
        setNotice("Link revoked. It stops working on the next request.");
      }
      onRefresh();
    } catch {
      setNotice("Network error — the link was not revoked.");
    } finally {
      setRevokingId(null);
    }
  }

  async function copyIssued() {
    if (!issued) return;
    try {
      await navigator.clipboard.writeText(issued.url);
      setNotice("Link copied.");
    } catch {
      setNotice("Your browser blocked the clipboard. Select the address and copy it manually.");
    }
  }

  return (
    <div className="space-y-6">
      <form onSubmit={handleCreate} className="card p-6 space-y-4">
        <div>
          <h2 className="text-sm font-semibold uppercase tracking-wide text-[var(--muted)]">
            Issue a share link
          </h2>
          <p className="text-xs text-[var(--muted)] mt-1">
            A link opens this document for one anonymous reader until it expires or you revoke it. It
            never grants edit rights — those still need a named account.
          </p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <label htmlFor="share-label" className="block text-sm font-medium mb-1">
              Issued to <span className="text-[var(--muted)] font-normal">(optional)</span>
            </label>
            <input
              id="share-label"
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              maxLength={200}
              placeholder="e.g. external auditor"
              className="input"
            />
          </div>
          <div>
            <label htmlFor="share-expiry" className="block text-sm font-medium mb-1">
              Expires
            </label>
            <input
              id="share-expiry"
              type="datetime-local"
              value={expiresAt}
              onChange={(e) => setExpiresAt(e.target.value)}
              required
              className="input"
            />
          </div>
          <div>
            <label htmlFor="share-views" className="block text-sm font-medium mb-1">
              Maximum views{" "}
              <span className="text-[var(--muted)] font-normal">(blank = unlimited)</span>
            </label>
            <input
              id="share-views"
              type="number"
              min={1}
              max={1000}
              value={maxViews}
              onChange={(e) => setMaxViews(e.target.value)}
              placeholder="unlimited"
              className="input"
            />
          </div>
          <div className="flex flex-col justify-end gap-2 pb-1">
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={allowDownload}
                onChange={(e) => setAllowDownload(e.target.checked)}
              />
              Allow download
            </label>
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={watermark}
                onChange={(e) => setWatermark(e.target.checked)}
              />
              Watermark text files
            </label>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button type="submit" disabled={creating} className="btn btn-primary btn-sm">
            {creating ? <Loader2 className="w-4 h-4 animate-spin" /> : <Link2 className="w-4 h-4" />}
            Create link
          </button>
          {formError && (
            <span role="alert" className="text-sm text-danger">
              {formError}
            </span>
          )}
        </div>

        {issued && (
          <div className="rounded-lg border border-brand-700/30 bg-brand-700/5 p-4 space-y-2">
            <div className="text-sm font-medium">This URL is shown once and cannot be recovered.</div>
            <div className="flex items-center gap-2">
              <code className="flex-1 min-w-0 break-all text-xs bg-[var(--background)] rounded px-2 py-1">
                {issued.url}
              </code>
              <button
                type="button"
                onClick={copyIssued}
                className="btn btn-secondary btn-sm flex-shrink-0"
              >
                <Copy className="w-4 h-4" />
                Copy
              </button>
            </div>
            <p className="text-xs text-[var(--muted)]">
              TrustVault keeps only a SHA-256 digest of the token, so the link exists only in your
              message to the recipient. Link id {issued.id}.
            </p>
          </div>
        )}
      </form>

      <div className="card p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-sm font-semibold uppercase tracking-wide text-[var(--muted)]">
            Issued links ({links.length})
          </h2>
          <button type="button" onClick={onRefresh} className="btn btn-secondary btn-sm">
            Refresh
          </button>
        </div>

        {notice && (
          <div role="status" className="text-sm mb-3 text-[var(--muted)]">
            {notice}
          </div>
        )}

        {loading && <div className="skeleton h-16 w-full" />}

        {!loading && links.length === 0 && (
          <p className="text-sm text-[var(--muted)]">
            No links issued. Nobody outside the permission list can open this document.
          </p>
        )}

        {!loading && links.length > 0 && (
          <ul className="space-y-3">
            {links.map((link) => {
              const expired = !link.is_active && !link.revoked_at;
              const status = link.revoked_at ? "revoked" : expired ? "expired" : "active";
              return (
                <li
                  key={link.id}
                  className="rounded-lg border border-[var(--card-border)] p-4 space-y-2"
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="text-sm font-medium truncate">
                        {link.label || <span className="text-[var(--muted)]">unlabelled</span>}
                      </div>
                      <div className="text-xs text-[var(--muted)] mt-0.5 font-mono truncate">
                        {link.id}
                      </div>
                    </div>
                    <span
                      className={`badge text-xs flex-shrink-0 ${
                        status === "active"
                          ? "badge-brand"
                          : status === "revoked"
                            ? "badge-danger"
                            : "badge-neutral"
                      }`}
                    >
                      {status}
                    </span>
                  </div>

                  <div className="flex flex-wrap gap-x-5 gap-y-1 text-xs text-[var(--muted)]">
                    <span>expires {new Date(link.expires_at).toLocaleString()}</span>
                    <span>
                      views {link.access_count}
                      {link.max_access_count !== null ? `/${link.max_access_count}` : ""}
                    </span>
                    <span>
                      last read{" "}
                      {link.last_accessed_at
                        ? new Date(link.last_accessed_at).toLocaleString()
                        : "never"}
                    </span>
                    <span>{link.allow_download ? "download allowed" : "view only"}</span>
                    {link.revoked_at && (
                      <span>
                        revoked {new Date(link.revoked_at).toLocaleString()} by{" "}
                        {link.revoked_by || "unknown"}
                      </span>
                    )}
                  </div>

                  {status === "active" && (
                    <button
                      type="button"
                      onClick={() => handleRevoke(link.id)}
                      disabled={revokingId === link.id}
                      className="btn btn-danger btn-sm"
                    >
                      {revokingId === link.id ? (
                        <Loader2 className="w-4 h-4 animate-spin" />
                      ) : (
                        <Ban className="w-4 h-4" />
                      )}
                      Revoke now
                    </button>
                  )}
                </li>
              );
            })}
          </ul>
        )}
      </div>
    </div>
  );
}

function VersionsTab({
  versions,
  loading,
  docId,
  onRefresh,
}: {
  versions: Version[];
  loading: boolean;
  docId: string;
  onRefresh: () => void;
}) {
  const [showUpload, setShowUpload] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [file, setFile] = useState<File | null>(null);
  const [changeNotes, setChangeNotes] = useState("");

  async function handleUploadVersion() {
    if (!file) return;
    setUploading(true);
    const formData = new FormData();
    formData.append("file", file);
    if (changeNotes) formData.append("change_notes", changeNotes);

    try {
      const res = await fetch(`/api/documents/${docId}/versions`, {
        method: "POST",
        body: formData,
      });
      const data = await res.json();
      if (data.success) {
        setShowUpload(false);
        setFile(null);
        setChangeNotes("");
        onRefresh();
      } else {
        alert(data.error || "Upload failed");
      }
    } catch {
      alert("Upload failed");
    } finally {
      setUploading(false);
    }
  }

  if (loading) {
    return (
      <div className="card space-y-3">
        <div className="skeleton h-6 w-48" />
        <div className="skeleton h-16 w-full" />
        <div className="skeleton h-16 w-full" />
      </div>
    );
  }

  return (
    <div className="space-y-4 animate-fade-in">
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold flex items-center gap-2">
            <Clock className="w-5 h-5 text-brand-700" />
            Version History ({versions.length})
          </h3>
          <button
            onClick={() => setShowUpload(!showUpload)}
            className="btn btn-primary btn-sm"
          >
            <Upload className="w-4 h-4" /> New Version
          </button>
        </div>

        {showUpload && (
          <div className="p-4 rounded-lg bg-[var(--input-bg)] mb-4 space-y-3 animate-fade-in">
            <input
              type="file"
              onChange={(e) => setFile(e.target.files?.[0] || null)}
              className="input text-sm"
            />
            <input
              type="text"
              value={changeNotes}
              onChange={(e) => setChangeNotes(e.target.value)}
              placeholder="Change notes (optional)"
              className="input"
            />
            <div className="flex gap-2">
              <button
                onClick={handleUploadVersion}
                disabled={!file || uploading}
                className="btn btn-primary btn-sm"
              >
                {uploading ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : null}
                Upload
              </button>
              <button
                onClick={() => setShowUpload(false)}
                className="btn btn-secondary btn-sm"
              >
                Cancel
              </button>
            </div>
          </div>
        )}

        {versions.length > 0 ? (
          <div className="space-y-2">
            {versions.map((ver, i) => (
              <div
                key={ver.id}
                className={`flex items-center justify-between p-3 rounded-lg ${
                  i === 0 ? "bg-brand-500/5 border border-brand-500/20" : "bg-[var(--input-bg)]"
                }`}
              >
                <div className="flex items-center gap-3">
                  <div
                    className={`w-8 h-8 rounded-lg flex items-center justify-center text-xs font-bold ${
                      i === 0
                        ? "bg-brand-500/20 text-brand-400"
                        : "bg-[var(--card-border)] text-[var(--muted)]"
                    }`}
                  >
                    v{ver.version_number}
                  </div>
                  <div>
                    <p className="text-sm font-medium">
                      {ver.file_name}
                      {i === 0 && (
                        <span className="badge badge-brand ml-2 text-[10px]">
                          Current
                        </span>
                      )}
                    </p>
                    <p className="text-xs text-[var(--muted)]">
                      {ver.uploader?.full_name || ver.uploader?.email} •{" "}
                      {new Date(ver.created_at).toLocaleString()} •{" "}
                      {formatFileSize(ver.file_size)}
                    </p>
                    {ver.change_notes && (
                      <p className="text-xs text-[var(--muted)] mt-1 italic">
                        &quot;{ver.change_notes}&quot;
                      </p>
                    )}
                  </div>
                </div>
                <code className="text-[10px] text-[var(--muted)] font-mono hidden sm:block">
                  {ver.checksum.substring(0, 12)}...
                </code>
              </div>
            ))}
          </div>
        ) : (
          <div className="empty-state py-6">
            <Clock className="w-8 h-8 text-[var(--muted)] opacity-30" />
            <p className="text-sm text-[var(--muted)] mt-2">
              No version history available
            </p>
          </div>
        )}
      </div>
    </div>
  );
}

function AuditTab({
  events,
  loading,
  docId,
}: {
  events: AuditEvent[];
  loading: boolean;
  docId: string;
}) {
  if (loading) {
    return (
      <div className="card space-y-3">
        <div className="skeleton h-6 w-48" />
        <div className="skeleton h-10 w-full" />
        <div className="skeleton h-10 w-full" />
      </div>
    );
  }

  return (
    <div className="card animate-fade-in">
      <div className="flex items-center justify-between mb-4 flex-wrap gap-2">
        <h3 className="text-lg font-semibold flex items-center gap-2">
          <Activity className="w-5 h-5 text-brand-700" />
          Audit Trail ({events.length} events)
        </h3>
        <a
          href={`/api/documents/${docId}/certificate?download=true`}
          download
          className="btn btn-secondary btn-sm flex items-center gap-1.5 text-xs font-semibold"
          id="export-compliance-certificate-btn"
        >
          <ShieldCheck className="w-4 h-4 text-brand-700" />
          Export Compliance Certificate
        </a>
      </div>

      {events.length > 0 ? (
        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Actor</th>
                <th>Action</th>
                <th>Result</th>
              </tr>
            </thead>
            <tbody>
              {events.map((event) => (
                <tr key={event.id}>
                  <td className="text-xs whitespace-nowrap">
                    {new Date(event.occurred_at).toLocaleString()}
                  </td>
                  <td className="text-xs">{event.actor_email || "System"}</td>
                  <td>
                    <span className="badge badge-neutral">
                      {formatAction(event.action)}
                    </span>
                    {Boolean(event.details_jsonb?.ai_suggested) && (
                      <span
                        className="badge badge-brand ml-1.5 text-[10px] inline-flex items-center gap-1"
                        title={String(event.details_jsonb?.ai_rationale || "AI recommendation confirmed by human owner")}
                      >
                        <Sparkles className="w-2.5 h-2.5" /> AI Assisted
                      </span>
                    )}
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
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="empty-state py-6">
          <Activity className="w-8 h-8 text-[var(--muted)] opacity-30" />
          <p className="text-sm text-[var(--muted)] mt-2">
            No audit events for this document
          </p>
        </div>
      )}
    </div>
  );
}

/* === Grant Permission Modal === */

function GrantPermissionModal({
  docId,
  docTitle,
  docCategory,
  onClose,
  onSuccess,
}: {
  docId: string;
  docTitle: string;
  docCategory: string;
  onClose: () => void;
  onSuccess: () => void;
}) {
  const [email, setEmail] = useState("");
  const [level, setLevel] = useState<"read" | "edit">("read");
  const [expiresAt, setExpiresAt] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [burnAfterRead, setBurnAfterRead] = useState(false);
  const [maxAccessCount, setMaxAccessCount] = useState<number | "">("");
  const [watermarkEnabled, setWatermarkEnabled] = useState(true);
  const [aiSuggested, setAiSuggested] = useState(false);
  const [aiRationale, setAiRationale] = useState("");
  const [aiExpanded, setAiExpanded] = useState(false);

  function generateAiRecommendation() {
    const isHighSensitivity = ["financial", "legal", "hr"].includes(docCategory?.toLowerCase() || "");
    const days = isHighSensitivity ? 14 : 30;
    const future = new Date(Date.now() + days * 86400000);
    const pad = (n: number) => n.toString().padStart(2, "0");
    const formattedDate = `${future.getFullYear()}-${pad(future.getMonth() + 1)}-${pad(future.getDate())}T${pad(future.getHours())}:${pad(future.getMinutes())}`;

    const rationale = isHighSensitivity
      ? `Least Privilege Policy: "${docCategory}" classification mandates time-bound read access (${days} days). Edit permission restricted to authors.`
      : `Standard Organization Policy: Read-only access recommended with a ${days}-day expiration window.`;

    setLevel("read");
    setExpiresAt(formattedDate);
    if (!email) {
      setEmail("viewer@example.com");
    }
    setAiSuggested(true);
    setAiRationale(rationale);
    setAiExpanded(true);
  }

  async function handleGrant(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError("");

    try {
      const res = await fetch(`/api/documents/${docId}/permissions`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          user_email: email,
          permission_level: level,
          expires_at: expiresAt ? new Date(expiresAt).toISOString() : undefined,
          burn_after_read: burnAfterRead,
          max_access_count: burnAfterRead ? 1 : (typeof maxAccessCount === "number" ? maxAccessCount : undefined),
          watermark_enabled: watermarkEnabled,
          ai_suggested: aiSuggested,
          ai_rationale: aiRationale || undefined,
        }),
      });
      const data = await res.json();
      if (data.success) {
        onSuccess();
      } else {
        setError(data.error || "Failed to grant permission");
      }
    } catch {
      setError("Network error");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-lg font-bold flex items-center gap-2">
              <Shield className="w-5 h-5 text-brand-400" />
              Grant Access
            </h3>
            <p className="text-xs text-[var(--muted)] mt-0.5 truncate">{docTitle}</p>
          </div>
          <button onClick={onClose} className="btn btn-ghost btn-sm">
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* AI Access Advisor Card */}
        <div className="mb-4 p-3.5 rounded-xl bg-surface-200 border border-brand-700/20">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-brand-700 animate-pulse" />
              <span className="text-xs font-semibold text-brand-700 uppercase tracking-wider">
                AI Access Advisor
              </span>
            </div>
            <button
              type="button"
              onClick={generateAiRecommendation}
              className="btn btn-xs bg-brand-700 hover:bg-brand-800 text-white rounded-lg px-2.5 py-1 text-xs font-medium transition-all shadow-sm flex items-center gap-1.5"
            >
              <Sparkles className="w-3 h-3" />
              Suggest Safe Policy
            </button>
          </div>

          {aiExpanded && (
            <div className="mt-3 pt-3 border-t border-brand-700/20 text-xs space-y-1.5 animate-fade-in">
              <p className="font-semibold text-brand-800">
                💡 AI Policy Recommendation Applied:
              </p>
              <p className="text-[var(--foreground)] opacity-85 leading-relaxed">
                {aiRationale}
              </p>
              <div className="flex items-start gap-1.5 text-[11px] text-amber-800 mt-2 bg-amber-500/10 p-2 rounded-lg border border-amber-600/20">
                <Shield className="w-3.5 h-3.5 flex-shrink-0 mt-0.5 text-amber-700" />
                <span>
                  <strong>Strict Security Guardrail:</strong> AI cannot automatically widen or grant access. As document owner, you must confirm this grant. Both the recommendation and your decision will be immutably recorded in the SHA-256 audit trail.
                </span>
              </div>
            </div>
          )}
        </div>

        {error && (
          <div className="mb-4 p-3 rounded-lg bg-danger/10 border border-danger/20 text-danger text-sm">
            {error}
          </div>
        )}

        <form onSubmit={handleGrant} className="space-y-4">
          <div>
            <label className="block text-sm font-medium mb-1.5 text-[var(--muted)]">
              User Email *
            </label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="input"
              placeholder="user@example.com"
              required
              id="grant-permission-email"
            />
          </div>

          <div>
            <label className="block text-sm font-medium mb-1.5 text-[var(--muted)]">
              Permission Level *
            </label>
            <div className="flex gap-3">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="radio"
                  name="level"
                  value="read"
                  checked={level === "read"}
                  onChange={() => setLevel("read")}
                  className="accent-brand-500"
                />
                <Eye className="w-4 h-4 text-success" />
                <span className="text-sm">Read</span>
              </label>
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="radio"
                  name="level"
                  value="edit"
                  checked={level === "edit"}
                  onChange={() => setLevel("edit")}
                  className="accent-brand-500"
                />
                <Edit3 className="w-4 h-4 text-warning" />
                <span className="text-sm">Edit</span>
              </label>
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium mb-1.5 text-[var(--muted)]">
              Expiry Date (optional)
            </label>
            <input
              type="datetime-local"
              value={expiresAt}
              onChange={(e) => setExpiresAt(e.target.value)}
              className="input"
            />
          </div>

          {/* Ephemeral Access & Forensic Watermark Controls */}
          <div className="p-3.5 rounded-xl bg-surface-200 border border-brand-700/20 space-y-3">
            <label className="flex items-start gap-2.5 cursor-pointer">
              <input
                type="checkbox"
                checked={burnAfterRead}
                onChange={(e) => {
                  setBurnAfterRead(e.target.checked);
                  if (e.target.checked) setMaxAccessCount(1);
                }}
                className="mt-0.5 accent-brand-700"
                id="grant-burn-after-read"
              />
              <div>
                <div className="flex items-center gap-1.5 text-xs font-semibold text-[var(--foreground)]">
                  <Flame className="w-4 h-4 text-amber-600" />
                  Burn After Reading (Single-Use Ephemeral Grant)
                </div>
                <p className="text-[11px] text-[var(--muted)] leading-relaxed mt-0.5">
                  Permission automatically revokes immediately after the recipient downloads or inspects the document once.
                </p>
              </div>
            </label>

            {!burnAfterRead && (
              <div className="pt-2.5 border-t border-brand-700/15">
                <label className="block text-xs font-medium mb-1 text-[var(--muted)]">
                  Max Access Limit (Optional Count)
                </label>
                <input
                  type="number"
                  min="1"
                  value={maxAccessCount}
                  onChange={(e) => setMaxAccessCount(e.target.value ? parseInt(e.target.value, 10) : "")}
                  placeholder="e.g. 3 (leave blank for unlimited)"
                  className="input text-xs py-1.5"
                  id="grant-max-access-count"
                />
              </div>
            )}

            <div className="pt-2.5 border-t border-brand-700/15">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={watermarkEnabled}
                  onChange={(e) => setWatermarkEnabled(e.target.checked)}
                  className="accent-brand-700"
                  id="grant-watermark-enabled"
                />
                <span className="text-xs font-medium flex items-center gap-1 text-[var(--foreground)]">
                  <ShieldCheck className="w-3.5 h-3.5 text-brand-700" />
                  Enforce Dynamic Forensic Watermarking on Download
                </span>
              </label>
            </div>
          </div>

          <button
            type="submit"
            disabled={loading || !email}
            className="btn btn-primary w-full"
            id="grant-permission-submit"
          >
            {loading ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <Shield className="w-4 h-4" />
            )}
            Grant Access
          </button>
        </form>
      </div>
    </div>
  );
}

/* === Helpers === */

function formatAction(action: string): string {
  const map: Record<string, string> = {
    upload: "Upload",
    download: "Download",
    preview: "View",
    update: "Update",
    delete: "Delete",
    restore: "Restore",
    permission_grant: "Grant",
    permission_revoke: "Revoke",
    login: "Login",
    login_failure: "Login Failed",
    logout: "Logout",
    search: "Search",
    version_upload: "New Version",
  };
  return map[action] || action;
}

function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function AIAssistantTab({ docId, docTitle }: { docId: string; docTitle: string }) {
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<{
    answer: string;
    summary?: string;
    citations: Array<{ lineStart: number; lineEnd: number; textSnippet: string }>;
    groundedConfidence: number;
    promptInjectionDetected: boolean;
    model: string;
  } | null>(null);

  async function handleAsk(promptText?: string) {
    const q = (promptText || query).trim();
    if (!q) return;
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`/api/documents/${docId}/ai-assistant`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query: q }),
      });
      const data = await res.json();
      if (data.success && data.data) {
        setResult(data.data);
      } else {
        setError(data.error || "Failed to process query");
      }
    } catch {
      setError("Network error communicating with AI Assistant service");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="card space-y-6">
      <div className="flex items-start justify-between border-b border-[var(--card-border)] pb-4">
        <div>
          <h2 className="text-lg font-bold flex items-center gap-2">
            <Sparkles className="w-5 h-5 text-brand-700" />
            Document AI Assistant & Grounded Passage Analysis
          </h2>
          <p className="text-sm text-[var(--muted)]">
            Ask questions or summarize &quot;{docTitle}&quot;. All answers are strictly grounded in document content with line citations and prompt injection protection.
          </p>
        </div>
        <span className="badge badge-brand text-xs font-mono">Zero-Trust Guarded</span>
      </div>

      {/* Suggested prompts */}
      <div className="flex flex-wrap gap-2">
        <button
          onClick={() => { setQuery("Summarize this document"); handleAsk("Summarize this document"); }}
          disabled={loading}
          className="btn btn-secondary btn-sm text-xs"
        >
          ✨ Summarize Document
        </button>
        <button
          onClick={() => { setQuery("What are the key terms and security requirements?"); handleAsk("What are the key terms and security requirements?"); }}
          disabled={loading}
          className="btn btn-secondary btn-sm text-xs"
        >
          🛡️ Key Requirements
        </button>
        <button
          onClick={() => { setQuery("Are there sensitive credentials or dates mentioned?"); handleAsk("Are there sensitive credentials or dates mentioned?"); }}
          disabled={loading}
          className="btn btn-secondary btn-sm text-xs"
        >
          🔍 Sensitive Data Check
        </button>
      </div>

      {/* Input */}
      <form
        onSubmit={(e) => { e.preventDefault(); handleAsk(); }}
        className="flex gap-2"
      >
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Ask a question about this document..."
          className="input flex-1"
          disabled={loading}
        />
        <button
          type="submit"
          disabled={loading || !query.trim()}
          className="btn btn-primary"
        >
          {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Sparkles className="w-4 h-4" />}
          Ask Assistant
        </button>
      </form>

      {error && (
        <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/20 text-red-500 text-sm flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {result && (
        <div className="space-y-4 pt-2">
          {result.promptInjectionDetected && (
            <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/20 text-red-500 text-sm flex items-center gap-2">
              <Ban className="w-4 h-4 flex-shrink-0" />
              <span><strong>Adversarial Input Blocked:</strong> Attempted prompt injection was quarantined. Security alert logged.</span>
            </div>
          )}

          <div className="p-4 rounded-xl bg-[var(--background)] border border-[var(--card-border)] space-y-3">
            <div className="flex items-center justify-between text-xs text-[var(--muted)] border-b border-[var(--card-border)] pb-2">
              <span className="font-mono">Engine: {result.model}</span>
              <span className="flex items-center gap-1 font-semibold text-emerald-400">
                <CheckCircle2 className="w-3.5 h-3.5" />
                Confidence: {Math.round(result.groundedConfidence * 100)}%
              </span>
            </div>

            <div className="text-sm text-[var(--foreground)] whitespace-pre-wrap leading-relaxed">
              {result.answer}
            </div>

            {result.citations.length > 0 && (
              <div className="mt-4 pt-3 border-t border-[var(--card-border)]">
                <h4 className="text-xs font-semibold text-[var(--muted)] uppercase tracking-wider mb-2">
                  Verified Source Citations ({result.citations.length})
                </h4>
                <div className="space-y-1.5">
                  {result.citations.map((c, i) => (
                    <div
                      key={i}
                      className="text-xs p-2 rounded bg-brand-700/5 border border-brand-700/20 text-[var(--foreground)] flex items-start gap-2"
                    >
                      <span className="badge badge-brand text-[10px] px-1.5 py-0.5 whitespace-nowrap">
                        Line {c.lineStart}
                      </span>
                      <span className="font-mono text-xs opacity-90">&quot;{c.textSnippet}&quot;</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

