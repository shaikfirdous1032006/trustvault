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

type Tab = "details" | "permissions" | "versions" | "audit";

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
    fetchDocument();
  }, [fetchDocument]);

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

  const fetchAudit = useCallback(async () => {
    if (!docId) return;
    setAuditLoading(true);
    try {
      const res = await fetch(`/api/documents/${docId}/audit`);
      const data = await res.json();
      if (data.success) setAuditEvents(data.data);
    } catch {
      /* ignored */
    } finally {
      setAuditLoading(false);
    }
  }, [docId]);

  useEffect(() => {
    if (activeTab === "permissions") fetchPermissions();
    if (activeTab === "versions") fetchVersions();
    if (activeTab === "audit") fetchAudit();
  }, [activeTab, fetchPermissions, fetchVersions, fetchAudit]);

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
    ...(isOwner
      ? [
          {
            key: "permissions" as const,
            label: "Permissions",
            icon: <Shield className="w-4 h-4" />,
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
          <button
            onClick={() => setShowDeleteConfirm(true)}
            className="btn btn-danger btn-sm"
            id="delete-document-btn"
          >
            <Trash2 className="w-4 h-4" /> Delete
          </button>
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
      {activeTab === "permissions" && (
        <PermissionsTab
          permissions={permissions}
          loading={permLoading}
          docId={doc.id}
          isOwner={true}
          onRevoke={handleRevokePermission}
          onGrant={() => setShowGrantModal(true)}
          onRefresh={fetchPermissions}
        />
      )}
      {activeTab === "versions" && (
        <VersionsTab versions={versions} loading={verLoading} docId={doc.id} onRefresh={fetchVersions} />
      )}
      {activeTab === "audit" && (
        <AuditTab events={auditEvents} loading={auditLoading} />
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
  docId,
  isOwner,
  onRevoke,
  onGrant,
  onRefresh,
}: {
  permissions: Permission[];
  loading: boolean;
  docId: string;
  isOwner: boolean;
  onRevoke: (id: string) => void;
  onGrant: () => void;
  onRefresh: () => void;
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
                <div className="flex items-center gap-3">
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
}: {
  events: AuditEvent[];
  loading: boolean;
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
      <h3 className="text-lg font-semibold flex items-center gap-2 mb-4">
        <Activity className="w-5 h-5 text-brand-700" />
        Audit Trail ({events.length} events)
      </h3>

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
          expires_at: expiresAt || undefined,
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
          <h3 className="text-lg font-bold flex items-center gap-2">
            <Shield className="w-5 h-5 text-brand-400" />
            Grant Access
          </h3>
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
