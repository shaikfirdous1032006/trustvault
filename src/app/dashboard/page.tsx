import { createClient, isSupabaseConfigured } from "@/lib/supabase/server";
import { getAuthenticatedUser } from "@/lib/auth";
import { redirect } from "next/navigation";
import type { User } from "@/lib/types";
import {
  FileText,
  Users,
  Shield,
  Activity,
  Upload,
  ArrowRight,
  AlertTriangle,
  CheckCircle2,
  Clock,
  Info,
} from "lucide-react";
import Link from "next/link";

export const metadata = {
  title: "Dashboard — TrustVault",
};

export default async function DashboardPage() {
  const user = await getAuthenticatedUser();
  if (!user) redirect("/login");

  const isConfigured = isSupabaseConfigured();

  let docCount = 0;
  let recentDocs: any[] = [];
  let recentAudit: Array<{
    id: string;
    action: string;
    result: string;
    occurred_at: string;
    actor_email: string | null;
  }> = [];
  let deniedCount = 0;
  let sharedCount = 0;

  if (isConfigured) {
    try {
      const supabase = await createClient();

      const { count: dCount } = await supabase
        .from("documents")
        .select("*", { count: "exact", head: true })
        .eq("is_deleted", false);
      docCount = dCount || 0;

      const { data: rDocs } = await supabase
        .from("documents")
        .select(
          "id, title, category, created_at, owner:users!documents_owner_id_fkey(email, full_name)"
        )
        .eq("is_deleted", false)
        .order("created_at", { ascending: false })
        .limit(5);
      recentDocs = rDocs || [];

      if (user.role === "admin" || user.role === "owner") {
        const { data: events } = await supabase
          .from("audit_events")
          .select("id, action, result, occurred_at, actor_email")
          .order("occurred_at", { ascending: false })
          .limit(8);
        recentAudit = events || [];
      }

      if (user.role === "admin") {
        const { count } = await supabase
          .from("audit_events")
          .select("*", { count: "exact", head: true })
          .eq("result", "denied");
        deniedCount = count || 0;
      }

      const { count: sCount } = await supabase
        .from("document_permissions")
        .select("*", { count: "exact", head: true })
        .eq("user_id", user.id)
        .is("revoked_at", null);
      sharedCount = sCount || 0;
    } catch {
      // In case of query error, keep defaults
    }
  } else {
    const { getStore, withUser } = await import("@/lib/local-db");
    const { evaluateDocumentPermission } = await import("@/lib/permission");
    const store = getStore();
    const visible = store.documents.filter((doc) =>
      evaluateDocumentPermission({
        document: doc,
        grants: store.permissions.filter((p) => p.document_id === doc.id),
        userId: user.id,
        requiredLevel: "read",
      }).allowed
    );
    docCount = visible.filter((d) => !d.is_deleted).length;
    recentDocs = visible
      .filter((d) => !d.is_deleted)
      .sort((a, b) => b.created_at.localeCompare(a.created_at))
      .slice(0, 5)
      .map((d) => withUser(d, store));
    sharedCount = store.permissions.filter(
      (p) => p.user_id === user.id && !p.revoked_at
    ).length;
    deniedCount = store.audit.filter((e) => e.result === "denied").length;
    if (user.role === "admin" || user.role === "owner") {
      recentAudit = store.audit
        .slice()
        .sort((a, b) => b.occurred_at.localeCompare(a.occurred_at))
        .slice(0, 8)
        .map((e) => ({
          id: e.id,
          action: e.action,
          result: e.result,
          occurred_at: e.occurred_at,
          actor_email: e.actor_email,
        }));
    }
  }

  const greeting = getGreeting();

  return (
    <div className="max-w-7xl mx-auto animate-fade-in">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-3xl font-bold mb-1">
          {greeting}, {user.full_name || user.email.split("@")[0]}
        </h1>
        <p className="text-[var(--muted)] text-sm">
          {user.role === "admin"
            ? "Platform overview and security monitoring"
            : user.role === "owner"
            ? "Manage your documents and permissions"
            : "Access documents shared with you"}
        </p>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
        <StatCard
          icon={<FileText className="w-5 h-5" />}
          label="Documents"
          value={docCount ?? 0}
          color="brand"
        />
        <StatCard
          icon={<Shield className="w-5 h-5" />}
          label="Shared with me"
          value={sharedCount ?? 0}
          color="info"
        />
        {user.role === "admin" && (
          <StatCard
            icon={<AlertTriangle className="w-5 h-5" />}
            label="Denied Attempts"
            value={deniedCount}
            color="danger"
          />
        )}
        <StatCard
          icon={<Activity className="w-5 h-5" />}
          label="Audit Events"
          value={recentAudit.length > 0 ? `${recentAudit.length} recent` : "—"}
          color="success"
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Recent Documents */}
        <div className="lg:col-span-2 card">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold flex items-center gap-2">
              <FileText className="w-5 h-5 text-brand-700" />
              Recent Documents
            </h2>
            <Link
              href="/dashboard/documents"
              className="text-sm text-brand-700 hover:text-brand-800 flex items-center gap-1 font-medium transition-colors"
            >
              View all <ArrowRight className="w-3.5 h-3.5" />
            </Link>
          </div>

          {recentDocs && recentDocs.length > 0 ? (
            <div className="space-y-2">
              {recentDocs.map((doc, i) => (
                <Link
                  key={doc.id}
                  href={`/dashboard/documents/${doc.id}`}
                  className="flex items-center gap-4 p-3 rounded-lg hover:bg-[var(--input-bg)] transition-all group"
                  style={{ animationDelay: `${i * 50}ms` }}
                >
                  <div className="w-10 h-10 rounded-lg bg-brand-700/10 flex items-center justify-center flex-shrink-0">
                    <FileText className="w-5 h-5 text-brand-700" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium truncate group-hover:text-brand-700 transition-colors">
                      {doc.title}
                    </p>
                    <p className="text-xs text-[var(--muted)]">
                      {doc.category} •{" "}
                      {new Date(doc.created_at).toLocaleDateString()}
                    </p>
                  </div>
                  <span className="badge badge-neutral text-xs">
                    {(() => {
                      const ownerRecord = Array.isArray(doc.owner) ? doc.owner[0] : doc.owner;
                      const typedOwner = ownerRecord as { full_name?: string | null; email?: string } | undefined;
                      return typedOwner?.full_name || typedOwner?.email || "Unknown";
                    })()}
                  </span>
                </Link>
              ))}
            </div>
          ) : (
            <div className="empty-state py-8">
              <FileText className="w-10 h-10 text-[var(--muted)] opacity-30" />
              <p className="text-sm text-[var(--muted)] mt-2">
                No documents yet
              </p>
              {(user.role === "owner" || user.role === "admin") && (
                <Link
                  href="/dashboard/upload"
                  className="btn btn-primary btn-sm mt-3"
                >
                  <Upload className="w-4 h-4" /> Upload your first document
                </Link>
              )}
            </div>
          )}
        </div>

        {/* Activity Feed */}
        <div className="card">
          <h2 className="text-lg font-semibold flex items-center gap-2 mb-4">
            <Activity className="w-5 h-5 text-success" />
            Recent Activity
          </h2>

          {recentAudit.length > 0 ? (
            <div className="space-y-3">
              {recentAudit.map((event) => (
                <div
                  key={event.id}
                  className="flex items-start gap-3 text-sm"
                >
                  <div className="mt-0.5">
                    {event.result === "allowed" ? (
                      <CheckCircle2 className="w-4 h-4 text-success" />
                    ) : (
                      <AlertTriangle className="w-4 h-4 text-danger" />
                    )}
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="truncate">
                      <span className="text-[var(--muted)]">
                        {event.actor_email?.split("@")[0] || "Unknown"}
                      </span>{" "}
                      <span className="font-medium">
                        {formatAction(event.action)}
                      </span>
                    </p>
                    <p className="text-xs text-[var(--muted)] flex items-center gap-1">
                      <Clock className="w-3 h-3" />
                      {formatTimeAgo(event.occurred_at)}
                    </p>
                  </div>
                  <span
                    className={`badge ${
                      event.result === "allowed"
                        ? "badge-success"
                        : "badge-danger"
                    }`}
                  >
                    {event.result}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <div className="empty-state py-8">
              <Activity className="w-10 h-10 text-[var(--muted)] opacity-30" />
              <p className="text-sm text-[var(--muted)] mt-2">
                No recent activity
              </p>
            </div>
          )}
        </div>
      </div>

      {/* Quick Actions */}
      {(user.role === "owner" || user.role === "admin") && (
        <div className="mt-6 card">
          <h2 className="text-lg font-semibold mb-4">Quick Actions</h2>
          <div className="flex flex-wrap gap-3">
            <Link href="/dashboard/upload" className="btn btn-primary btn-sm">
              <Upload className="w-4 h-4" /> Upload Document
            </Link>
            <Link
              href="/dashboard/documents"
              className="btn btn-secondary btn-sm"
            >
              <FileText className="w-4 h-4" /> Browse Documents
            </Link>
            {user.role === "admin" && (
              <>
                <Link
                  href="/dashboard/admin/users"
                  className="btn btn-secondary btn-sm"
                >
                  <Users className="w-4 h-4" /> Manage Users
                </Link>
                <Link
                  href="/dashboard/admin/audit"
                  className="btn btn-secondary btn-sm"
                >
                  <Activity className="w-4 h-4" /> Audit Log
                </Link>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function StatCard({
  icon,
  label,
  value,
  color,
}: {
  icon: React.ReactNode;
  label: string;
  value: number | string;
  color: "brand" | "success" | "danger" | "info";
}) {
  const colors = {
    brand: "from-brand-700/15 to-brand-500/10 text-brand-700",
    success: "from-success/15 to-success/5 text-success",
    danger: "from-danger/15 to-danger/5 text-danger",
    info: "from-info/15 to-info/5 text-info",
  };

  return (
    <div className="card flex items-center gap-4">
      <div
        className={`w-11 h-11 rounded-xl bg-gradient-to-br ${colors[color]} flex items-center justify-center flex-shrink-0`}
      >
        {icon}
      </div>
      <div>
        <p className="text-2xl font-bold">{value}</p>
        <p className="text-xs text-[var(--muted)]">{label}</p>
      </div>
    </div>
  );
}

function getGreeting(): string {
  const hour = new Date().getHours();
  if (hour < 12) return "Good morning";
  if (hour < 17) return "Good afternoon";
  return "Good evening";
}

function formatAction(action: string): string {
  const map: Record<string, string> = {
    upload: "uploaded a document",
    download: "downloaded a document",
    preview: "viewed a document",
    update: "updated a document",
    delete: "deleted a document",
    restore: "restored a document",
    permission_grant: "granted permission",
    permission_revoke: "revoked permission",
    login: "signed in",
    login_failure: "failed login attempt",
    logout: "signed out",
    search: "searched documents",
    version_upload: "uploaded a new version",
  };
  return map[action] || action;
}

function formatTimeAgo(dateStr: string): string {
  const date = new Date(dateStr);
  const now = new Date();
  const diff = Math.floor((now.getTime() - date.getTime()) / 1000);

  if (diff < 60) return "just now";
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}
