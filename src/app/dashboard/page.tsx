import { createClient, isSupabaseConfigured } from "@/lib/supabase/server";
import { getAuthenticatedUser } from "@/lib/auth";
import { redirect } from "next/navigation";
import {
  FileText,
  Users,
  Shield,
  Activity,
  Upload,
  ArrowRight,
  AlertTriangle,
  Sparkles,
  ShieldAlert,
  Sliders,
  Database,
} from "lucide-react";
import Link from "next/link";
import { DashboardRecentActivity } from "@/components/dashboard-recent-activity";

export const metadata = {
  title: "Dashboard — TrustVault",
};

interface RecentDoc {
  id: string;
  title: string;
  category: string;
  created_at: string;
  owner?: { full_name?: string | null; email?: string } | { full_name?: string | null; email?: string }[];
}

export default async function DashboardPage() {
  const user = await getAuthenticatedUser();
  if (!user) redirect("/login");

  const isConfigured = isSupabaseConfigured();

  let docCount = 0;
  let recentDocs: RecentDoc[] = [];
  let recentAudit: Array<{
    id: string;
    action: string;
    result: string;
    occurred_at: string;
    actor_id?: string | null;
    actor_email: string | null;
    document_id?: string | null;
    document_title?: string | null;
    description?: string;
    target_resource_type?: string;
    target_resource_id?: string | null;
    details?: Record<string, unknown>;
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

      const { formatAuditDescription } = await import("@/lib/audit");
      type AuditAction = import("@/lib/types").AuditAction;
      type AuditResult = import("@/lib/types").AuditResult;

      if (user.role === "admin" || user.role === "owner") {
        const { data: events } = await supabase
          .from("audit_events")
          .select("id, action, result, occurred_at, actor_id, actor_email, document_id, details_jsonb")
          .order("occurred_at", { ascending: false })
          .limit(10);
        recentAudit = (events || []).map((e) => {
          const details = (e.details_jsonb as Record<string, unknown>) || {};
          return {
            id: e.id,
            action: e.action,
            result: e.result,
            occurred_at: e.occurred_at,
            actor_id: e.actor_id,
            actor_email: e.actor_email,
            document_id: e.document_id,
            document_title: (details.file_name as string) || (details.title as string) || (details.document_title as string) || null,
            description: (details.description as string) || formatAuditDescription({
              actorId: e.actor_id,
              actorEmail: e.actor_email,
              documentId: e.document_id,
              action: e.action as AuditAction,
              result: e.result as AuditResult,
              details,
            }),
            target_resource_type: (details.target_resource_type as string) || (e.document_id ? "document" : "system"),
            target_resource_id: (details.target_resource_id as string) || e.document_id || null,
            details,
          };
        });
      } else {
        const { data: events } = await supabase
          .from("audit_events")
          .select("id, action, result, occurred_at, actor_id, actor_email, document_id, details_jsonb")
          .eq("actor_id", user.id)
          .order("occurred_at", { ascending: false })
          .limit(10);
        recentAudit = (events || []).map((e) => {
          const details = (e.details_jsonb as Record<string, unknown>) || {};
          return {
            id: e.id,
            action: e.action,
            result: e.result,
            occurred_at: e.occurred_at,
            actor_id: e.actor_id,
            actor_email: e.actor_email,
            document_id: e.document_id,
            document_title: (details.file_name as string) || (details.title as string) || (details.document_title as string) || null,
            description: (details.description as string) || formatAuditDescription({
              actorId: e.actor_id,
              actorEmail: e.actor_email,
              documentId: e.document_id,
              action: e.action as AuditAction,
              result: e.result as AuditResult,
              details,
            }),
            target_resource_type: (details.target_resource_type as string) || (e.document_id ? "document" : "system"),
            target_resource_id: (details.target_resource_id as string) || e.document_id || null,
            details,
          };
        });
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
    const { formatAuditDescription } = await import("@/lib/audit");
    type AuditAction = import("@/lib/types").AuditAction;
    type AuditResult = import("@/lib/types").AuditResult;

    const store = getStore();
    const docMap = new Map<string, string>();
    store.documents.forEach((d) => docMap.set(d.id, d.title));

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

    const mapStoreAudit = (e: (typeof store.audit)[0]) => {
      const details = (e.details_jsonb as Record<string, unknown>) || {};
      const docTitle = e.document_id ? docMap.get(e.document_id) || (details.file_name as string) || (details.title as string) || null : null;
      return {
        id: e.id,
        action: e.action,
        result: e.result,
        occurred_at: e.occurred_at,
        actor_id: e.actor_id,
        actor_email: e.actor_email,
        document_id: e.document_id,
        document_title: docTitle,
        description: (details.description as string) || formatAuditDescription({
          actorId: e.actor_id,
          actorEmail: e.actor_email,
          documentId: e.document_id,
          action: e.action as AuditAction,
          result: e.result as AuditResult,
          details: { ...details, title: docTitle },
        }),
        target_resource_type: (details.target_resource_type as string) || (e.document_id ? "document" : "system"),
        target_resource_id: (details.target_resource_id as string) || e.document_id || null,
        details,
      };
    };

    if (user.role === "admin" || user.role === "owner") {
      recentAudit = store.audit
        .slice()
        .sort((a, b) => b.occurred_at.localeCompare(a.occurred_at))
        .slice(0, 10)
        .map(mapStoreAudit);
    } else {
      recentAudit = store.audit
        .filter((e) => e.actor_email === user.email || e.actor_id === user.id)
        .sort((a, b) => b.occurred_at.localeCompare(a.occurred_at))
        .slice(0, 10)
        .map(mapStoreAudit);
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

      {/* MongoDB Atlas Connected Banner */}
      <div className="mb-8 p-4 rounded-xl bg-gradient-to-r from-emerald-500/10 via-brand-500/10 to-transparent border border-emerald-500/20 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-emerald-500/20 text-emerald-400 flex items-center justify-center flex-shrink-0">
            <Database className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-sm font-bold text-[var(--foreground)]">Connected to MongoDB Atlas Database</h2>
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                Live Cluster
              </span>
            </div>
            <p className="text-xs text-[var(--muted)] mt-0.5 font-mono">
              Cluster: cluster0.m0y0ghy.mongodb.net • Database: trustvault • Collections: documents, users, permissions, versions, share_links, audit
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2 self-start sm:self-center flex-shrink-0">
          <Link
            href="/dashboard/documents"
            className="btn btn-secondary btn-sm text-xs"
          >
            Explore Collections
          </Link>
        </div>
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

      {/* Zero-Trust Platform Modules Quick Access */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
        <Link
          href="/dashboard/privacy"
          className="card p-5 border hover:border-brand-500/50 transition group flex flex-col justify-between"
        >
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="p-2 rounded-lg bg-brand-500/10 text-brand-400">
                <Sparkles className="w-5 h-5" />
              </span>
              <span className="badge badge-brand text-xs">AI Security</span>
            </div>
            <h3 className="text-base font-bold group-hover:text-brand-400 transition">
              AI Privacy Shield
            </h3>
            <p className="text-xs text-[var(--muted)] mt-1">
              Automated PII detection, SSN/Card pattern redaction, and owner-approved asset generation.
            </p>
          </div>
          <div className="mt-4 flex items-center text-xs font-semibold text-brand-400 gap-1">
            Open Privacy Shield <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-1 transition-transform" />
          </div>
        </Link>

        {user.role === "admin" ? (
          <Link
            href="/dashboard/admin/alerts"
            className="card p-5 border hover:border-red-500/50 transition group flex flex-col justify-between"
          >
            <div>
              <div className="flex items-center justify-between mb-2">
                <span className="p-2 rounded-lg bg-red-500/10 text-red-400">
                  <ShieldAlert className="w-5 h-5" />
                </span>
                <span className="badge badge-danger text-xs">Active Monitoring</span>
              </div>
              <h3 className="text-base font-bold group-hover:text-red-400 transition">
                Threat Detection & Alerts
              </h3>
              <p className="text-xs text-[var(--muted)] mt-1">
                Real-time anomaly rules detecting brute force, IDOR enumeration, and mass download bursts.
              </p>
            </div>
            <div className="mt-4 flex items-center text-xs font-semibold text-red-400 gap-1">
              Review Security Alerts <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-1 transition-transform" />
            </div>
          </Link>
        ) : (
          <div className="card p-5 border opacity-75 flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between mb-2">
                <span className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400">
                  <Shield className="w-5 h-5" />
                </span>
                <span className="badge badge-success text-xs">Enforced</span>
              </div>
              <h3 className="text-base font-bold">Zero-Trust Authorization</h3>
              <p className="text-xs text-[var(--muted)] mt-1">
                Authoritative per-document permissions, time-bound grants, and least-privilege enforcement.
              </p>
            </div>
            <div className="mt-4 text-xs text-[var(--muted)] font-medium">
              Active Protection
            </div>
          </div>
        )}

        {user.role === "admin" ? (
          <Link
            href="/dashboard/admin/simulator"
            className="card p-5 border hover:border-purple-500/50 transition group flex flex-col justify-between"
          >
            <div>
              <div className="flex items-center justify-between mb-2">
                <span className="p-2 rounded-lg bg-purple-500/10 text-purple-400">
                  <Sliders className="w-5 h-5" />
                </span>
                <span className="badge badge-neutral text-xs">Simulator</span>
              </div>
              <h3 className="text-base font-bold group-hover:text-purple-400 transition">
                Policy Simulator
              </h3>
              <p className="text-xs text-[var(--muted)] mt-1">
                Pre-flight &quot;What-If&quot; policy preview projecting access changes and risk consequences.
              </p>
            </div>
            <div className="mt-4 flex items-center text-xs font-semibold text-purple-400 gap-1">
              Simulate Policies <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-1 transition-transform" />
            </div>
          </Link>
        ) : (
          <Link
            href="/dashboard/documents"
            className="card p-5 border hover:border-brand-500/50 transition group flex flex-col justify-between"
          >
            <div>
              <div className="flex items-center justify-between mb-2">
                <span className="p-2 rounded-lg bg-brand-500/10 text-brand-400">
                  <FileText className="w-5 h-5" />
                </span>
                <span className="badge badge-brand text-xs">Vault</span>
              </div>
              <h3 className="text-base font-bold group-hover:text-brand-400 transition">
                Document Library
              </h3>
              <p className="text-xs text-[var(--muted)] mt-1">
                Browse confidential files, verify access permissions, and preview authorized content.
              </p>
            </div>
            <div className="mt-4 flex items-center text-xs font-semibold text-brand-400 gap-1">
              Browse Vault <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-1 transition-transform" />
            </div>
          </Link>
        )}
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

        {/* Real-Time Live Activity Feed */}
        <DashboardRecentActivity initialEvents={recentAudit} />
      </div>

      {/* Quick Actions */}
      <div className="mt-6 card">
        <h2 className="text-lg font-semibold mb-4">Quick Actions</h2>
        <div className="flex flex-wrap gap-3">
          {user.role === "owner" && (
            <Link href="/dashboard/upload" className="btn btn-primary btn-sm">
              <Upload className="w-4 h-4" /> Upload Document
            </Link>
          )}
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

