"use client";

import { useState, useEffect, useCallback } from "react";
import {
  Users,
  Search,
  Shield,
  ChevronLeft,
  ChevronRight,
  CheckCircle2,
  XCircle,
  Loader2,
  RefreshCw,
  Power,
} from "lucide-react";

interface UserRecord {
  id: string;
  email: string;
  full_name: string | null;
  role: string;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export default function AdminUsersPage() {
  const [users, setUsers] = useState<UserRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [updatingId, setUpdatingId] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [search, setSearch] = useState("");
  const [statusMessage, setStatusMessage] = useState<string | null>(null);
  const pageSize = 20;

  const loadUsers = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      params.set("page", page.toString());
      params.set("pageSize", pageSize.toString());
      const res = await fetch(`/api/admin/users?${params}`);
      const data = await res.json();
      if (data.success) {
        setUsers(data.data);
        setTotal(data.total);
      }
    } catch {
      /* ignored */
    } finally {
      setLoading(false);
    }
  }, [page]);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        const params = new URLSearchParams();
        params.set("page", page.toString());
        params.set("pageSize", pageSize.toString());
        const res = await fetch(`/api/admin/users?${params}`);
        const data = await res.json();
        if (data.success && !cancelled) {
          setUsers(data.data);
          setTotal(data.total);
        }
      } catch {
        /* ignored */
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    void load();
    return () => {
      cancelled = true;
    };
  }, [page]);

  async function handleRoleChange(userId: string, newRole: string) {
    setUpdatingId(userId);
    setStatusMessage(null);
    try {
      const res = await fetch("/api/admin/users", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ userId, role: newRole }),
      });
      const data = await res.json();
      if (data.success) {
        setUsers((prev) =>
          prev.map((u) => (u.id === userId ? { ...u, role: newRole } : u))
        );
        setStatusMessage(`✅ Role successfully changed to ${newRole}`);
      } else {
        setStatusMessage(`⚠️ ${data.error || "Failed to update role"}`);
      }
    } catch {
      setStatusMessage("⚠️ Failed to update role");
    } finally {
      setUpdatingId(null);
    }
  }

  async function handleToggleActive(userId: string, currentActive: boolean) {
    setUpdatingId(userId);
    setStatusMessage(null);
    const newActive = !currentActive;
    try {
      const res = await fetch("/api/admin/users", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ userId, is_active: newActive }),
      });
      const data = await res.json();
      if (data.success) {
        setUsers((prev) =>
          prev.map((u) => (u.id === userId ? { ...u, is_active: newActive } : u))
        );
        setStatusMessage(
          `✅ Account ${newActive ? "activated" : "deactivated"} successfully`
        );
      } else {
        setStatusMessage(`⚠️ ${data.error || "Failed to update account status"}`);
      }
    } catch {
      setStatusMessage("⚠️ Failed to update account status");
    } finally {
      setUpdatingId(null);
    }
  }

  const filteredUsers = search
    ? users.filter(
        (u) =>
          u.email.toLowerCase().includes(search.toLowerCase()) ||
          u.full_name?.toLowerCase().includes(search.toLowerCase())
      )
    : users;

  const totalPages = Math.ceil(total / pageSize);

  const roleBadge = (role: string) => {
    switch (role) {
      case "admin":
        return "badge-danger";
      case "owner":
        return "badge-brand";
      default:
        return "badge-success";
    }
  };

  return (
    <div className="max-w-5xl mx-auto animate-fade-in">
      <div className="mb-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Users className="w-6 h-6 text-brand-400" />
            User Management & Authorization
          </h1>
          <p className="text-[var(--muted)] text-sm mt-1">
            View platform users, manage role assignments, and control account activation status
          </p>
        </div>
        <button
          onClick={() => void loadUsers()}
          className="btn btn-secondary btn-sm flex items-center gap-1.5 self-start sm:self-auto"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
          Refresh
        </button>
      </div>

      {statusMessage && (
        <div className="mb-4 p-3 rounded-lg bg-[var(--input-bg)] border border-[var(--card-border)] text-xs animate-fade-in flex items-center justify-between">
          <span>{statusMessage}</span>
          <button
            onClick={() => setStatusMessage(null)}
            className="text-[var(--muted)] hover:text-[var(--foreground)] ml-2"
          >
            ✕
          </button>
        </div>
      )}

      {/* Search */}
      <div className="relative mb-6">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[var(--muted)]" />
        <input
          type="text"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search users by name or email..."
          className="input pl-10"
          id="search-users-input"
        />
      </div>

      {/* Users Table */}
      {loading ? (
        <div className="card space-y-3">
          {Array.from({ length: 5 }).map((_, i) => (
            <div key={i} className="skeleton h-12 w-full" />
          ))}
        </div>
      ) : filteredUsers.length > 0 ? (
        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>User</th>
                <th>Email</th>
                <th>Role</th>
                <th>Status</th>
                <th>Joined</th>
                <th className="text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredUsers.map((user) => {
                const isUpdating = updatingId === user.id;

                return (
                  <tr key={user.id}>
                    <td>
                      <div className="flex items-center gap-3">
                        <div className="w-8 h-8 rounded-full bg-gradient-to-br from-brand-400 to-brand-600 flex items-center justify-center text-white text-xs font-bold flex-shrink-0">
                          {user.full_name?.[0]?.toUpperCase() ||
                            user.email[0].toUpperCase()}
                        </div>
                        <span className="text-sm font-medium">
                          {user.full_name || user.email.split("@")[0]}
                        </span>
                      </div>
                    </td>
                    <td className="text-sm text-[var(--muted)]">{user.email}</td>
                    <td>
                      <div className="flex items-center gap-2">
                        <span className={`badge ${roleBadge(user.role)}`}>
                          <Shield className="w-3 h-3 mr-1" />
                          {user.role}
                        </span>
                        <select
                          value={user.role}
                          disabled={isUpdating}
                          onChange={(e) => void handleRoleChange(user.id, e.target.value)}
                          className="bg-[var(--input-bg)] border border-[var(--card-border)] rounded px-1.5 py-0.5 text-xs text-[var(--foreground)] cursor-pointer"
                        >
                          <option value="viewer">Viewer</option>
                          <option value="owner">Owner</option>
                          <option value="admin">Admin</option>
                        </select>
                      </div>
                    </td>
                    <td>
                      {user.is_active ? (
                        <span className="badge badge-success">
                          <CheckCircle2 className="w-3 h-3 mr-1" />
                          Active
                        </span>
                      ) : (
                        <span className="badge badge-danger">
                          <XCircle className="w-3 h-3 mr-1" />
                          Inactive
                        </span>
                      )}
                    </td>
                    <td className="text-xs text-[var(--muted)]">
                      {new Date(user.created_at).toLocaleDateString()}
                    </td>
                    <td className="text-right">
                      <button
                        onClick={() => void handleToggleActive(user.id, user.is_active)}
                        disabled={isUpdating}
                        className={`btn btn-sm text-xs inline-flex items-center gap-1 ${
                          user.is_active
                            ? "btn-secondary hover:text-danger hover:border-danger/30"
                            : "btn-primary"
                        }`}
                        title={user.is_active ? "Deactivate account" : "Activate account"}
                      >
                        {isUpdating ? (
                          <Loader2 className="w-3 h-3 animate-spin" />
                        ) : (
                          <Power className="w-3 h-3" />
                        )}
                        {user.is_active ? "Deactivate" : "Activate"}
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="empty-state py-16">
          <Users className="w-12 h-12 text-[var(--muted)] opacity-30" />
          <p className="text-lg font-medium mt-3">No users found</p>
        </div>
      )}

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between mt-6">
          <p className="text-sm text-[var(--muted)]">
            Showing {(page - 1) * pageSize + 1}–
            {Math.min(page * pageSize, total)} of {total}
          </p>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setPage(page - 1)}
              disabled={page === 1}
              className="btn btn-secondary btn-sm"
            >
              <ChevronLeft className="w-4 h-4" /> Prev
            </button>
            <span className="text-sm">
              {page} / {totalPages}
            </span>
            <button
              onClick={() => setPage(page + 1)}
              disabled={page >= totalPages}
              className="btn btn-secondary btn-sm"
            >
              Next <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
