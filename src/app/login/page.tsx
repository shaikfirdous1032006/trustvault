"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import {
  Shield,
  Lock,
  Eye,
  EyeOff,
  Loader2,
  FileCheck,
  Users,
  Activity,
} from "lucide-react";

const DEMO_ACCOUNTS = [
  { email: "admin@example.com", role: "Admin", desc: "Platform oversight" },
  { email: "owner@example.com", role: "Owner", desc: "Upload & manage docs" },
  { email: "viewer@example.com", role: "Viewer", desc: "View shared docs" },
];

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function handleLogin(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError("");

    try {
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });

      const data = await res.json();

      if (!res.ok) {
        setError(data.error || "Login failed");
        return;
      }

      router.push("/dashboard");
      router.refresh();
    } catch {
      setError("Network error. Please try again.");
    } finally {
      setLoading(false);
    }
  }

  function fillDemo(demoEmail: string) {
    setEmail(demoEmail);
    setPassword("TrustVault2024!");
    setError("");
  }

  return (
    <div className="min-h-screen flex">
      {/* Left panel — branding */}
      <div className="hidden lg:flex lg:w-1/2 relative overflow-hidden bg-surface-900 flex-col justify-between p-12">
        {/* Background pattern */}
        <div className="absolute inset-0 opacity-5">
          <div
            className="absolute inset-0"
            style={{
              backgroundImage: `radial-gradient(circle at 1px 1px, rgba(194,155,110,0.3) 1px, transparent 0)`,
              backgroundSize: "40px 40px",
            }}
          />
        </div>

        {/* Gradient orbs */}
        <div className="absolute top-20 left-20 w-72 h-72 bg-brand-600/20 rounded-full blur-[100px]" />
        <div className="absolute bottom-40 right-20 w-96 h-96 bg-brand-400/10 rounded-full blur-[120px]" />

        <div className="relative z-10">
          <div className="flex items-center gap-3 mb-2">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-brand-500 to-brand-700 flex items-center justify-center">
              <Shield className="w-6 h-6 text-white" />
            </div>
            <span className="text-2xl font-bold text-white">TrustVault</span>
          </div>
          <p className="text-surface-200/60 text-sm mt-1 ml-[52px]">
            Secure Document Sharing Platform
          </p>
        </div>

        <div className="relative z-10 space-y-8">
          <h1 className="text-4xl font-bold text-white leading-tight">
            Security-first
            <br />
            document sharing
            <br />
            <span className="text-brand-400">you can trust.</span>
          </h1>

          <div className="space-y-4 text-surface-200/80">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-lg bg-brand-600/20 flex items-center justify-center flex-shrink-0">
                <Lock className="w-4 h-4 text-brand-400" />
              </div>
              <span className="text-sm">
                End-to-end encrypted storage with private buckets
              </span>
            </div>
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-lg bg-brand-600/20 flex items-center justify-center flex-shrink-0">
                <FileCheck className="w-4 h-4 text-brand-400" />
              </div>
              <span className="text-sm">
                SHA-256 hash chain for tamper-evident audit trail
              </span>
            </div>
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-lg bg-brand-600/20 flex items-center justify-center flex-shrink-0">
                <Users className="w-4 h-4 text-brand-400" />
              </div>
              <span className="text-sm">
                Granular per-document permissions with instant revocation
              </span>
            </div>
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-lg bg-brand-600/20 flex items-center justify-center flex-shrink-0">
                <Activity className="w-4 h-4 text-brand-400" />
              </div>
              <span className="text-sm">
                Append-only audit log — every action recorded
              </span>
            </div>
          </div>
        </div>

        <p className="relative z-10 text-surface-200/40 text-xs">
          © 2024 TrustVault. Built with security as the foundation.
        </p>
      </div>

      {/* Right panel — login form */}
      <div className="flex-1 flex items-center justify-center p-6 sm:p-12">
        <div className="w-full max-w-md animate-fade-in">
          {/* Mobile logo */}
          <div className="flex items-center gap-3 mb-8 lg:hidden">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-brand-500 to-brand-700 flex items-center justify-center">
              <Shield className="w-6 h-6 text-white" />
            </div>
            <span className="text-2xl font-bold">TrustVault</span>
          </div>

          <div>
            <h2 className="text-2xl font-bold mb-1">Welcome back</h2>
            <p className="text-[var(--muted)] text-sm mb-8">
              Sign in to access your secure documents
            </p>
          </div>

          {error && (
            <div className="mb-6 p-3 rounded-lg bg-danger/10 border border-danger/20 text-danger text-sm flex items-center gap-2 animate-fade-in">
              <svg className="w-4 h-4 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
                <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
              </svg>
              {error}
            </div>
          )}

          <form onSubmit={handleLogin} className="space-y-4">
            <div>
              <label
                htmlFor="email"
                className="block text-sm font-medium mb-1.5 text-[var(--muted)]"
              >
                Email address
              </label>
              <input
                id="email"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="input"
                placeholder="you@example.com"
                required
                autoComplete="email"
              />
            </div>

            <div>
              <label
                htmlFor="password"
                className="block text-sm font-medium mb-1.5 text-[var(--muted)]"
              >
                Password
              </label>
              <div className="relative">
                <input
                  id="password"
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="input pr-10"
                  placeholder="••••••••"
                  required
                  autoComplete="current-password"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-[var(--muted)] hover:text-[var(--foreground)] transition-colors"
                  aria-label={showPassword ? "Hide password" : "Show password"}
                >
                  {showPassword ? (
                    <EyeOff className="w-4 h-4" />
                  ) : (
                    <Eye className="w-4 h-4" />
                  )}
                </button>
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="btn btn-primary w-full btn-lg mt-2"
            >
              {loading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  Signing in...
                </>
              ) : (
                <>
                  <Lock className="w-4 h-4" />
                  Sign in
                </>
              )}
            </button>
          </form>

          {/* Demo accounts */}
          <div className="mt-8">
            <div className="flex items-center gap-3 mb-4">
              <div className="h-px flex-1 bg-[var(--card-border)]" />
              <span className="text-xs text-[var(--muted)] uppercase tracking-wider font-medium">
                Demo Accounts
              </span>
              <div className="h-px flex-1 bg-[var(--card-border)]" />
            </div>

            <div className="space-y-2">
              {DEMO_ACCOUNTS.map((account) => (
                <button
                  key={account.email}
                  onClick={() => fillDemo(account.email)}
                  className="w-full flex items-center gap-3 p-3 rounded-lg border border-[var(--card-border)] hover:border-brand-500/40 hover:bg-brand-500/5 transition-all text-left group"
                >
                  <div className="w-8 h-8 rounded-full bg-gradient-to-br from-brand-500/20 to-brand-700/20 flex items-center justify-center text-brand-400 text-xs font-bold flex-shrink-0">
                    {account.role[0]}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="text-sm font-medium group-hover:text-brand-400 transition-colors">
                      {account.role}
                    </div>
                    <div className="text-xs text-[var(--muted)] truncate">
                      {account.email} — {account.desc}
                    </div>
                  </div>
                  <svg
                    className="w-4 h-4 text-[var(--muted)] group-hover:text-brand-400 transition-colors flex-shrink-0"
                    fill="none"
                    viewBox="0 0 24 24"
                    stroke="currentColor"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M9 5l7 7-7 7"
                    />
                  </svg>
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
