
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
  ArrowRight,
  UserPlus,
  Database,
} from "lucide-react";

type DemoAccount = {
  email: string;
  role: string;
  description: string;
};

const DEMO_PASSWORD = "TrustVault2024!";

const DEMO_ACCOUNTS: DemoAccount[] = [
  {
    email: "admin@example.com",
    role: "Admin",
    description: "Platform oversight",
  },
  {
    email: "owner@example.com",
    role: "Owner",
    description: "Upload and manage documents",
  },
  {
    email: "viewer@example.com",
    role: "Viewer",
    description: "View shared documents",
  },
];

export default function LoginPage() {
  const router = useRouter();

  const [mode, setMode] = useState<"login" | "register">("login");
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  function chooseMode(nextMode: "login" | "register") {
    setMode(nextMode);
    setError("");
    setMessage("");
  }

  function fillDemo(account: DemoAccount) {
    setMode("login");
    setEmail(account.email);
    setPassword(DEMO_PASSWORD);
    setError("");
    setMessage(`${account.role} demo credentials filled in.`);
    setShowPassword(false);
  }

  async function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    setMessage("");

    if (mode === "register") {
      if (password.length < 8) {
        setError("Choose a password with at least 8 characters.");
        return;
      }

      if (password !== confirmPassword) {
        setError("The passwords do not match.");
        return;
      }
    }

    setLoading(true);

    try {
      const endpoint =
        mode === "login" ? "/api/auth/login" : "/api/auth/register";

      const body =
        mode === "login"
          ? { email: email.trim(), password }
          : {
              full_name: name.trim(),
              name: name.trim(),
              email: email.trim(),
              password,
            };

      const response = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "same-origin",
        body: JSON.stringify(body),
      });

      const data = await response.json().catch(() => null);

      if (!response.ok) {
        setError(
          data?.error ||
            (mode === "login"
              ? "Sign-in failed. Check your credentials."
              : "Registration failed. Check that the registration API is configured.")
        );
        return;
      }

      if (mode === "register") {
        setMessage("Account created. You can now sign in.");
        setMode("login");
        setPassword("");
        setConfirmPassword("");
        return;
      }

      router.replace("/dashboard");
      router.refresh();
    } catch {
      setError("Cannot reach the server. Make sure TrustVault is running.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="min-h-screen flex bg-[var(--background)]">
      <section className="hidden lg:flex lg:w-1/2 relative overflow-hidden bg-surface-900 flex-col justify-between p-12">
        <div
          className="absolute inset-0 opacity-10"
          style={{
            backgroundImage:
              "radial-gradient(circle, rgba(194,155,110,0.5) 1px, transparent 1px)",
            backgroundSize: "32px 32px",
          }}
        />

        <div className="absolute top-20 left-20 h-72 w-72 rounded-full bg-brand-600/20 blur-[100px]" />
        <div className="absolute bottom-32 right-12 h-80 w-80 rounded-full bg-brand-400/10 blur-[110px]" />

        <div className="relative z-10">
          <div className="flex items-center gap-3">
            <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-brand-600">
              <Shield className="h-6 w-6 text-white" />
            </div>
            <span className="text-2xl font-bold text-white">TrustVault</span>
          </div>
          <p className="ml-14 mt-1 text-sm text-surface-200/60">
            Secure Document Sharing Platform
          </p>
        </div>

        <div className="relative z-10 space-y-8">
          <h1 className="text-4xl font-bold leading-tight text-white">
            Security-first
            <br />
            document sharing
            <br />
            <span className="text-brand-400">you can trust.</span>
          </h1>

          <div className="space-y-5 text-surface-200/80">
            <div className="flex items-center gap-3">
              <Lock className="h-5 w-5 text-brand-400" />
              <span className="text-sm">
                Server-side access control for private documents
              </span>
            </div>
            <div className="flex items-center gap-3">
              <FileCheck className="h-5 w-5 text-brand-400" />
              <span className="text-sm">
                Tamper-evident SHA-256 audit trail
              </span>
            </div>
            <div className="flex items-center gap-3">
              <Users className="h-5 w-5 text-brand-400" />
              <span className="text-sm">
                Per-document permissions and access revocation
              </span>
            </div>
            <div className="flex items-center gap-3">
              <Activity className="h-5 w-5 text-brand-400" />
              <span className="text-sm">
                Auditable security events
              </span>
            </div>
            <div className="flex items-center gap-3">
              <Database className="h-5 w-5 text-emerald-400" />
              <span className="text-sm">
                Connected to MongoDB Atlas (<span className="text-emerald-400 font-mono text-xs">Cluster0</span>)
              </span>
            </div>
          </div>
        </div>

        <p className="relative z-10 text-xs text-surface-200/40">
          © 2026 TrustVault. Security by design.
        </p>
      </section>

      <section className="flex flex-1 items-center justify-center p-5 sm:p-10">
        <div className="w-full max-w-md">
          <div className="mb-8 flex items-center gap-3 lg:hidden">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-brand-600">
              <Shield className="h-6 w-6 text-white" />
            </div>
            <span className="text-2xl font-bold">TrustVault</span>
          </div>

          <div className="mb-7">
            <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full text-xs font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 mb-3">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
              <Database className="w-3.5 h-3.5" />
              <span>MongoDB Atlas Connected</span>
            </div>
            <h2 className="text-3xl font-bold tracking-tight">
              {mode === "login" ? "Welcome back" : "Create your account"}
            </h2>
            <p className="mt-2 text-sm text-[var(--muted)]">
              {mode === "login"
                ? "Sign in to access your secure documents."
                : "Create an account to get started with TrustVault."}
            </p>
          </div>

          <div className="mb-6 grid grid-cols-2 rounded-xl border border-[var(--card-border)] p-1">
            <button
              type="button"
              onClick={() => chooseMode("login")}
              className={`rounded-lg px-4 py-2.5 text-sm font-semibold transition ${
                mode === "login"
                  ? "bg-brand-600 text-white"
                  : "text-[var(--muted)] hover:text-[var(--foreground)]"
              }`}
            >
              <Lock className="mr-2 inline h-4 w-4" />
              Login
            </button>
            <button
              type="button"
              onClick={() => chooseMode("register")}
              className={`rounded-lg px-4 py-2.5 text-sm font-semibold transition ${
                mode === "register"
                  ? "bg-brand-600 text-white"
                  : "text-[var(--muted)] hover:text-[var(--foreground)]"
              }`}
            >
              <UserPlus className="mr-2 inline h-4 w-4" />
              Register
            </button>
          </div>

          {error && (
            <div
              role="alert"
              className="mb-4 rounded-lg border border-danger/30 bg-danger/10 p-3 text-sm text-danger"
            >
              {error}
            </div>
          )}

          {message && (
            <div
              role="status"
              className="mb-4 rounded-lg border border-brand-500/30 bg-brand-500/10 p-3 text-sm"
            >
              {message}
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            {mode === "register" && (
              <div>
                <label
                  htmlFor="full-name"
                  className="mb-1.5 block text-sm font-medium text-[var(--muted)]"
                >
                  Full name
                </label>
                <input
                  id="full-name"
                  type="text"
                  className="input"
                  placeholder="Your full name"
                  autoComplete="name"
                  value={name}
                  onChange={(event) => setName(event.target.value)}
                  required
                  maxLength={100}
                />
              </div>
            )}

            <div>
              <label
                htmlFor="email"
                className="mb-1.5 block text-sm font-medium text-[var(--muted)]"
              >
                Email address
              </label>
              <input
                id="email"
                type="email"
                className="input"
                placeholder="you@example.com"
                autoComplete="email"
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                required
                maxLength={254}
              />
            </div>

            <div>
              <label
                htmlFor="password"
                className="mb-1.5 block text-sm font-medium text-[var(--muted)]"
              >
                Password
              </label>
              <div className="relative">
                <input
                  id="password"
                  type={showPassword ? "text" : "password"}
                  className="input pr-11"
                  placeholder="Enter your password"
                  autoComplete={
                    mode === "login" ? "current-password" : "new-password"
                  }
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  required
                  maxLength={200}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword((current) => !current)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-[var(--muted)]"
                  aria-label={showPassword ? "Hide password" : "Show password"}
                >
                  {showPassword ? (
                    <EyeOff className="h-4 w-4" />
                  ) : (
                    <Eye className="h-4 w-4" />
                  )}
                </button>
              </div>
            </div>

            {mode === "register" && (
              <div>
                <label
                  htmlFor="confirm-password"
                  className="mb-1.5 block text-sm font-medium text-[var(--muted)]"
                >
                  Confirm password
                </label>
                <input
                  id="confirm-password"
                  type={showPassword ? "text" : "password"}
                  className="input"
                  placeholder="Enter your password again"
                  autoComplete="new-password"
                  value={confirmPassword}
                  onChange={(event) => setConfirmPassword(event.target.value)}
                  required
                  maxLength={200}
                />
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="btn btn-primary btn-lg mt-2 w-full"
            >
              {loading ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Please wait...
                </>
              ) : (
                <>
                  {mode === "login" ? "Continue to TrustVault" : "Create account"}
                  <ArrowRight className="h-4 w-4" />
                </>
              )}
            </button>
          </form>

          {mode === "login" && (
            <div className="mt-8">
              <div className="mb-4 flex items-center gap-3">
                <div className="h-px flex-1 bg-[var(--card-border)]" />
                <span className="text-xs font-medium uppercase tracking-wider text-[var(--muted)]">
                  Try a demo account
                </span>
                <div className="h-px flex-1 bg-[var(--card-border)]" />
              </div>

              <div className="space-y-3">
                {DEMO_ACCOUNTS.map((account) => (
                  <button
                    key={account.email}
                    type="button"
                    onClick={() => fillDemo(account)}
                    className="group flex w-full items-center gap-3 rounded-xl border border-[var(--card-border)] p-3 text-left transition hover:border-brand-500/50 hover:bg-brand-500/5"
                  >
                    <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-brand-500/10 text-sm font-bold text-brand-400">
                      {account.role.charAt(0)}
                    </div>

                    <div className="min-w-0 flex-1">
                      <div className="text-sm font-semibold group-hover:text-brand-400">
                        {account.role}
                      </div>
                      <div className="truncate text-xs text-[var(--muted)]">
                        {account.email}
                      </div>
                      <div className="mt-1 text-xs text-[var(--muted)]">
                        {account.description}
                      </div>
                    </div>

                    <ArrowRight className="h-4 w-4 shrink-0 text-[var(--muted)] transition group-hover:translate-x-1 group-hover:text-brand-400" />
                  </button>
                ))}
              </div>

              <div className="mt-4 rounded-lg border border-[var(--card-border)] p-3">
                <p className="text-xs font-semibold text-[var(--muted)]">
                  Shared demo password
                </p>
                <p className="mt-1 break-all font-mono text-sm">
                  {DEMO_PASSWORD}
                </p>
                <p className="mt-2 text-xs text-[var(--muted)]">
                  Click any demo account to fill both fields, then continue.
                </p>
              </div>
            </div>
          )}

          <p className="mt-6 text-center text-xs text-[var(--muted)]">
            {mode === "login"
              ? "Protected access. Every session is verified by the server."
              : "New accounts must receive their permissions from the server."}
          </p>
        </div>
      </section>
    </main>
  );
}
