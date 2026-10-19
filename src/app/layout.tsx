import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "TrustVault — Secure Document Sharing",
  description:
    "Enterprise-grade document sharing platform with tamper-evident audit trail, role-based access control, and end-to-end security.",
  keywords: ["document sharing", "security", "audit trail", "enterprise"],
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark h-full antialiased">
      <body className="min-h-full flex flex-col bg-[var(--background)] text-[var(--foreground)] font-sans">
        {children}
      </body>
    </html>
  );
}
