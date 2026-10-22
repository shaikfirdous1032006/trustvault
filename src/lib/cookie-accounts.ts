import { createHmac } from "crypto";
import type { NextRequest, NextResponse } from "next/server";
import type { User } from "@/lib/types";

const COOKIE_NAME = "tv_accounts";
const SECRET = process.env.SESSION_SECRET || "e7cb79cf640dd4e9f5d7d69964b93113c839db6ff18ae6a939986c437409225a";

export interface StoredAccount {
  user: User;
  salt: string;
  hash: string;
}

function sign(payload: string): string {
  const hmac = createHmac("sha256", SECRET).update(payload).digest("hex");
  return `${Buffer.from(payload, "utf8").toString("base64url")}.${hmac}`;
}

function verify(token: string): string | null {
  const parts = token.split(".");
  if (parts.length !== 2) return null;
  const [b64, signature] = parts;
  try {
    const raw = Buffer.from(b64, "base64url").toString("utf8");
    const expected = createHmac("sha256", SECRET).update(raw).digest("hex");
    if (signature === expected) {
      return raw;
    }
  } catch {
    // ignore
  }
  return null;
}

export function getRegisteredAccounts(request: NextRequest): StoredAccount[] {
  const cookieVal = request.cookies.get(COOKIE_NAME)?.value;
  if (!cookieVal) return [];

  const raw = verify(cookieVal);
  if (!raw) return [];

  try {
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) return parsed as StoredAccount[];
  } catch {
    // ignore
  }
  return [];
}

export function findCookieAccount(
  request: NextRequest,
  email: string
): StoredAccount | undefined {
  const accounts = getRegisteredAccounts(request);
  const target = email.trim().toLowerCase();
  return accounts.find((a) => a.user.email.toLowerCase() === target);
}

export function appendCookieAccount(
  request: NextRequest,
  response: NextResponse,
  account: StoredAccount
): void {
  const existing = getRegisteredAccounts(request).filter(
    (a) => a.user.email.toLowerCase() !== account.user.email.toLowerCase()
  );
  existing.push(account);

  const signed = sign(JSON.stringify(existing));
  response.cookies.set(COOKIE_NAME, signed, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
    maxAge: 60 * 60 * 24 * 365, // 1 year
  });
}
