import type { User, UserRole } from '@/lib/types';

export const SESSION_COOKIE = 'tv_session';

type SessionPayload = {
  id: string;
  email: string;
  role: UserRole;
  full_name: string | null;
  is_active: boolean;
  iat: number;
  exp: number;
};

function getSecret(): string {
  return process.env.SESSION_SECRET || 'trustvault-local-dev-only-change-me';
}

function toHex(buffer: ArrayBuffer): string {
  return [...new Uint8Array(buffer)]
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

async function hmacSha256(message: string, secret: string): Promise<string> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(message));
  return toHex(sig);
}

function b64urlEncode(value: string): string {
  const bytes = new TextEncoder().encode(value);
  let binary = '';
  bytes.forEach((b) => {
    binary += String.fromCharCode(b);
  });
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function b64urlDecode(value: string): string {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/');
  const pad = padded.length % 4 === 0 ? '' : '='.repeat(4 - (padded.length % 4));
  const binary = atob(padded + pad);
  const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

export async function createSessionToken(user: {
  id: string;
  email: string;
  role: UserRole;
  full_name: string | null;
  is_active?: boolean;
}): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const payload: SessionPayload = {
    id: user.id,
    email: user.email,
    role: user.role,
    full_name: user.full_name,
    is_active: user.is_active !== false,
    iat: now,
    exp: now + 60 * 60 * 24,
  };
  const body = b64urlEncode(JSON.stringify(payload));
  const sig = await hmacSha256(body, getSecret());
  return `${body}.${sig}`;
}

export async function verifySessionToken(token: string | undefined | null): Promise<User | null> {
  if (!token) return null;
  const [body, sig] = token.split('.');
  if (!body || !sig) return null;

  const expected = await hmacSha256(body, getSecret());
  if (expected.length !== sig.length) return null;

  let mismatch = 0;
  for (let i = 0; i < expected.length; i++) {
    mismatch |= expected.charCodeAt(i) ^ sig.charCodeAt(i);
  }
  if (mismatch !== 0) return null;

  try {
    const payload = JSON.parse(b64urlDecode(body)) as SessionPayload;
    if (payload.exp < Math.floor(Date.now() / 1000)) return null;
    return {
      id: payload.id,
      email: payload.email,
      role: payload.role,
      full_name: payload.full_name,
      is_active: payload.is_active,
      created_at: new Date(payload.iat * 1000).toISOString(),
      updated_at: new Date(payload.iat * 1000).toISOString(),
    };
  } catch {
    return null;
  }
}
