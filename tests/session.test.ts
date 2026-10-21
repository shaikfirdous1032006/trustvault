import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  createSessionToken,
  verifySessionToken,
  SessionConfigError,
  SESSION_COOKIE,
} from '@/lib/session';
import type { UserRole } from '@/lib/types';

const SECRET_A = 'a'.repeat(64);
const SECRET_B = 'b'.repeat(64);

function user(role: UserRole = 'viewer') {
  return {
    id: `usr-${role}-test`,
    email: `${role}@example.com`,
    role,
    full_name: 'Test Subject',
    is_active: true,
  };
}

describe('session signing key', () => {
  const originalSecret = process.env.SESSION_SECRET;

  afterEach(() => {
    vi.unstubAllEnvs();
    if (originalSecret === undefined) Reflect.deleteProperty(process.env, 'SESSION_SECRET');
    else process.env.SESSION_SECRET = originalSecret;
    vi.useRealTimers();
  });

  it('round-trips a token signed with the configured secret', async () => {
    process.env.SESSION_SECRET = SECRET_A;
    const token = await createSessionToken(user('owner'));
    const verified = await verifySessionToken(token);

    expect(verified?.id).toBe('usr-owner-test');
    expect(verified?.role).toBe('owner');
  });

  it('rejects a token signed with a different key', async () => {
    process.env.SESSION_SECRET = SECRET_A;
    const token = await createSessionToken(user('admin'));

    process.env.SESSION_SECRET = SECRET_B;
    expect(await verifySessionToken(token)).toBeNull();
  });

  it('rejects a token signed with the previously committed fallback value', async () => {
    // Regression guard: this literal was hard-coded in src/lib/session.ts and
    // let anyone with repository access mint an admin session.
    process.env.SESSION_SECRET = SECRET_A;
    const forged = await signWith('trustvault-local-dev-only-change-me', {
      id: 'usr-admin-demo-001',
      email: 'admin@example.com',
      role: 'admin',
      full_name: 'Forged',
      is_active: true,
    });

    expect(await verifySessionToken(forged)).toBeNull();
  });

  it('rejects a token whose payload was altered after signing', async () => {
    process.env.SESSION_SECRET = SECRET_A;
    const token = await createSessionToken(user('viewer'));
    const [body, sig] = token.split('.');

    const escalated = JSON.parse(Buffer.from(body, 'base64url').toString());
    escalated.role = 'admin';
    const tamperedBody = Buffer.from(JSON.stringify(escalated)).toString('base64url');

    expect(await verifySessionToken(`${tamperedBody}.${sig}`)).toBeNull();
  });

  it('rejects an expired token', async () => {
    process.env.SESSION_SECRET = SECRET_A;
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-01-01T00:00:00Z'));

    const token = await createSessionToken(user('owner'));

    vi.setSystemTime(new Date('2026-01-03T00:00:00Z'));
    expect(await verifySessionToken(token)).toBeNull();
  });

  it('refuses to sign when SESSION_SECRET is shorter than the minimum', async () => {
    process.env.SESSION_SECRET = 'too-short';
    await expect(createSessionToken(user())).rejects.toBeInstanceOf(SessionConfigError);
  });

  it('refuses to sign in production when SESSION_SECRET is absent', async () => {
    Reflect.deleteProperty(process.env, 'SESSION_SECRET');
    vi.stubEnv('NODE_ENV', 'production');
    await expect(createSessionToken(user())).rejects.toBeInstanceOf(SessionConfigError);
  });

  it('fails closed to unauthenticated rather than throwing when production has no key', async () => {
    process.env.SESSION_SECRET = SECRET_A;
    const token = await createSessionToken(user('admin'));

    Reflect.deleteProperty(process.env, 'SESSION_SECRET');
    vi.stubEnv('NODE_ENV', 'production');

    expect(await verifySessionToken(token)).toBeNull();
  });

  it('names the cookie the middleware and routes agree on', () => {
    expect(SESSION_COOKIE).toBe('tv_session');
  });
});

async function signWith(
  secret: string,
  payload: Record<string, unknown>
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const body = Buffer.from(
    JSON.stringify({ ...payload, iat: now, exp: now + 86400 })
  ).toString('base64url');
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(body));
  const hex = [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, '0')).join('');
  return `${body}.${hex}`;
}
