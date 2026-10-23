import { describe, it, expect, vi, beforeEach } from 'vitest';
import { NextRequest } from 'next/server';
import type { User } from '@/lib/types';
import { getStore, DEMO_IDS } from '@/lib/local-db';
import { createSessionToken, SESSION_COOKIE } from '@/lib/session';

const cookieJar = vi.hoisted(() => ({ current: {} as Record<string, string> }));

vi.mock('next/headers', () => ({
  cookies: async () => ({
    get: (name: string) =>
      cookieJar.current[name] ? { name, value: cookieJar.current[name] } : undefined,
    set: (name: string, value: string) => {
      cookieJar.current[name] = value;
    },
    getAll: () => [],
  }),
  headers: async () => new Headers({ 'x-forwarded-for': '203.0.113.9', 'user-agent': 'Vitest-Preview' }),
}));

import { GET as previewRoute } from '@/app/api/documents/[id]/preview/route';

const SHARED = DEMO_IDS.docShared;
const PRIVATE = DEMO_IDS.docPrivate;

function userByEmail(email: string): User {
  const user = getStore().users.find((u) => u.email === email);
  if (!user) throw new Error(`Missing user ${email}`);
  return user;
}

const OWNER = () => userByEmail('owner@example.com');
const VIEWER = () => userByEmail('viewer@example.com');
const ADMIN = () => userByEmail('admin@example.com');

async function signIn(user: User) {
  cookieJar.current[SESSION_COOKIE] = await createSessionToken(user);
}

function signOut() {
  delete cookieJar.current[SESSION_COOKIE];
}

describe('Document Preview & Zero-Leak Streaming', () => {
  beforeEach(() => {
    signOut();
  });

  it('rejects preview if unauthenticated', async () => {
    const req = new NextRequest(`http://localhost:3000/api/documents/${SHARED}/preview`);
    const res = await previewRoute(req, {
      params: Promise.resolve({ id: SHARED }),
    });
    expect(res.status).toBe(401);
  });

  it('allows document owner to preview document inline', async () => {
    await signIn(OWNER());
    const req = new NextRequest(`http://localhost:3000/api/documents/${PRIVATE}/preview`);
    const res = await previewRoute(req, {
      params: Promise.resolve({ id: PRIVATE }),
    });

    expect(res.status).toBe(200);
    expect(res.headers.get('Content-Disposition')).toContain('inline');
    expect(res.headers.get('X-Content-Type-Options')).toBe('nosniff');
  });

  it('rejects preview if user has no permission to private document', async () => {
    await signIn(VIEWER());
    const req = new NextRequest(`http://localhost:3000/api/documents/${PRIVATE}/preview`);
    const res = await previewRoute(req, {
      params: Promise.resolve({ id: PRIVATE }),
    });

    expect(res.status).toBe(403);
  });

  it('allows viewer with granted permission to preview shared document', async () => {
    await signIn(VIEWER());
    const req = new NextRequest(`http://localhost:3000/api/documents/${SHARED}/preview`);
    const res = await previewRoute(req, {
      params: Promise.resolve({ id: SHARED }),
    });

    expect(res.status).toBe(200);
    expect(res.headers.get('Content-Disposition')).toContain('inline');
  });

  it('returns 403 or 404 for non-existent document preview', async () => {
    await signIn(ADMIN());
    const req = new NextRequest(`http://localhost:3000/api/documents/non-existent-id/preview`);
    const res = await previewRoute(req, {
      params: Promise.resolve({ id: 'non-existent-id' }),
    });

    expect([403, 404]).toContain(res.status);
  });

  it('logs preview audit event with document details', async () => {
    await signIn(OWNER());
    const initialLogsCount = getStore().audit.length;

    const req = new NextRequest(`http://localhost:3000/api/documents/${PRIVATE}/preview`);
    const res = await previewRoute(req, {
      params: Promise.resolve({ id: PRIVATE }),
    });

    expect(res.status).toBe(200);
    const logs = getStore().audit;
    expect(logs.length).toBeGreaterThan(initialLogsCount);

    const latest = logs[logs.length - 1];
    expect(latest.action).toBe('preview');
    expect(latest.document_id).toBe(PRIVATE);
    expect(latest.result).toBe('allowed');
  });
});
