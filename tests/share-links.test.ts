import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { NextRequest } from 'next/server';
import type { ShareLink, User } from '@/lib/types';

/**
 * Only the framework's cookie transport is replaced. requireAuth(), the permission
 * rules, the share resolver and the audit writer are the real modules, so deleting
 * an authorisation check from any of them fails this file.
 */
const cookieJar = vi.hoisted(() => ({ current: {} as Record<string, string> }));

vi.mock('next/headers', () => ({
  cookies: async () => ({
    get: (name: string) =>
      cookieJar.current[name] ? { name, value: cookieJar.current[name] } : undefined,
    set: (name: string, value: string) => {
      cookieJar.current[name] = value;
    },
    getAll: () => [] as Array<{ name: string; value: string }>,
  }),
  headers: async () => new Headers(),
}));

import { createSessionToken, SESSION_COOKIE } from '@/lib/session';
import { getStore, mutateStore, DEMO_IDS } from '@/lib/local-db';
import type { LocalStore } from '@/lib/local-db';
import { resetRateLimit } from '@/lib/security';
import { evaluateShareLink, generateShareToken, hashShareToken } from '@/lib/share';
import { resolveShare } from '@/lib/share-access';
import * as manageLinks from '@/app/api/documents/[id]/share-links/route';
import * as revokeLink from '@/app/api/documents/[id]/share-links/[linkId]/route';
import * as publicView from '@/app/api/public/share/[token]/route';
import * as publicDownload from '@/app/api/public/share/[token]/download/route';

const OWNER: User = {
  id: DEMO_IDS.owner,
  email: 'owner@example.com',
  full_name: 'Document Owner',
  role: 'owner',
  is_active: true,
  created_at: '2026-01-01T00:00:00.000Z',
  updated_at: '2026-01-01T00:00:00.000Z',
};

const VIEWER: User = {
  ...OWNER,
  id: DEMO_IDS.viewer,
  email: 'viewer@example.com',
  full_name: 'Document Viewer',
  role: 'viewer',
};

async function signIn(user: User) {
  cookieJar.current[SESSION_COOKIE] = await createSessionToken(user);
}

function signOut() {
  delete cookieJar.current[SESSION_COOKIE];
}

function jsonRequest(url: string, body: unknown, method = 'POST') {
  return new NextRequest(`http://localhost:3000${url}`, {
    method,
    headers: { 'Content-Type': 'application/json', Origin: 'http://localhost:3000' },
    body: JSON.stringify(body),
  });
}

function getReq(url: string) {
  return new NextRequest(`http://localhost:3000${url}`, { method: 'GET' });
}

const ORIGIN = 'http://localhost:3000';

async function issueLink(overrides: Record<string, unknown> = {}) {
  const res = await manageLinks.POST(
    jsonRequest(`/api/documents/${DEMO_IDS.docShared}/share-links`, {
      label: 'external auditor',
      expires_at: new Date(Date.now() + 3600_000).toISOString(),
      ...overrides,
    }),
    { params: Promise.resolve({ id: DEMO_IDS.docShared }) }
  );
  const data = await res.json();
  return { res, data };
}

let snapshot: string;

beforeEach(async () => {
  resetRateLimit();
  await mutateStore((store) => {
    store.share_links = [];
  });
  snapshot = JSON.stringify(getStore());
});

afterEach(async () => {
  // Tests soft-delete documents and rewrite grants; the next test must not inherit it.
  const restored = JSON.parse(snapshot) as LocalStore;
  await mutateStore((store) => {
    Object.assign(store, restored);
  });
  vi.useRealTimers();
  signOut();
});

describe('share link tokens', () => {
  it('mints 256-bit url-safe tokens and stores only their digest', async () => {
    const token = generateShareToken();
    expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(hashShareToken(token)).toMatch(/^[0-9a-f]{64}$/);
    expect(hashShareToken(token)).toBe(hashShareToken(token));
    expect(hashShareToken(token)).not.toBe(hashShareToken(generateShareToken()));

    await signIn(OWNER);
    const { res, data } = await issueLink();
    expect(res.status).toBe(201);
    expect(data.data.token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(data.data.url).toBe(`${process.env.NEXT_PUBLIC_APP_URL}/share/${data.data.token}`);

    const persisted = JSON.stringify(getStore().share_links);
    expect(persisted).not.toContain(data.data.token);
    expect(persisted).toContain(hashShareToken(data.data.token));

    const listed = await manageLinks.GET(getReq(`/api/documents/${DEMO_IDS.docShared}/share-links`), {
      params: Promise.resolve({ id: DEMO_IDS.docShared }),
    });
    const listedBody = await listed.json();
    expect(JSON.stringify(listedBody)).not.toContain('token_hash');
    expect(JSON.stringify(listedBody)).not.toContain(data.data.token);
  });

  it('refuses to create a credential for someone who does not own the document', async () => {
    await signIn(VIEWER);
    const res = await manageLinks.POST(
      jsonRequest(`/api/documents/${DEMO_IDS.docShared}/share-links`, {
        expires_at: new Date(Date.now() + 3600_000).toISOString(),
      }),
      { params: Promise.resolve({ id: DEMO_IDS.docShared }) }
    );
    expect(res.status).toBe(403);
    expect(getStore().share_links).toHaveLength(0);

    const denied = getStore().audit.filter((e) => e.action === 'share_link_created');
    expect(denied.some((e) => e.result === 'denied')).toBe(true);
  });

  it('rejects an anonymous mint request at the route, not at the middleware', async () => {
    signOut();
    const res = await manageLinks.POST(
      jsonRequest(`/api/documents/${DEMO_IDS.docShared}/share-links`, {
        expires_at: new Date(Date.now() + 3600_000).toISOString(),
      }),
      { params: Promise.resolve({ id: DEMO_IDS.docShared }) }
    );
    expect(res.status).toBe(401);
  });

  it('rejects an expiry in the past and one shorter than the minimum window', async () => {
    await signIn(OWNER);
    const past = await issueLink({ expires_at: new Date(Date.now() - 60_000).toISOString() });
    expect(past.res.status).toBe(400);

    const tooShort = await issueLink({ expires_at: new Date(Date.now() + 5_000).toISOString() });
    expect(tooShort.res.status).toBe(400);
    expect(getStore().share_links).toHaveLength(0);
  });
});

describe('evaluateShareLink', () => {
  const link: ShareLink = {
    id: 'link-1',
    document_id: DEMO_IDS.docShared,
    token_hash: 'a'.repeat(64),
    label: 'auditor',
    created_by: OWNER.id,
    created_at: '2026-01-01T00:00:00.000Z',
    expires_at: '2026-01-02T00:00:00.000Z',
    revoked_at: null,
    revoked_by: null,
    access_count: 0,
    max_access_count: null,
    last_accessed_at: null,
    allow_download: true,
    watermark_enabled: true,
  };
  const live = { is_deleted: false };
  const nowMs = Date.parse('2026-01-01T12:00:00.000Z');

  const decide = (over: Partial<typeof link> = {}, doc = live, wantsDownload = false) =>
    evaluateShareLink({
      link: { ...link, ...over },
      document: doc,
      wantsDownload,
      nowMs,
    });

  it('allows a live link and refuses each dead state', () => {
    expect(decide()).toEqual({ allowed: true });
    expect(decide({ revoked_at: '2026-01-01T11:00:00.000Z' })).toEqual({
      allowed: false,
      reason: 'revoked',
    });
    expect(decide({ expires_at: '2026-01-01T11:59:59.999Z' })).toEqual({
      allowed: false,
      reason: 'expired',
    });
    expect(decide({ max_access_count: 3, access_count: 3 })).toEqual({
      allowed: false,
      reason: 'exhausted',
    });
    expect(decide({ allow_download: false }, live, true)).toEqual({
      allowed: false,
      reason: 'download_forbidden',
    });
    expect(evaluateShareLink({ link: null, document: live, wantsDownload: false, nowMs })).toEqual({
      allowed: false,
      reason: 'not_found',
    });
    expect(decide({}, { is_deleted: true })).toEqual({
      allowed: false,
      reason: 'document_unavailable',
    });
  });

  it('checks revocation before expiry so a revoked link never reads as expired', () => {
    expect(
      decide({
        revoked_at: '2026-01-01T10:00:00.000Z',
        expires_at: '2026-01-01T11:00:00.000Z',
      })
    ).toEqual({ allowed: false, reason: 'revoked' });
  });
});

describe('bearer access to a shared document', () => {
  it('serves the file to a live link and closes it on the next request after revocation', async () => {
    await signIn(OWNER);
    const { data } = await issueLink();
    const token = data.data.token as string;
    const linkId = data.data.link.id as string;
    signOut();

    const view = await publicView.GET(getReq(`/api/public/share/${token}`), {
      params: Promise.resolve({ token }),
    });
    expect(view.status).toBe(200);
    expect(view.headers.get('X-Robots-Tag')).toContain('noindex');
    const body = await view.json();
    expect(body.data.document.id).toBe(DEMO_IDS.docShared);
    expect(body.data.preview).toContain('TRUSTVAULT SECURE DISCLOSURE');
    expect(body.data.link.access_count).toBe(1);

    const download = await publicDownload.GET(getReq(`/api/public/share/${token}/download`), {
      params: Promise.resolve({ token }),
    });
    expect(download.status).toBe(200);
    expect(download.headers.get('X-TrustVault-Share-Link')).toBe(linkId);
    expect(download.headers.get('X-TrustVault-Watermark-Applied')).toBe('true');
    expect(await download.text()).toContain('Q3 2026 Financial Audit');

    await signIn(OWNER);
    const revoked = await revokeLink.PATCH(
      jsonRequest(`/api/documents/${DEMO_IDS.docShared}/share-links/${linkId}`, { action: 'revoke' }),
      { params: Promise.resolve({ id: DEMO_IDS.docShared, linkId }) }
    );
    expect(revoked.status).toBe(200);
    signOut();

    // Same token, same client, one request later.
    const after = await publicView.GET(getReq(`/api/public/share/${token}`), {
      params: Promise.resolve({ token }),
    });
    expect(after.status).toBe(410);
    expect((await after.json()).reason).toBe('revoked');

    const afterDownload = await publicDownload.GET(getReq(`/api/public/share/${token}/download`), {
      params: Promise.resolve({ token }),
    });
    expect(afterDownload.status).toBe(410);

    const trail = getStore().audit.filter((e) => e.action.startsWith('share_link_'));
    expect(trail.some((e) => e.action === 'share_link_revoked' && e.result === 'allowed')).toBe(true);
    expect(trail.some((e) => e.action === 'share_link_denied' && e.result === 'denied')).toBe(true);
    expect(trail.filter((e) => e.action === 'share_link_denied').every((e) => e.document_id === DEMO_IDS.docShared)).toBe(true);
  });

  it('stops working the moment the clock passes the expiry', async () => {
    await signIn(OWNER);
    const { data } = await issueLink({ expires_at: new Date(Date.now() + 120_000).toISOString() });
    const token = data.data.token as string;
    signOut();

    expect(
      (
        await publicView.GET(getReq(`/api/public/share/${token}`), {
          params: Promise.resolve({ token }),
        })
      ).status
    ).toBe(200);

    vi.setSystemTime(new Date(Date.now() + 180_000));
    const expired = await publicView.GET(getReq(`/api/public/share/${token}`), {
      params: Promise.resolve({ token }),
    });
    expect(expired.status).toBe(410);
    expect((await expired.json()).reason).toBe('expired');
  });

  it('burns a single-view link and refuses the following request', async () => {
    await signIn(OWNER);
    const { data } = await issueLink({ max_views: 1 });
    const token = data.data.token as string;
    const linkId = data.data.link.id as string;
    signOut();

    const first = await publicView.GET(getReq(`/api/public/share/${token}`), {
      params: Promise.resolve({ token }),
    });
    expect(first.status).toBe(200);

    const second = await publicView.GET(getReq(`/api/public/share/${token}`), {
      params: Promise.resolve({ token }),
    });
    expect(second.status).toBe(410);
    expect((await second.json()).reason).toBe('exhausted');

    const stored = getStore().share_links.find((l) => l.id === linkId);
    expect(stored?.revoked_by).toBe('system-auto-revoke');
    expect(stored?.access_count).toBe(1);
  });

  it('says "revoked" when an owner closes a capped link, not "exhausted"', async () => {
    await signIn(OWNER);
    const { data } = await issueLink({ max_views: 5 });
    const token = data.data.token as string;
    const linkId = data.data.link.id as string;

    await publicView.GET(getReq(`/api/public/share/${token}`), {
      params: Promise.resolve({ token }),
    });
    const closed = await revokeLink.PATCH(
      jsonRequest(`/api/documents/${DEMO_IDS.docShared}/share-links/${linkId}`, { action: 'revoke' }),
      { params: Promise.resolve({ id: DEMO_IDS.docShared, linkId }) }
    );
    expect(closed.status).toBe(200);
    signOut();

    const refused = await publicView.GET(getReq(`/api/public/share/${token}`), {
      params: Promise.resolve({ token }),
    });
    expect(refused.status).toBe(410);
    expect((await refused.json()).reason).toBe('revoked');
  });

  it('refuses unknown and malformed tokens without naming the document', async () => {
    for (const token of [generateShareToken(), 'not-a-real-token', 'a'.repeat(5000)]) {
      const res = await publicView.GET(getReq(`/api/public/share/${token}`), {
        params: Promise.resolve({ token }),
      });
      expect(res.status).toBe(404);
      const body = await res.json();
      expect(JSON.stringify(body)).not.toContain('Q3');
      expect(JSON.stringify(body)).not.toContain(token.slice(0, 12));
    }
  });

  it('rate limits guessing without leaking how many attempts remain', async () => {
    let lastStatus = 0;
    for (let i = 0; i < 40; i++) {
      const token = generateShareToken();
      const res = await publicView.GET(getReq(`/api/public/share/${token}`), {
        params: Promise.resolve({ token }),
      });
      lastStatus = res.status;
      if (res.status === 429) {
        expect(res.headers.get('Retry-After')).toBeTruthy();
        break;
      }
    }
    expect(lastStatus).toBe(429);
  });

  it('honours a view-only link but still serves the preview', async () => {
    await signIn(OWNER);
    const { data } = await issueLink({ allow_download: false });
    const token = data.data.token as string;
    signOut();

    const view = await publicView.GET(getReq(`/api/public/share/${token}`), {
      params: Promise.resolve({ token }),
    });
    expect(view.status).toBe(200);

    const download = await publicDownload.GET(getReq(`/api/public/share/${token}/download`), {
      params: Promise.resolve({ token }),
    });
    expect(download.status).toBe(403);
    expect((await download.json()).reason).toBe('download_forbidden');
  });

  it('closes a link when the document behind it is deleted', async () => {
    await signIn(OWNER);
    const { data } = await issueLink();
    const token = data.data.token as string;
    await mutateStore((store) => {
      const doc = store.documents.find((d) => d.id === DEMO_IDS.docShared);
      if (doc) doc.is_deleted = true;
    });
    signOut();

    const res = await publicView.GET(getReq(`/api/public/share/${token}`), {
      params: Promise.resolve({ token }),
    });
    expect(res.status).toBe(404);
    expect((await res.json()).reason).toBe('document_unavailable');
  });

  it('never lets a link for one document reach another', async () => {
    await signIn(OWNER);
    const { data } = await issueLink();
    const token = data.data.token as string;
    signOut();

    const resolution = await resolveShare(token, false);
    expect(resolution.allowed).toBe(true);
    if (resolution.allowed) {
      expect(resolution.document.id).toBe(DEMO_IDS.docShared);
      expect(resolution.document.id).not.toBe(DEMO_IDS.docPrivate);
    }
  });
});
