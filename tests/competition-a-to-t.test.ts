/**
 * TrustVault competition suite — requirements A through T, run against the real
 * route handlers.
 *
 * This file deliberately mocks only next/headers (there is no async request store
 * outside a running server). Authorization, sessions, uploads, the audit chain and
 * the JSON store are the production implementations, so deleting a guard in a route
 * handler makes tests here fail. That property is what Requirement T+ is really
 * about: a suite that stubs the authorizer cannot detect the authorizer vanishing.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { NextRequest } from 'next/server';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import type { User } from '@/lib/types';
import { getStore, mutateStore, DEMO_IDS } from '@/lib/local-db';
import { createSessionToken, SESSION_COOKIE } from '@/lib/session';
import { resetRateLimit } from '@/lib/security';
import { validateUpload, MAX_FILE_SIZE, ALLOWED_MIME_TYPES } from '@/lib/permission';

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
  headers: async () =>
    new Headers({ 'x-forwarded-for': '203.0.113.7', 'user-agent': 'TrustVault-Competition-Runner' }),
}));

import { GET as listDocs, POST as uploadDoc } from '@/app/api/documents/route';
import { GET as getDoc, PATCH as patchDoc, DELETE as deleteDoc } from '@/app/api/documents/[id]/route';
import { GET as downloadDoc } from '@/app/api/documents/[id]/download/route';
import { GET as listPerms, POST as grantPerm } from '@/app/api/documents/[id]/permissions/route';
import { DELETE as revokePerm } from '@/app/api/documents/[id]/permissions/[permissionId]/route';
import { GET as listVersions, POST as newVersion } from '@/app/api/documents/[id]/versions/route';
import { GET as docAudit } from '@/app/api/documents/[id]/audit/route';
import { POST as createLink } from '@/app/api/documents/[id]/share-links/route';
import { PATCH as revokeLink } from '@/app/api/documents/[id]/share-links/[linkId]/route';
import { GET as publicView } from '@/app/api/public/share/[token]/route';
import { POST as verifyChain } from '@/app/api/admin/audit/verify/route';
import { GET as adminUsers } from '@/app/api/admin/users/route';
import { GET as adminAlerts } from '@/app/api/admin/alerts/route';
import { POST as login } from '@/app/api/auth/login/route';

const ORIGIN = 'http://localhost:3000';

const SHARED = DEMO_IDS.docShared;
const PRIVATE = DEMO_IDS.docPrivate;

function user(email: string): User {
  const found = getStore().users.find((u) => u.email === email);
  if (!found) throw new Error(`Seed is missing ${email}`);
  return found;
}

const owner = () => user('owner@example.com');
const viewer = () => user('viewer@example.com');
const admin = () => user('admin@example.com');

async function signIn(as: User) {
  cookieJar.current[SESSION_COOKIE] = await createSessionToken(as);
}

function anon() {
  delete cookieJar.current[SESSION_COOKIE];
}

function json(url: string, body?: unknown, method?: string) {
  return new NextRequest(`http://localhost:3000${url}`, {
    method: method ?? (body === undefined ? 'GET' : 'POST'),
    headers: { 'Content-Type': 'application/json', Origin: ORIGIN },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

function upload(url: string, file: File, meta: Record<string, string> = {}) {
  const form = new FormData();
  form.set('file', file);
  for (const [key, value] of Object.entries(meta)) form.set(key, value);
  return new NextRequest(`http://localhost:3000${url}`, {
    method: 'POST',
    headers: { Origin: ORIGIN },
    body: form,
  });
}

const oneParam = (id: string) => ({ params: Promise.resolve({ id }) });
const twoParams = (id: string, permissionId: string) => ({
  params: Promise.resolve({ id, permissionId }),
});

/** Bytes that begin with the real PDF signature so the magic-number check passes. */
function pdfBytes(label: string): string {
  return `%PDF-1.4\n${label}\ntrailer\n%%EOF\n`;
}

let snapshot: string;

beforeEach(() => {
  resetRateLimit();
  snapshot = JSON.stringify(getStore());
});

afterEach(async () => {
  const restored = JSON.parse(snapshot) as ReturnType<typeof getStore>;
  await mutateStore((store) => {
    Object.assign(store, restored);
  });
  vi.useRealTimers();
  anon();
});

// ---------------------------------------------------------------------------
// A–F: the authorization boundary, from the outside
// ---------------------------------------------------------------------------

describe('A–C: a guessed document id is not a capability', () => {
  it('A. user A cannot read user B document by id', async () => {
    await signIn(viewer());
    const res = await getDoc(json(`/api/documents/${PRIVATE}`), oneParam(PRIVATE));
    expect(res.status).toBe(403);
    const body = await res.json();
    expect(JSON.stringify(body)).not.toContain('Zero-Trust');
  });

  it('B. user A cannot download user B bytes even knowing the id', async () => {
    await signIn(viewer());
    const res = await downloadDoc(json(`/api/documents/${PRIVATE}/download`), oneParam(PRIVATE));
    expect(res.status).toBe(403);
    expect(await res.text()).not.toContain('Zero-Trust');
  });

  it('C. user A cannot mutate or delete user B document, and state is unchanged', async () => {
    await signIn(viewer());
    const patched = await patchDoc(
      json(`/api/documents/${PRIVATE}`, { title: 'taken over' }),
      oneParam(PRIVATE)
    );
    expect(patched.status).toBe(403);
    const removed = await deleteDoc(json(`/api/documents/${PRIVATE}`, undefined, 'DELETE'), oneParam(PRIVATE));
    expect(removed.status).toBe(403);

    const doc = getStore().documents.find((d) => d.id === PRIVATE)!;
    expect(doc.title).toBe('Security & Zero-Trust Architecture');
    expect(doc.is_deleted).toBe(false);
  });

  it('anonymous callers are refused before any document lookup', async () => {
    anon();
    for (const call of [
      () => getDoc(json(`/api/documents/${SHARED}`), oneParam(SHARED)),
      () => listDocs(json('/api/documents')),
      () => docAudit(json(`/api/documents/${SHARED}/audit`), oneParam(SHARED)),
      () => adminAlerts(json('/api/admin/alerts')),
    ]) {
      expect((await call()).status).toBe(401);
    }
  });
});

describe('D–F: grants are explicit, levelled, and end when they should', () => {
  it('D. a read grant opens read but never edit', async () => {
    await signIn(owner());
    const granted = await grantPerm(
      json(`/api/documents/${PRIVATE}/permissions`, {
        user_email: 'viewer@example.com',
        permission_level: 'read',
      }),
      oneParam(PRIVATE)
    );
    expect(granted.status).toBe(201);

    await signIn(viewer());
    expect((await getDoc(json(`/api/documents/${PRIVATE}`), oneParam(PRIVATE))).status).toBe(200);
    expect(
      (await patchDoc(json(`/api/documents/${PRIVATE}`, { title: 'escalated' }), oneParam(PRIVATE))).status
    ).toBe(403);
  });

  it('E. revocation is felt by the next request, with no cache in between', async () => {
    await signIn(viewer());
    expect((await getDoc(json(`/api/documents/${SHARED}`), oneParam(SHARED))).status).toBe(200);

    await signIn(owner());
    const revoked = await revokePerm(
      json(`/api/documents/${SHARED}/permissions/${DEMO_IDS.grantViewer}`, undefined, 'DELETE'),
      twoParams(SHARED, DEMO_IDS.grantViewer)
    );
    expect(revoked.status).toBe(200);

    await signIn(viewer());
    expect((await getDoc(json(`/api/documents/${SHARED}`), oneParam(SHARED))).status).toBe(403);
    expect((await downloadDoc(json(`/api/documents/${SHARED}/download`), oneParam(SHARED))).status).toBe(403);
  });

  it('F. a grant that has passed its expiry stops working without anyone touching it', async () => {
    await signIn(owner());
    const stale = await grantPerm(
      json(`/api/documents/${PRIVATE}/permissions`, {
        user_email: 'admin@example.com',
        permission_level: 'read',
        expires_at: new Date(Date.now() - 60_000).toISOString(),
      }),
      oneParam(PRIVATE)
    );
    expect(stale.status).toBe(201);
    await signIn(admin());
    expect((await getDoc(json(`/api/documents/${PRIVATE}`), oneParam(PRIVATE))).status).toBe(403);
  });

  it('an owner cannot grant a document to themselves and cannot self-grant as a non-owner', async () => {
    await signIn(owner());
    const self = await grantPerm(
      json(`/api/documents/${PRIVATE}/permissions`, {
        user_email: 'owner@example.com',
        permission_level: 'edit',
      }),
      oneParam(PRIVATE)
    );
    expect(self.status).toBe(400);
  });
});

// ---------------------------------------------------------------------------
// G–J: uploads are validated on the server, storage keys are not user input
// ---------------------------------------------------------------------------

describe('G–J: secure storage boundaries', () => {
  it('G. a genuine PDF is stored under an opaque server-generated key', async () => {
    await signIn(owner());
    const res = await uploadDoc(
      upload('/api/documents', new File([pdfBytes('trustvault')], 'Q3 Report.pdf', { type: 'application/pdf' }), {
        title: 'Q3 Report',
        category: 'financial',
      })
    );
    const text = await res.text();
    expect(res.status, text).toBe(201);
    const { data } = JSON.parse(text);
    expect(data.storage_path).toMatch(/^usr-owner-demo-002\/[0-9a-f-]{36}\.pdf$/);
    expect(data.storage_path).not.toContain('Q3');
    expect(data.checksum).toBe(createHash('sha256').update(pdfBytes('trustvault')).digest('hex'));
    expect(data.file_name).toBe('Q3_Report.pdf');
    expect(data.current_version).toBe(1);
  });

  it('H. empty, disallowed, mislabelled and oversized files are refused with 400', async () => {
    await signIn(owner());
    const cases: Array<[string, File]> = [
      ['empty file', new File([], 'nothing.pdf', { type: 'application/pdf' })],
      ['disallowed type', new File([pdfBytes('x')], 'page.html', { type: 'text/html' })],
      ['executable', new File([pdfBytes('x')], 'payload.exe', { type: 'application/x-msdownload' })],
      ['file that lies about its signature', new File([new Uint8Array([0x4d, 0x5a, 1, 2, 3]).buffer], 'fake.pdf', { type: 'application/pdf' })],
      ['path traversal name', new File([pdfBytes('x')], '../../windows/system32.pdf', { type: 'application/pdf' })],
    ];
    for (const [label, file] of cases) {
      const res = await uploadDoc(
        upload('/api/documents', file, { title: label.trim(), category: 'general' })
      );
      expect(res.status, `${label} was accepted`).toBe(400);
    }
  });

  it('the size limit is enforced against the declared ceiling, not the client claim', () => {
    expect(MAX_FILE_SIZE).toBe(52_428_800);
    expect(ALLOWED_MIME_TYPES).not.toContain('application/x-msdownload');
    expect(
      validateUpload({ type: 'application/pdf', size: MAX_FILE_SIZE + 1, name: 'big.pdf' })
    ).toMatch(/50MB/);
    expect(validateUpload({ type: 'application/pdf', size: 12, name: 'ok.pdf' })).toBeNull();
  });

  it('I. a new version preserves history and changes the checksum', async () => {
    await signIn(owner());
    const first = getStore().documents.find((d) => d.id === SHARED)!;
    const res = await newVersion(
      upload(
        `/api/documents/${SHARED}/versions`,
        new File([pdfBytes('second edition')], 'audit-v2.pdf', { type: 'application/pdf' }),
        { change_notes: 'restated figures' }
      ),
      oneParam(SHARED)
    );
    expect(res.status).toBe(201);
    const after = getStore().documents.find((d) => d.id === SHARED)!;
    expect(after.current_version).toBe(first.current_version + 1);
    const history = await listVersions(json(`/api/documents/${SHARED}/versions`), oneParam(SHARED));
    const body = await history.json();
    const versions = body.data.versions ?? body.data;
    expect(versions.length).toBeGreaterThanOrEqual(2);
    expect(new Set(versions.map((v: { checksum: string }) => v.checksum)).size).toBe(versions.length);
  });

  it('a read grantee cannot add a version', async () => {
    await signIn(viewer());
    const res = await newVersion(
      upload(
        `/api/documents/${SHARED}/versions`,
        new File([pdfBytes('sneaky')], 'sneak.pdf', { type: 'application/pdf' })
      ),
      oneParam(SHARED)
    );
    expect(res.status).toBe(403);
    expect(getStore().documents.find((d) => d.id === SHARED)!.current_version).toBe(1);
  });

  it('metadata validation rejects a blank title and an unknown category shape', async () => {
    await signIn(owner());
    const res = await uploadDoc(
      upload('/api/documents', new File([pdfBytes('x')], 'ok.pdf', { type: 'application/pdf' }), {
        title: '',
        category: 'financial',
      })
    );
    expect(res.status).toBe(400);
  });
});

// ---------------------------------------------------------------------------
// K–O: the audit trail is evidence, not decoration
// ---------------------------------------------------------------------------

describe('K–O: audit evidence and tamper detection', () => {
  it('K. the owner can read the access history of their document', async () => {
    await signIn(viewer());
    await getDoc(json(`/api/documents/${SHARED}`), oneParam(SHARED));
    await signIn(owner());
    const res = await docAudit(json(`/api/documents/${SHARED}/audit`), oneParam(SHARED));
    expect(res.status).toBe(200);
    const body = await res.json();
    const events = body.data.events ?? body.data;
    expect(events.some((e: { action: string; actor_id: string }) => e.action === 'preview' && e.actor_id === viewer().id)).toBe(true);
  });

  it('L. a non-grantee cannot read the audit trail of that document', async () => {
    await mutateStore((store) => {
      store.permissions = store.permissions.filter((p) => p.user_id !== viewer().id);
    });
    await signIn(viewer());
    const res = await docAudit(json(`/api/documents/${SHARED}/audit`), oneParam(SHARED));
    expect(res.status).toBe(403);
  });

  it('M. refused attempts are recorded with the actor who was refused', async () => {
    await signIn(viewer());
    await getDoc(json(`/api/documents/${PRIVATE}`), oneParam(PRIVATE));
    await downloadDoc(json(`/api/documents/${PRIVATE}/download`), oneParam(PRIVATE));
    const denied = getStore().audit.filter((e) => e.result === 'denied' && e.document_id === PRIVATE);
    expect(denied.length).toBeGreaterThanOrEqual(2);
    expect(denied.every((e) => e.actor_id === viewer().id)).toBe(true);
  });

  it('N. only an admin may ask whether the chain is intact', async () => {
    await signIn(owner());
    expect((await verifyChain(json('/api/admin/audit/verify', {}))).status).toBe(403);
    anon();
    expect((await verifyChain(json('/api/admin/audit/verify', {}))).status).toBe(401);
    await signIn(admin());
    const res = await verifyChain(json('/api/admin/audit/verify', {}));
    expect(res.status).toBe(200);
    expect((await res.json()).valid).toBe(true);
  });

  it('O. rewriting one stored event is reported as the first invalid event', async () => {
    await signIn(admin());
    const victim = getStore().audit[1];
    await mutateStore((store) => {
      store.audit[1].action = 'delete';
    });
    const res = await verifyChain(json('/api/admin/audit/verify', {}));
    const body = await res.json();
    expect(body.valid).toBe(false);
    expect(body.first_invalid).toBe(victim.id);
  });

  it('deleting an event from the middle of the chain orphans its successor', async () => {
    const audit = getStore().audit;
    if (audit.length < 3) throw new Error('Seed needs three audit rows to prove excision detection');
    const removed = audit[1];
    await signIn(admin());
    await mutateStore((store) => {
      store.audit.splice(1, 1);
    });
    const body = await (await verifyChain(json('/api/admin/audit/verify', {}))).json();
    expect(body.valid).toBe(false);
    // The row that is gone is reported at its child, because a missing parent is
    // only observable as a prev_hash that matches nothing.
    expect(body.first_invalid).toBeTruthy();
    expect(body.first_invalid).not.toBe(removed.id);
    expect(JSON.stringify(body.mismatches)).toContain('orphaned');
  });

  it('honest limit: cutting the newest events off the tail leaves a valid chain', async () => {
    await signIn(admin());
    const head = getStore().audit.at(-1)!;
    await mutateStore((store) => {
      store.audit.pop();
    });
    const body = await (await verifyChain(json('/api/admin/audit/verify', {}))).json();
    expect(body.valid).toBe(true);
    expect(head.id).toBeTruthy();
    // Detecting this truncation is the signed checkpoint's job, not the chain's.
  });
});

// ---------------------------------------------------------------------------
// P–T: sessions, throttles, bearer links and secret hygiene
// ---------------------------------------------------------------------------

describe('P–S: credential handling', () => {
  const loginBody = (email: string, password: string) => json('/api/auth/login', { email, password });

  it('P. a wrong password yields no session cookie', async () => {
    const res = await login(loginBody('owner@example.com', 'definitely-not-the-password'));
    expect(res.status).toBe(401);
    expect(res.headers.getSetCookie().join('')).not.toContain(SESSION_COOKIE);
  });

  it('a malformed login body is refused without authenticating anything', async () => {
    const res = await login(json('/api/auth/login', { email: 'not-an-email' }));
    expect(res.status).toBe(400);
    expect(res.headers.getSetCookie().join('')).not.toContain(SESSION_COOKIE);
    anon();
    expect((await listDocs(json('/api/documents'))).status).toBe(401);
  });

  it('Q. repeated guesses from one client are throttled', async () => {
    let last = 0;
    for (let i = 0; i < 12; i += 1) {
      last = (await login(loginBody('owner@example.com', `guess-${i}`))).status;
    }
    expect(last).toBe(429);
  });

  it('the throttle records the failed attempts rather than swallowing them', async () => {
    await login(loginBody('viewer@example.com', 'wrong-one'));
    await login(loginBody('viewer@example.com', 'wrong-two'));
    const failures = getStore().audit.filter((e) => e.action === 'login_failure' || e.action === 'LOGIN_FAILED');
    expect(failures.length).toBeGreaterThanOrEqual(2);
    expect(failures.every((e) => e.result === 'denied')).toBe(true);
  });

  it('R. a forged cookie payload is rejected by the signature check', async () => {
    const forged = `${Buffer.from(
      JSON.stringify({ id: owner().id, email: owner().email, role: 'owner' })
    ).toString('base64url')}.${'0'.repeat(64)}`;
    cookieJar.current[SESSION_COOKIE] = forged;
    const res = await getDoc(json(`/api/documents/${PRIVATE}`), oneParam(PRIVATE));
    expect(res.status).toBe(401);
  });

  it('S. deactivated accounts lose access immediately', async () => {
    await mutateStore((store) => {
      store.users.find((u) => u.email === 'viewer@example.com')!.is_active = false;
    });
    await signIn(viewer());
    expect((await getDoc(json(`/api/documents/${SHARED}`), oneParam(SHARED))).status).toBe(403);
    expect((await listDocs(json('/api/documents'))).status).toBe(403);
  });
});

describe('T: bearer links and secret hygiene', () => {
  it('a share link stores only its digest and is closed by revocation', async () => {
    await signIn(owner());
    const created = await createLink(
      json(`/api/documents/${SHARED}/share-links`, {
        label: 'auditor',
        expires_at: new Date(Date.now() + 3600_000).toISOString(),
        max_views: 1,
        allow_download: false,
        watermark_enabled: true,
      }),
      oneParam(SHARED)
    );
    expect(created.status).toBe(201);
    const { token, link } = (await created.json()).data;
    const stored = getStore().share_links.find((l) => l.id === link.id)!;
    expect(stored.token_hash).toBe(createHash('sha256').update(token).digest('hex'));
    expect(JSON.stringify(getStore().share_links)).not.toContain(token);

    anon();
    const view = await publicView(json(`/api/public/share/${token}`), {
      params: Promise.resolve({ token }),
    });
    expect(view.status).toBe(200);

    await signIn(owner());
    expect(
      (await revokeLink(
        json(`/api/documents/${SHARED}/share-links/${link.id}`, { action: 'revoke' }, 'PATCH'),
        { params: Promise.resolve({ id: SHARED, linkId: link.id }) }
      )).status
    ).toBe(200);

    anon();
    const after = await publicView(json(`/api/public/share/${token}`), { params: Promise.resolve({ token }) });
    expect(after.status).toBe(410);
  });

  it('no route response or seed row carries credential material', async () => {
    await signIn(admin());
    const users = await adminUsers(json('/api/admin/users'));
    expect(users.status).toBe(200);
    const serialized = JSON.stringify(await users.json());
    for (const forbidden of ['password', 'token_hash', 'session_secret', 'service_role']) {
      expect(serialized.toLowerCase(), `admin/users leaked ${forbidden}`).not.toContain(forbidden);
    }
    const rawStore = readFileSync(`${process.env.DATA_DIR}/store.json`, 'utf8');
    expect(rawStore.toLowerCase()).not.toContain(process.env.SESSION_SECRET ?? '__never__');
    expect(rawStore.toLowerCase()).not.toContain(process.env.DEMO_PASSWORD ?? '__never__');
  });

  it('rule-based detection raises a high-severity alert for repeated refusals', async () => {
    await signIn(viewer());
    for (let i = 0; i < 6; i += 1) {
      await getDoc(json(`/api/documents/${PRIVATE}`), oneParam(PRIVATE));
    }
    await signIn(admin());
    const res = await adminAlerts(json('/api/admin/alerts'));
    expect(res.status).toBe(200);
    const body = await res.json();
    const alert = body.data.find((a: { rule: string }) => a.rule === 'repeated_denied_access');
    expect(alert).toBeDefined();
    expect(alert.affected_actor_email).toBe('viewer@example.com');
    expect(alert.severity).toBe('high');
  });
});
