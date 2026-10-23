import { describe, it, expect, vi, beforeEach } from 'vitest';
import { NextRequest } from 'next/server';
import type { User } from '@/lib/types';
import { getStore, mutateStore } from '@/lib/local-db';
import { createSessionToken, SESSION_COOKIE } from '@/lib/session';
import { logAuditEvent, formatAuditDescription } from '@/lib/audit';

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
  headers: async () => new Headers({ 'x-forwarded-for': '203.0.113.9', 'user-agent': 'Vitest' }),
}));

import { GET as getActivity } from '@/app/api/dashboard/activity/route';
import { GET as getMetrics } from '@/app/api/admin/audit/metrics/route';
import { PATCH as patchUser, POST as postUser } from '@/app/api/admin/users/route';
import { PATCH as patchMe } from '@/app/api/auth/me/route';
import { PATCH as patchPermission } from '@/app/api/documents/[id]/permissions/[permissionId]/route';

describe('Real-Time Activity Monitoring and Audit Logging Suite', () => {
  function userByEmail(email: string): User {
    const user = getStore().users.find((u) => u.email === email);
    if (!user) throw new Error(`Seed is missing ${email}`);
    return user;
  }

  const ADMIN = () => userByEmail('admin@example.com');
  const OWNER = () => userByEmail('owner@example.com');
  const VIEWER = () => userByEmail('viewer@example.com');

  async function loginAs(user: User | null) {
    if (!user) {
      delete cookieJar.current[SESSION_COOKIE];
      return;
    }
    const token = await createSessionToken(user);
    cookieJar.current[SESSION_COOKIE] = token;
  }

  beforeEach(() => {
    delete cookieJar.current[SESSION_COOKIE];
  });

  describe('1. Activity Feed API (/api/dashboard/activity)', () => {
    it('rejects unauthenticated requests with 401', async () => {
      await loginAs(null);
      const req = new NextRequest('http://localhost:3000/api/dashboard/activity');
      const res = await getActivity(req);
      expect(res.status).toBe(401);
      const json = await res.json();
      expect(json.success).toBe(false);
      expect(json.error).toBe('Unauthorized');
    });

    it('returns activity feed for authenticated admin with pagination metadata', async () => {
      await loginAs(ADMIN());
      const req = new NextRequest('http://localhost:3000/api/dashboard/activity?page=1&pageSize=5');
      const res = await getActivity(req);
      expect(res.status).toBe(200);
      const json = await res.json();
      expect(json.success).toBe(true);
      expect(Array.isArray(json.data)).toBe(true);
      expect(json.page).toBe(1);
      expect(json.pageSize).toBe(5);
      expect(json.total).toBeGreaterThan(0);
      expect(typeof json.hasMore).toBe('boolean');
    });

    it('filters activity by search keyword across descriptions and actor emails', async () => {
      await loginAs(ADMIN());
      const req = new NextRequest('http://localhost:3000/api/dashboard/activity?search=viewer');
      const res = await getActivity(req);
      const json = await res.json();
      expect(json.success).toBe(true);
      for (const item of json.data) {
        const matches =
          (item.actor_email && item.actor_email.toLowerCase().includes('viewer')) ||
          item.description.toLowerCase().includes('viewer') ||
          (item.document_title && item.document_title.toLowerCase().includes('viewer'));
        expect(matches).toBe(true);
      }
    });

    it('filters activity by category (auth)', async () => {
      await loginAs(ADMIN());
      const req = new NextRequest('http://localhost:3000/api/dashboard/activity?category=auth');
      const res = await getActivity(req);
      const json = await res.json();
      expect(json.success).toBe(true);
      const allowedAuthActions = ['login', 'logout', 'login_failure', 'register', 'register_failure'];
      for (const item of json.data) {
        expect(allowedAuthActions).toContain(item.action);
      }
    });

    it('filters activity by outcome (allowed vs denied)', async () => {
      await loginAs(ADMIN());
      const reqDenied = new NextRequest('http://localhost:3000/api/dashboard/activity?result=denied');
      const resDenied = await getActivity(reqDenied);
      const jsonDenied = await resDenied.json();
      expect(jsonDenied.success).toBe(true);
      for (const item of jsonDenied.data) {
        expect(item.result).toBe('denied');
      }

      const reqAllowed = new NextRequest('http://localhost:3000/api/dashboard/activity?result=allowed');
      const resAllowed = await getActivity(reqAllowed);
      const jsonAllowed = await resAllowed.json();
      expect(jsonAllowed.success).toBe(true);
      for (const item of jsonAllowed.data) {
        expect(item.result).toBe('allowed');
      }
    });

    it('enforces role-based visibility: viewer only sees their own or permitted activity', async () => {
      const viewer = VIEWER();
      await loginAs(viewer);
      const req = new NextRequest('http://localhost:3000/api/dashboard/activity');
      const res = await getActivity(req);
      const json = await res.json();
      expect(json.success).toBe(true);

      const store = getStore();
      const permittedDocIds = new Set(
        store.permissions
          .filter((p) => p.user_id === viewer.id && !p.revoked_at)
          .map((p) => p.document_id)
      );

      for (const item of json.data) {
        const isSelf = item.actor_email === viewer.email || item.actor_id === viewer.id;
        const isPermittedDoc = item.document_id ? permittedDocIds.has(item.document_id) : false;
        expect(isSelf || isPermittedDoc).toBe(true);
      }
    });
  });

  describe('2. Admin Audit Metrics API (/api/admin/audit/metrics)', () => {
    it('blocks unauthenticated access with 401', async () => {
      await loginAs(null);
      const req = new NextRequest('http://localhost:3000/api/admin/audit/metrics');
      const res = await getMetrics(req);
      expect(res.status).toBe(401);
    });

    it('blocks viewer access with 403 Forbidden', async () => {
      await loginAs(VIEWER());
      const req = new NextRequest('http://localhost:3000/api/admin/audit/metrics');
      const res = await getMetrics(req);
      expect(res.status).toBe(403);
      const json = await res.json();
      expect(json.success).toBe(false);
      expect(json.error).toContain('Insufficient role');
    });

    it('blocks owner access with 403 Forbidden', async () => {
      await loginAs(OWNER());
      const req = new NextRequest('http://localhost:3000/api/admin/audit/metrics');
      const res = await getMetrics(req);
      expect(res.status).toBe(403);
    });

    it('returns comprehensive activity metrics derived from database for admin', async () => {
      await loginAs(ADMIN());
      const req = new NextRequest('http://localhost:3000/api/admin/audit/metrics?period=all');
      const res = await getMetrics(req);
      expect(res.status).toBe(200);
      const json = await res.json();
      expect(json.success).toBe(true);
      expect(json.data).toBeDefined();

      const m = json.data;
      expect(typeof m.totalActivities).toBe('number');
      expect(typeof m.allowedCount).toBe('number');
      expect(typeof m.deniedCount).toBe('number');
      expect(typeof m.securityEventsCount).toBe('number');
      expect(m.allowedCount + m.deniedCount).toBe(m.totalActivities);
      expect(Array.isArray(m.mostActiveUsers)).toBe(true);
      expect(m.mostActiveUsers.length).toBeLessThanOrEqual(5);
    });
  });

  describe('3. Admin User Management & Audit Logging (/api/admin/users)', () => {
    it('allows admin to change user role and creates an audit record', async () => {
      await loginAs(ADMIN());
      const viewer = VIEWER();
      const req = new NextRequest('http://localhost:3000/api/admin/users', {
        method: 'PATCH',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ userId: viewer.id, role: 'owner' }),
      });
      const res = await patchUser(req);
      expect(res.status).toBe(200);
      const json = await res.json();
      expect(json.success).toBe(true);
      expect(json.data.role).toBe('owner');

      // Verify audit record was logged
      const store = getStore();
      const lastAudit = store.audit[store.audit.length - 1];
      expect(lastAudit.action).toBe('role_change');
      expect(lastAudit.result).toBe('allowed');
      expect(lastAudit.actor_id).toBe(ADMIN().id);
      expect(lastAudit.details_jsonb.new_role).toBe('owner');
    });

    it('allows admin to toggle account activation status and logs audit event', async () => {
      await loginAs(ADMIN());
      const viewer = VIEWER();
      const req = new NextRequest('http://localhost:3000/api/admin/users', {
        method: 'PATCH',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ userId: viewer.id, is_active: false }),
      });
      const res = await patchUser(req);
      expect(res.status).toBe(200);
      const json = await res.json();
      expect(json.success).toBe(true);
      expect(json.data.is_active).toBe(false);

      const store = getStore();
      const lastAudit = store.audit[store.audit.length - 1];
      expect(lastAudit.action).toBe('account_deactivated');
      expect(lastAudit.details_jsonb.is_active).toBe(false);

      // Re-activate viewer so subsequent tests have a valid active user
      await mutateStore((s) => {
        const u = s.users.find((usr) => usr.id === viewer.id);
        if (u) {
          u.is_active = true;
          u.role = 'viewer';
        }
      });
    });

    it('prevents administrator from deactivating their own account (self-lockout protection)', async () => {
      const admin = ADMIN();
      await loginAs(admin);
      const req = new NextRequest('http://localhost:3000/api/admin/users', {
        method: 'PATCH',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ userId: admin.id, is_active: false }),
      });
      const res = await patchUser(req);
      expect(res.status).toBe(400);
      const json = await res.json();
      expect(json.success).toBe(false);
      expect(json.error).toContain('cannot deactivate their own account');
    });

    it('blocks non-admin users from modifying roles or activation', async () => {
      await loginAs(OWNER());
      const req = new NextRequest('http://localhost:3000/api/admin/users', {
        method: 'PATCH',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ userId: VIEWER().id, role: 'admin' }),
      });
      const res = await patchUser(req);
      expect(res.status).toBe(403);
    });

    it('allows admin to create a new user and logs user_created audit event', async () => {
      await loginAs(ADMIN());
      const uniqueEmail = `newuser_${Date.now()}@example.com`;
      const req = new NextRequest('http://localhost:3000/api/admin/users', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          email: uniqueEmail,
          full_name: 'Audit Test User',
          role: 'viewer',
        }),
      });
      const res = await postUser(req);
      expect(res.status).toBe(201);
      const json = await res.json();
      expect(json.success).toBe(true);

      const freshAudit = getStore().audit;
      const lastAudit = freshAudit[freshAudit.length - 1];
      expect(lastAudit.action).toBe('user_created');
      expect(lastAudit.result).toBe('allowed');
      expect(lastAudit.details_jsonb.target_user_email).toBe(uniqueEmail);
      expect(lastAudit.details_jsonb.target_resource_type).toBe('user');
    });
  });

  describe('4. Profile & Permission Update Audit Trail', () => {
    it('records profile_update audit event when user updates profile name', async () => {
      const viewer = VIEWER();
      await loginAs(viewer);
      const req = new NextRequest('http://localhost:3000/api/auth/me', {
        method: 'PATCH',
        headers: {
          'content-type': 'application/json',
          origin: 'http://localhost:3000',
        },
        body: JSON.stringify({ full_name: 'Updated Viewer Name' }),
      });
      const res = await patchMe(req);
      expect(res.status).toBe(200);
      const json = await res.json();
      expect(json.success).toBe(true);
      expect(json.data.full_name).toBe('Updated Viewer Name');

      const freshAudit = getStore().audit;
      const lastAudit = freshAudit[freshAudit.length - 1];
      expect(lastAudit.action).toBe('profile_update');
      expect(lastAudit.result).toBe('allowed');
      expect(lastAudit.actor_id).toBe(viewer.id);
      expect(lastAudit.details_jsonb.target_resource_type).toBe('user');
    });

    it('records permission_update audit event when document owner updates existing permission', async () => {
      const owner = OWNER();
      await loginAs(owner);
      const store = getStore();
      const doc = store.documents.find((d) => d.owner_id === owner.id && !d.is_deleted);
      if (!doc) throw new Error('Owner has no documents');
      const perm = store.permissions.find((p) => p.document_id === doc.id && !p.revoked_at);
      if (!perm) throw new Error('Document has no active permissions');

      const req = new NextRequest(`http://localhost:3000/api/documents/${doc.id}/permissions/${perm.id}`, {
        method: 'PATCH',
        headers: {
          'content-type': 'application/json',
          origin: 'http://localhost:3000',
        },
        body: JSON.stringify({ permission_level: 'edit' }),
      });
      const res = await patchPermission(req, {
        params: Promise.resolve({ id: doc.id, permissionId: perm.id }),
      });
      expect(res.status).toBe(200);
      const json = await res.json();
      expect(json.success).toBe(true);

      const freshAudit = getStore().audit;
      const lastAudit = freshAudit[freshAudit.length - 1];
      expect(lastAudit.action).toBe('permission_update');
      expect(lastAudit.result).toBe('allowed');
      expect(lastAudit.document_id).toBe(doc.id);
      expect(lastAudit.details_jsonb.target_resource_type).toBe('permission');
    });
  });

  describe('4. Centralized Audit Utility & Sanitization', () => {
    it('redacts sensitive information from audit details', async () => {
      const admin = ADMIN();
      await logAuditEvent({
        actorId: admin.id,
        actorEmail: admin.email,
        action: 'admin_action',
        result: 'allowed',
        details: {
          secret_key: 'sk_live_1234567890',
          password: 'SuperSecretPassword!',
          bearer_token: 'jwt.token.here',
          file_name: 'PublicReport.pdf',
        },
      });

      const store = getStore();
      const last = store.audit[store.audit.length - 1];
      expect(last.details_jsonb.secret_key).toBe('[REDACTED]');
      expect(last.details_jsonb.password).toBe('[REDACTED]');
      expect(last.details_jsonb.bearer_token).toBe('[REDACTED]');
      expect(last.details_jsonb.file_name).toBe('PublicReport.pdf');
    });

    it('formats clean, human-readable descriptions automatically', () => {
      const descLogin = formatAuditDescription({
        actorId: 'user-1',
        actorEmail: 'test@example.com',
        action: 'login',
        result: 'allowed',
      });
      expect(descLogin).toBe('test@example.com successfully signed in');

      const descUpload = formatAuditDescription({
        actorId: 'user-1',
        actorEmail: 'owner@example.com',
        action: 'upload',
        result: 'allowed',
        details: { file_name: 'Confidential.pdf' },
      });
      expect(descUpload).toBe('owner@example.com uploaded Confidential.pdf');

      const descDenied = formatAuditDescription({
        actorId: 'user-1',
        actorEmail: 'viewer@example.com',
        action: 'delete',
        result: 'denied',
        details: { file_name: 'Confidential.pdf', reason: 'Not document owner' },
      });
      expect(descDenied).toContain('denied permission to delete Confidential.pdf');
    });
  });
});
