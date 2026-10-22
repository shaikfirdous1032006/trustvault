import { describe, it, expect, vi, beforeEach } from 'vitest';
import { NextRequest } from 'next/server';
import type { User } from '@/lib/types';
import { getStore } from '@/lib/local-db';
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
  headers: async () =>
    new Headers({ 'x-forwarded-for': '203.0.113.7', 'user-agent': 'TrustVault-Test-Runner' }),
}));

import { POST as registerUser } from '@/app/api/auth/register/route';
import { POST as uploadDoc } from '@/app/api/documents/route';
import { GET as getAdminAudit } from '@/app/api/admin/audit/route';

const ORIGIN = 'http://localhost:3000';

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
  return new NextRequest(`${ORIGIN}${url}`, {
    method: method ?? (body === undefined ? 'GET' : 'POST'),
    headers: { 'Content-Type': 'application/json', Origin: ORIGIN },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

function upload(url: string, file: File, meta: Record<string, string> = {}) {
  const form = new FormData();
  form.set('file', file);
  for (const [key, value] of Object.entries(meta)) form.set(key, value);
  return new NextRequest(`${ORIGIN}${url}`, {
    method: 'POST',
    headers: { Origin: ORIGIN },
    body: form,
  });
}

describe('User Role Features: Registration, Owner-Only Uploads & Admin Login/Logout History', () => {
  beforeEach(() => {
    anon();
  });

  describe('1. Registered users can select their role', () => {
    it('creates an account with owner role when owner is selected', async () => {
      anon();
      const email = `newowner_${Date.now()}@example.com`;
      const res = await registerUser(
        json('/api/auth/register', {
          full_name: 'Alice Owner',
          email,
          password: 'SecurePassword123!',
          role: 'owner',
        })
      );

      expect(res.status).toBe(201);
      const data = await res.json();
      expect(data.success).toBe(true);
      expect(data.data.user.role).toBe('owner');
      expect(data.data.user.email).toBe(email);

      const store = getStore();
      const created = store.users.find((u) => u.email === email);
      expect(created?.role).toBe('owner');
    });

    it('creates an account with viewer role when viewer is selected', async () => {
      anon();
      const email = `newviewer_${Date.now()}@example.com`;
      const res = await registerUser(
        json('/api/auth/register', {
          full_name: 'Bob Viewer',
          email,
          password: 'SecurePassword123!',
          role: 'viewer',
        })
      );

      expect(res.status).toBe(201);
      const data = await res.json();
      expect(data.success).toBe(true);
      expect(data.data.user.role).toBe('viewer');
    });

    it('defaults to viewer if no role is supplied', async () => {
      anon();
      const email = `defaultrole_${Date.now()}@example.com`;
      const res = await registerUser(
        json('/api/auth/register', {
          full_name: 'Charlie Default',
          email,
          password: 'SecurePassword123!',
        })
      );

      expect(res.status).toBe(201);
      const data = await res.json();
      expect(data.success).toBe(true);
      expect(data.data.user.role).toBe('viewer');
    });
  });

  describe('2. Only owners can upload documents', () => {
    it('allows document upload when user is owner', async () => {
      await signIn(owner());
      const res = await uploadDoc(
        upload('/api/documents', new File([Buffer.from('%PDF-1.4 test owner document bytes')], 'test-report.pdf', {
          type: 'application/pdf',
        }), {
          title: 'Owner Confidential Report',
          category: 'financial',
        })
      );

      expect(res.status).toBe(201);
      const data = await res.json();
      expect(data.success).toBe(true);
      expect(data.data.title).toBe('Owner Confidential Report');
    });

    it('rejects document upload when user is viewer with 403 Forbidden', async () => {
      await signIn(viewer());
      const res = await uploadDoc(
        upload('/api/documents', new File([Buffer.from('%PDF-1.4 test viewer document bytes')], 'viewer-doc.pdf', {
          type: 'application/pdf',
        }), {
          title: 'Unauthorized Viewer Upload',
          category: 'general',
        })
      );

      expect(res.status).toBe(403);
      const data = await res.json();
      expect(data.success).toBe(false);
      expect(data.error).toMatch(/Only owners can upload documents/i);
    });

    it('rejects document upload when user is admin with 403 Forbidden', async () => {
      await signIn(admin());
      const res = await uploadDoc(
        upload('/api/documents', new File([Buffer.from('%PDF-1.4 test admin document bytes')], 'admin-doc.pdf', {
          type: 'application/pdf',
        }), {
          title: 'Admin Upload Attempt',
          category: 'general',
        })
      );

      expect(res.status).toBe(403);
      const data = await res.json();
      expect(data.success).toBe(false);
      expect(data.error).toMatch(/Only owners can upload documents/i);
    });
  });

  describe('3. Admin can view history of logins and logouts', () => {
    it('returns login and logout events when admin queries action=auth', async () => {
      await signIn(admin());
      const res = await getAdminAudit(
        new NextRequest(`${ORIGIN}/api/admin/audit?action=auth`, {
          method: 'GET',
          headers: { Origin: ORIGIN },
        })
      );

      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.success).toBe(true);
      expect(Array.isArray(data.data)).toBe(true);

      for (const event of data.data) {
        expect(['login', 'logout', 'login_failure']).toContain(event.action);
      }
    });

    it('prevents non-admins from accessing admin audit log', async () => {
      await signIn(viewer());
      const res = await getAdminAudit(
        new NextRequest(`${ORIGIN}/api/admin/audit?action=auth`, {
          method: 'GET',
          headers: { Origin: ORIGIN },
        })
      );

      expect(res.status).toBe(403);
    });
  });
});
