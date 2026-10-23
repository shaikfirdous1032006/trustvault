import { describe, it, expect, vi, beforeEach } from 'vitest';
import { NextRequest } from 'next/server';
import type { User } from '@/lib/types';
import { getStore } from '@/lib/local-db';
import { createSessionToken, SESSION_COOKIE } from '@/lib/session';
import {
  formatISTDate,
  formatISTTime,
  formatISTDateTime,
  getActionDisplayLabel,
  getStatusDisplayLabel,
} from '@/lib/date-format';

const cookieJar = vi.hoisted(() => ({ current: {} as Record<string, string> }));

vi.mock('next/headers', () => ({
  cookies: async () => ({
    get: (name: string) =>
      cookieJar.current[name] ? { name, value: cookieJar.current[name] } : undefined,
    set: (name: string, value: string) => {
      cookieJar.current[name] = value;
    },
    delete: (name: string) => {
      delete cookieJar.current[name];
    },
    getAll: () => [],
  }),
  headers: async () =>
    new Headers({
      'x-forwarded-for': '203.0.113.19',
      'user-agent': 'TrustVault-Admin-Activity-Test',
    }),
}));

import { POST as loginUser } from '@/app/api/auth/login/route';
import { POST as logoutUser } from '@/app/api/auth/logout/route';
import { GET as getAdminAudit } from '@/app/api/admin/audit/route';

const ORIGIN = 'http://localhost:3000';

function findUser(email: string): User {
  const found = getStore().users.find((u) => u.email === email);
  if (!found) throw new Error(`Seed missing ${email}`);
  return found;
}

const adminUser = () => findUser('admin@example.com');
const ownerUser = () => findUser('owner@example.com');
const viewerUser = () => findUser('viewer@example.com');

async function setSession(user: User) {
  cookieJar.current[SESSION_COOKIE] = await createSessionToken(user);
}

function clearSession() {
  delete cookieJar.current[SESSION_COOKIE];
}

function postJson(url: string, body?: unknown) {
  return new NextRequest(`${ORIGIN}${url}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Origin: ORIGIN },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
}

function getRequest(url: string) {
  return new NextRequest(`${ORIGIN}${url}`, {
    method: 'GET',
    headers: { Origin: ORIGIN },
  });
}

describe('TrustVault — Admin Real-Time Login & Logout Activity', () => {
  beforeEach(() => {
    clearSession();
  });

  describe('1. Indian Standard Time (IST) Formatting & Labels', () => {
    it('formats UTC ISO timestamp into Asia/Kolkata date and time with seconds', () => {
      // 2026-10-23T08:45:32.000Z in UTC is 2026-10-23 14:15:32 (02:15:32 PM) in IST (+05:30)
      const isoUtc = '2026-10-23T08:45:32.000Z';

      const dateStr = formatISTDate(isoUtc);
      expect(dateStr).toContain('2026');
      expect(dateStr).toMatch(/23\s+Oct\s+2026/i);

      const timeStr = formatISTTime(isoUtc);
      expect(timeStr).toContain('IST');
      expect(timeStr).toMatch(/02:15:32\s+PM\s+IST/i);

      const fullStr = formatISTDateTime(isoUtc);
      expect(fullStr).toContain('2026');
      expect(fullStr).toContain('IST');
    });

    it('maps audit actions and statuses to human-readable labels', () => {
      expect(getActionDisplayLabel('LOGIN_SUCCESS')).toBe('Signed In');
      expect(getActionDisplayLabel('LOGOUT_SUCCESS')).toBe('Signed Out');
      expect(getActionDisplayLabel('LOGIN_FAILED')).toBe('Login Failed');

      const successStatus = getStatusDisplayLabel('allowed', 'LOGIN_SUCCESS');
      expect(successStatus.label).toBe('Success');
      expect(successStatus.isSuccess).toBe(true);

      const failedStatus = getStatusDisplayLabel('denied', 'LOGIN_FAILED');
      expect(failedStatus.label).toBe('Failed');
      expect(failedStatus.isSuccess).toBe(false);
    });
  });

  const DEMO_PASS = process.env.DEMO_PASSWORD || 'TrustVault2024!';

  describe('2. Backend Recording of Sign-in and Sign-out Events', () => {
    it('creates exactly one LOGIN_SUCCESS event upon valid authentication', async () => {
      const initialCount = getStore().audit.filter(
        (a) => a.action === 'LOGIN_SUCCESS' && a.actor_email === 'admin@example.com'
      ).length;

      const res = await loginUser(
        postJson('/api/auth/login', {
          email: 'admin@example.com',
          password: DEMO_PASS,
        })
      );

      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.success).toBe(true);

      const loginEvents = getStore().audit.filter(
        (a) => a.action === 'LOGIN_SUCCESS' && a.actor_email === 'admin@example.com'
      );
      expect(loginEvents.length).toBe(initialCount + 1);

      const latest = loginEvents[loginEvents.length - 1];
      expect(latest.actor_id).toBe(adminUser().id);
      expect(latest.actor_email).toBe('admin@example.com');
      expect(latest.result).toBe('allowed');
      expect(latest.occurred_at).toBeDefined();
      expect(latest.id).toBeDefined();
      expect(latest.event_hash).toBeDefined();
    });

    it('creates exactly one LOGOUT_SUCCESS event for the verified account before clearing session', async () => {
      await setSession(ownerUser());

      const initialCount = getStore().audit.filter(
        (a) => a.action === 'LOGOUT_SUCCESS' && a.actor_email === 'owner@example.com'
      ).length;

      const res = await logoutUser(postJson('/api/auth/logout'));
      expect(res.status).toBe(200);

      const logoutEvents = getStore().audit.filter(
        (a) => a.action === 'LOGOUT_SUCCESS' && a.actor_email === 'owner@example.com'
      );
      expect(logoutEvents.length).toBe(initialCount + 1);

      const latest = logoutEvents[logoutEvents.length - 1];
      expect(latest.actor_id).toBe(ownerUser().id);
      expect(latest.actor_email).toBe('owner@example.com');
      expect(latest.result).toBe('allowed');
      expect(latest.occurred_at).toBeDefined();
    });

    it('creates LOGIN_FAILED without leaking passwords or user existence on wrong credentials', async () => {
      const res = await loginUser(
        postJson('/api/auth/login', {
          email: 'admin@example.com',
          password: 'WrongPassword999!',
        })
      );

      expect(res.status).toBe(401);
      const json = await res.json();
      expect(json.success).toBe(false);
      expect(json.error).toBe('Invalid email or password');

      const failedEvents = getStore().audit.filter(
        (a) => a.action === 'LOGIN_FAILED' && a.actor_email === 'admin@example.com'
      );
      expect(failedEvents.length).toBeGreaterThan(0);

      const latest = failedEvents[failedEvents.length - 1];
      expect(latest.result).toBe('denied');
      const detailsStr = latest.details_jsonb ? JSON.stringify(latest.details_jsonb) : '';
      expect(detailsStr).not.toContain('WrongPassword999!');
    });

    it('records sign-in for a second account with that accounts email', async () => {
      const res = await loginUser(
        postJson('/api/auth/login', {
          email: 'viewer@example.com',
          password: DEMO_PASS,
        })
      );

      expect(res.status).toBe(200);

      const viewerEvents = getStore().audit.filter(
        (a) => a.action === 'LOGIN_SUCCESS' && a.actor_email === 'viewer@example.com'
      );
      expect(viewerEvents.length).toBeGreaterThanOrEqual(1);
      expect(viewerEvents[0].actor_id).toBe(viewerUser().id);
    });
  });

  describe('3. Admin Activity API Access & Filtering', () => {
    it('denies access to non-admin users (403)', async () => {
      await setSession(viewerUser());
      const res = await getAdminAudit(getRequest('/api/admin/audit'));
      expect(res.status).toBe(403);
    });

    it('denies access to anonymous requests (401)', async () => {
      clearSession();
      const res = await getAdminAudit(getRequest('/api/admin/audit'));
      expect(res.status).toBe(401);
    });

    it('allows admin users to read all audit activity sorted newest first', async () => {
      await setSession(adminUser());
      const res = await getAdminAudit(getRequest('/api/admin/audit?limit=50'));
      expect(res.status).toBe(200);

      const body = await res.json();
      expect(body.success).toBe(true);
      expect(Array.isArray(body.data)).toBe(true);
      expect(body.data.length).toBeGreaterThan(0);

      // Verify newest first
      const timestamps = body.data.map((e: { occurred_at: string }) =>
        new Date(e.occurred_at).getTime()
      );
      for (let i = 1; i < timestamps.length; i++) {
        expect(timestamps[i - 1]).toBeGreaterThanOrEqual(timestamps[i]);
      }
    });

    it('filters activity specifically by action=auth', async () => {
      await setSession(adminUser());
      const res = await getAdminAudit(getRequest('/api/admin/audit?action=auth'));
      expect(res.status).toBe(200);

      const body = await res.json();
      expect(body.success).toBe(true);
      const authActions = new Set([
        'LOGIN_SUCCESS',
        'LOGOUT_SUCCESS',
        'LOGIN_FAILED',
        'login_success',
        'logout_success',
        'login_failure',
      ]);
      for (const item of body.data) {
        expect(authActions.has(item.action)).toBe(true);
      }
    });

    it('filters activity by account email', async () => {
      await setSession(adminUser());
      const res = await getAdminAudit(
        getRequest('/api/admin/audit?email=viewer@example.com')
      );
      expect(res.status).toBe(200);

      const body = await res.json();
      expect(body.success).toBe(true);
      for (const item of body.data) {
        expect(item.actor_email?.toLowerCase()).toContain('viewer@example.com');
      }
    });
  });
});
