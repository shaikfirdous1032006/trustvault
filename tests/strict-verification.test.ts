import { describe, it, expect, vi, beforeAll } from 'vitest';
import { NextRequest } from 'next/server';
import fs from 'node:fs';
import path from 'node:path';
import { getStore, mutateStore, findUserByEmail, findUserById } from '@/lib/local-db';
import { getPasswordRecord, verifyPassword } from '@/lib/passwords';
import { SESSION_COOKIE, verifySessionToken } from '@/lib/session';

const cookieJar = vi.hoisted(() => ({ current: {} as Record<string, string> }));

let requestIpCounter = 100;

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
  headers: async () => {
    requestIpCounter += 1;
    return new Headers({
      'x-forwarded-for': `203.0.113.${requestIpCounter}`,
      'user-agent': 'Strict-Verification-Agent',
    });
  },
}));

import { POST as registerRoute } from '@/app/api/auth/register/route';
import { POST as loginRoute } from '@/app/api/auth/login/route';
import { GET as meRoute } from '@/app/api/auth/me/route';

const ORIGIN = 'http://localhost:3000';

function makePost(url: string, body: unknown, cookieValue?: string) {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    Origin: ORIGIN,
  };
  if (cookieValue) {
    headers['Cookie'] = `${SESSION_COOKIE}=${cookieValue}`;
  }
  return new NextRequest(`${ORIGIN}${url}`, {
    method: 'POST',
    headers,
    body: JSON.stringify(body),
  });
}

function makeGet(url: string, cookieValue?: string) {
  const headers: Record<string, string> = {
    Origin: ORIGIN,
  };
  if (cookieValue) {
    headers['Cookie'] = `${SESSION_COOKIE}=${cookieValue}`;
  }
  return new NextRequest(`${ORIGIN}${url}`, {
    method: 'GET',
    headers,
  });
}

describe('Strict End-to-End Authentication Verification', () => {
  const uniqueTag = Date.now();
  const testUser = {
    fullName: 'Strict Verification User',
    email: `strict.verify.${uniqueTag}@example.org`,
    password: `ValidSecurePass#${uniqueTag}!`,
    role: 'owner' as const,
  };

  let registeredUserId: string;
  let sessionTokenString: string;

  beforeAll(() => {
    process.env.SESSION_SECRET =
      process.env.SESSION_SECRET ||
      'e7cb79cf640dd4e9f5d7d69964b93113c839db6ff18ae6a939986c437409225a';
    process.env.DEMO_PASSWORD = process.env.DEMO_PASSWORD || 'TrustVault2024!';
  });

  it('Step 1: Verify database state is intact without wiping real project data', () => {
    const store = getStore();
    expect(store).toBeDefined();
    expect(Array.isArray(store.users)).toBe(true);
    expect(Array.isArray(store.documents)).toBe(true);
    expect(Array.isArray(store.audit)).toBe(true);

    // Verify existing demo accounts are preserved
    const demoOwner = store.users.find((u) => u.email === 'owner@example.com');
    const demoAdmin = store.users.find((u) => u.email === 'admin@example.com');
    const demoViewer = store.users.find((u) => u.email === 'viewer@example.com');

    expect(demoOwner).toBeDefined();
    expect(demoAdmin).toBeDefined();
    expect(demoViewer).toBeDefined();
  });

  it('Step 2: Register a new test user using the real registration API', async () => {
    const req = makePost('/api/auth/register', {
      full_name: testUser.fullName,
      email: testUser.email,
      password: testUser.password,
      role: testUser.role,
    });

    const res = await registerRoute(req);
    expect(res.status).toBe(201);

    const json = await res.json();
    expect(json.success).toBe(true);
    expect(json.data.user).toBeDefined();
    expect(json.data.user.email).toBe(testUser.email.toLowerCase());
    expect(json.data.user.role).toBe(testUser.role);
    expect(json.data.user.full_name).toBe(testUser.fullName);
    expect(typeof json.data.user.id).toBe('string');

    registeredUserId = json.data.user.id;
  });

  it('Step 3: Verify the user is persisted in the configured authoritative database', () => {
    const persistedUser = findUserByEmail(testUser.email);
    expect(persistedUser).toBeDefined();
    expect(persistedUser?.id).toBe(registeredUserId);
    expect(persistedUser?.email).toBe(testUser.email.toLowerCase());
    expect(persistedUser?.is_active).toBe(true);

    const passwordRecord = getPasswordRecord(registeredUserId);
    expect(passwordRecord).toBeDefined();
    expect(passwordRecord?.salt).toBeDefined();
    expect(passwordRecord?.hash).toBeDefined();

    // Verify credentials file on disk in configured data directory contains this record
    const dataDir = process.env.DATA_DIR || path.join(process.cwd(), '.data');
    const credsPath = path.join(dataDir, 'credentials.json');
    expect(fs.existsSync(credsPath)).toBe(true);
    const creds = JSON.parse(fs.readFileSync(credsPath, 'utf8'));
    expect(creds[registeredUserId]).toBeDefined();
    expect(creds[registeredUserId].hash).toBe(passwordRecord!.hash);

    // Verify scrypt hash matches candidate password
    const isMatch = verifyPassword(testUser.password, passwordRecord!);
    expect(isMatch).toBe(true);
  });

  it('Step 4 & 5: Log in with registered credentials and verify session cookie without leaking secrets', async () => {
    const req = makePost('/api/auth/login', {
      email: testUser.email,
      password: testUser.password,
    });

    const res = await loginRoute(req);
    expect(res.status).toBe(200);

    const json = await res.json();
    expect(json.success).toBe(true);
    expect(json.data.user.id).toBe(registeredUserId);
    expect(json.data.user.email).toBe(testUser.email.toLowerCase());
    expect(json.data.user.role).toBe(testUser.role);

    // Verify session cookie was set
    const cookieHeader = res.cookies.get(SESSION_COOKIE);
    expect(cookieHeader).toBeDefined();
    expect(cookieHeader?.httpOnly).toBe(true);
    expect(cookieHeader?.sameSite).toBe('lax');
    expect(cookieHeader?.path).toBe('/');
    expect(typeof cookieHeader?.value).toBe('string');
    expect(cookieHeader?.value.length).toBeGreaterThan(32);

    sessionTokenString = cookieHeader!.value;
    cookieJar.current[SESSION_COOKIE] = sessionTokenString;

    // Verify session token cryptographically
    const sessionPayload = await verifySessionToken(sessionTokenString);
    expect(sessionPayload).not.toBeNull();
    expect(sessionPayload?.id).toBe(registeredUserId);
    expect(sessionPayload?.email).toBe(testUser.email.toLowerCase());
    expect(sessionPayload?.role).toBe(testUser.role);
  });

  it('Step 6: Call /api/auth/me using resulting session and verify user and role', async () => {
    const res = await meRoute();
    expect(res.status).toBe(200);

    const json = await res.json();
    expect(json.success).toBe(true);
    expect(json.data).toEqual({
      id: registeredUserId,
      email: testUser.email.toLowerCase(),
      full_name: testUser.fullName,
      role: testUser.role,
    });
  });

  it('Step 7: Verify an incorrect password fails with 401 Unauthorized', async () => {
    const req = makePost('/api/auth/login', {
      email: testUser.email,
      password: 'IncorrectPassword999!',
    });

    const res = await loginRoute(req);
    expect(res.status).toBe(401);

    const json = await res.json();
    expect(json.success).toBe(false);
    expect(json.error).toMatch(/Invalid email or password/i);
  });

  it('Step 8: Verify an inactive account is rejected with 403 Forbidden', async () => {
    // Deactivate user in database
    await mutateStore((store) => {
      const u = store.users.find((entry) => entry.id === registeredUserId);
      if (u) u.is_active = false;
    });

    try {
      const req = makePost('/api/auth/login', {
        email: testUser.email,
        password: testUser.password,
      });

      const res = await loginRoute(req);
      expect(res.status).toBe(403);

      const json = await res.json();
      expect(json.success).toBe(false);
      expect(json.error).toMatch(/account.*inactive|deactivated/i);
    } finally {
      // Re-activate user
      await mutateStore((store) => {
        const u = store.users.find((entry) => entry.id === registeredUserId);
        if (u) u.is_active = true;
      });
    }
  });

  it('Step 9: Verify existing demo accounts still work', async () => {
    const demoAccounts = [
      { email: 'owner@example.com', role: 'owner' },
      { email: 'admin@example.com', role: 'admin' },
      { email: 'viewer@example.com', role: 'viewer' },
    ];

    for (const demo of demoAccounts) {
      const req = makePost('/api/auth/login', {
        email: demo.email,
        password: process.env.DEMO_PASSWORD!,
      });

      const res = await loginRoute(req);
      expect(res.status).toBe(200);

      const json = await res.json();
      expect(json.success).toBe(true);
      expect(json.data.user.email).toBe(demo.email);
      expect(json.data.user.role).toBe(demo.role);

      const cookie = res.cookies.get(SESSION_COOKIE);
      expect(cookie).toBeDefined();
      expect(cookie?.value.length).toBeGreaterThan(32);
    }
  });

  it('Step 10: Verify duplicate registration with same email is rejected with 409 Conflict', async () => {
    const req = makePost('/api/auth/register', {
      full_name: 'Imposter User',
      email: testUser.email.toUpperCase(), // Test case-insensitive duplicate rejection
      password: 'DifferentPassword456!',
      role: 'viewer',
    });

    const res = await registerRoute(req);
    expect(res.status).toBe(409);

    const json = await res.json();
    expect(json.success).toBe(false);
    expect(json.error).toMatch(/already exists|already registered|already in use/i);

    // Verify existing user was not overwritten
    const user = findUserById(registeredUserId);
    expect(user?.full_name).toBe(testUser.fullName);
    expect(user?.role).toBe(testUser.role);
  });

  it('Step 11: Simulate server restart / fresh read and verify registered account remains available', async () => {
    // Read raw store file from disk directly to simulate fresh boot without in-memory cache
    const dataDir = process.env.DATA_DIR || path.join(process.cwd(), '.data');
    const storePath = path.join(dataDir, 'store.json');
    const rawContent = fs.readFileSync(storePath, 'utf8');
    const freshStore = JSON.parse(rawContent);

    const userInFreshStore = freshStore.users.find(
      (u: { id: string }) => u.id === registeredUserId
    );
    expect(userInFreshStore).toBeDefined();
    expect(userInFreshStore.email).toBe(testUser.email.toLowerCase());

    // Verify login succeeds against the fresh read
    const req = makePost('/api/auth/login', {
      email: testUser.email,
      password: testUser.password,
    });

    const res = await loginRoute(req);
    expect(res.status).toBe(200);

    const json = await res.json();
    expect(json.success).toBe(true);
    expect(json.data.user.id).toBe(registeredUserId);
  });
});
