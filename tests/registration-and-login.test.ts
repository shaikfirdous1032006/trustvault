import { describe, it, expect, vi, beforeEach } from 'vitest';
import { NextRequest } from 'next/server';
import { getStore, mutateStore, findUserByEmail } from '@/lib/local-db';
import { getPasswordRecord, verifyPassword } from '@/lib/passwords';
import { SESSION_COOKIE, verifySessionToken } from '@/lib/session';

const cookieJar = vi.hoisted(() => ({ current: {} as Record<string, string> }));

let mockIpCounter = 1;

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
    mockIpCounter += 1;
    return new Headers({
      'x-forwarded-for': `198.51.100.${mockIpCounter}`,
      'user-agent': 'Vitest-Auth-Suite',
    });
  },
}));

import { POST as registerRoute } from '@/app/api/auth/register/route';
import { POST as loginRoute } from '@/app/api/auth/login/route';
import { GET as meRoute } from '@/app/api/auth/me/route';
import { POST as logoutRoute } from '@/app/api/auth/logout/route';

const ORIGIN = 'http://localhost:3000';

function post(url: string, body: unknown, cookieHeader?: string) {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    Origin: ORIGIN,
  };
  if (cookieHeader) {
    headers['Cookie'] = cookieHeader;
  }
  return new NextRequest(`${ORIGIN}${url}`, {
    method: 'POST',
    headers,
    body: JSON.stringify(body),
  });
}

function get(url: string, cookieHeader?: string) {
  const headers: Record<string, string> = {
    Origin: ORIGIN,
  };
  if (cookieHeader) {
    headers['Cookie'] = cookieHeader;
  }
  return new NextRequest(`${ORIGIN}${url}`, {
    method: 'GET',
    headers,
  });
}

describe('Registered User Authentication End-to-End Suite', () => {
  beforeEach(() => {
    cookieJar.current = {};
    process.env.SESSION_SECRET = 'e7cb79cf640dd4e9f5d7d69964b93113c839db6ff18ae6a939986c437409225a';
    process.env.DEMO_PASSWORD = 'TrustVault2024!';
  });

  it('1. Successfully registers an account and logs in with the registered credentials', async () => {
    const email = `engineer_${Date.now()}@testcompany.org`;
    const password = 'SuperSecretPassword2026!';

    // Register
    const regReq = post('/api/auth/register', {
      full_name: 'Test Engineer',
      email,
      password,
      role: 'owner',
    });
    const regRes = await registerRoute(regReq);
    expect(regRes.status).toBe(201);
    const regData = await regRes.json();
    expect(regData.success).toBe(true);
    expect(regData.data.user.email).toBe(email.toLowerCase());
    expect(regData.data.user.role).toBe('owner');

    // Login with same credentials
    const loginReq = post('/api/auth/login', {
      email,
      password,
    });
    const loginRes = await loginRoute(loginReq);
    expect(loginRes.status).toBe(200);
    const loginData = await loginRes.json();
    expect(loginData.success).toBe(true);
    expect(loginData.data.user.email).toBe(email.toLowerCase());
    expect(loginData.data.user.role).toBe('owner');

    // Verify session cookie was set
    const setCookie = loginRes.cookies.get(SESSION_COOKIE);
    expect(setCookie).toBeDefined();
    expect(setCookie?.value).toBeTruthy();

    // Verify session payload is valid
    const session = await verifySessionToken(setCookie!.value);
    expect(session).not.toBeNull();
    expect(session?.email).toBe(email.toLowerCase());
    expect(session?.role).toBe('owner');
  });

  it('2. Rejects login with incorrect password for a registered user', async () => {
    const email = `wrongpass_${Date.now()}@testcompany.org`;
    const password = 'CorrectPassword123!';

    await registerRoute(
      post('/api/auth/register', {
        full_name: 'Wrong Pass User',
        email,
        password,
        role: 'viewer',
      })
    );

    const loginRes = await loginRoute(
      post('/api/auth/login', {
        email,
        password: 'IncorrectPassword999!',
      })
    );

    expect(loginRes.status).toBe(401);
    const data = await loginRes.json();
    expect(data.success).toBe(false);
    expect(data.error).toBe('Invalid email or password');
    expect(loginRes.cookies.get(SESSION_COOKIE)).toBeUndefined();
  });

  it('3. Rejects login with an unknown email', async () => {
    const loginRes = await loginRoute(
      post('/api/auth/login', {
        email: `nonexistent_${Date.now()}@nowhere.com`,
        password: 'SomePassword123!',
      })
    );

    expect(loginRes.status).toBe(401);
    const data = await loginRes.json();
    expect(data.success).toBe(false);
    expect(data.error).toBe('Invalid email or password');
  });

  it('4. Handles email lookup case-insensitively and whitespace-tolerantly across register and login', async () => {
    const baseEmail = `casetest_${Date.now()}@DOMAIN.com`;
    const password = 'ValidPassword123!';

    // Register with mixed casing and surrounding spaces
    const regRes = await registerRoute(
      post('/api/auth/register', {
        full_name: 'Case Sensitive Tester',
        email: `   ${baseEmail}   `,
        password,
        role: 'viewer',
      })
    );
    expect(regRes.status).toBe(201);

    // Login with lowercase and different whitespace
    const loginRes = await loginRoute(
      post('/api/auth/login', {
        email: `  ${baseEmail.toLowerCase()}  `,
        password,
      })
    );
    expect(loginRes.status).toBe(200);
    const data = await loginRes.json();
    expect(data.success).toBe(true);
    expect(data.data.user.email).toBe(baseEmail.trim().toLowerCase());
  });

  it('5. Rejects duplicate registration with case-insensitive check without overwriting existing user', async () => {
    const email = `duplicate_${Date.now()}@testcompany.org`;
    const passwordOriginal = 'OriginalPassword123!';

    // First registration
    const firstReg = await registerRoute(
      post('/api/auth/register', {
        full_name: 'First Registerer',
        email,
        password: passwordOriginal,
        role: 'viewer',
      })
    );
    expect(firstReg.status).toBe(201);

    // Attempt second registration with different casing
    const secondReg = await registerRoute(
      post('/api/auth/register', {
        full_name: 'Malicious Overwriter',
        email: email.toUpperCase(),
        password: 'NewAttackerPassword999!',
        role: 'owner',
      })
    );
    expect(secondReg.status).toBe(409);
    const errData = await secondReg.json();
    expect(errData.error).toBe('An account with this email already exists.');

    // Original user credentials still intact
    const originalLogin = await loginRoute(
      post('/api/auth/login', {
        email,
        password: passwordOriginal,
      })
    );
    expect(originalLogin.status).toBe(200);
    const data = await originalLogin.json();
    expect(data.data.user.full_name).toBe('First Registerer');
    expect(data.data.user.role).toBe('viewer');
  });

  it('6. Rejects registration attempting to grant admin role', async () => {
    const email = `attacker_admin_${Date.now()}@testcompany.org`;
    const regRes = await registerRoute(
      post('/api/auth/register', {
        full_name: 'Attacker Admin',
        email,
        password: 'Password123!',
        role: 'admin',
      })
    );
    expect(regRes.status).toBe(400);
    const data = await regRes.json();
    expect(data.success).toBe(false);
  });

  it('7. Prevents deactivated/inactive users from logging in with 403 Forbidden', async () => {
    const email = `deactivated_${Date.now()}@testcompany.org`;
    const password = 'ActivePassword123!';

    // Register active user
    await registerRoute(
      post('/api/auth/register', {
        full_name: 'Deactivated User',
        email,
        password,
        role: 'viewer',
      })
    );

    // Deactivate user in authoritative store
    await mutateStore((store) => {
      const u = store.users.find((user) => user.email === email.toLowerCase());
      if (u) {
        u.is_active = false;
      }
    });

    // Attempt login with valid password
    const loginRes = await loginRoute(
      post('/api/auth/login', {
        email,
        password,
      })
    );
    expect(loginRes.status).toBe(403);
    const data = await loginRes.json();
    expect(data.success).toBe(false);
    expect(data.error).toContain('deactivated');
    expect(loginRes.cookies.get(SESSION_COOKIE)).toBeUndefined();
  });

  it('8. /api/auth/me recognizes the authenticated registered user session', async () => {
    const email = `me_test_${Date.now()}@testcompany.org`;
    const password = 'MeTestPassword123!';

    await registerRoute(
      post('/api/auth/register', {
        full_name: 'Me Endpoint User',
        email,
        password,
        role: 'owner',
      })
    );

    const loginRes = await loginRoute(post('/api/auth/login', { email, password }));
    const sessionToken = loginRes.cookies.get(SESSION_COOKIE)?.value;
    expect(sessionToken).toBeDefined();

    // Populate cookieJar for server components / next/headers mock
    cookieJar.current[SESSION_COOKIE] = sessionToken!;

    const meRes = await meRoute();
    expect(meRes.status).toBe(200);
    const meData = await meRes.json();
    expect(meData.success).toBe(true);
    expect(meData.data.email).toBe(email.toLowerCase());
    expect(meData.data.role).toBe('owner');
    expect(meData.data.full_name).toBe('Me Endpoint User');
  });

  it('9. Logout invalidates the session', async () => {
    const email = `logout_test_${Date.now()}@testcompany.org`;
    const password = 'LogoutPassword123!';

    await registerRoute(
      post('/api/auth/register', {
        full_name: 'Logout User',
        email,
        password,
        role: 'viewer',
      })
    );

    const loginRes = await loginRoute(post('/api/auth/login', { email, password }));
    const token = loginRes.cookies.get(SESSION_COOKIE)!.value;
    cookieJar.current[SESSION_COOKIE] = token;

    const logoutRes = await logoutRoute(
      new NextRequest(`${ORIGIN}/api/auth/logout`, {
        method: 'POST',
        headers: { Origin: ORIGIN },
      })
    );
    expect(logoutRes.status).toBe(200);
    const logoutData = await logoutRes.json();
    expect(logoutData.success).toBe(true);

    // Verify session cookie was deleted
    const cookieHeader = logoutRes.headers.get('set-cookie');
    expect(cookieHeader).toContain('tv_session=;');
  });

  it('10. Existing demo accounts continue to log in seamlessly', async () => {
    const demoAccounts = [
      { email: 'admin@example.com', role: 'admin' },
      { email: 'owner@example.com', role: 'owner' },
      { email: 'viewer@example.com', role: 'viewer' },
    ];

    for (const demo of demoAccounts) {
      const loginRes = await loginRoute(
        post('/api/auth/login', {
          email: demo.email,
          password: 'TrustVault2024!',
        })
      );
      expect(loginRes.status).toBe(200);
      const data = await loginRes.json();
      expect(data.success).toBe(true);
      expect(data.data.user.role).toBe(demo.role);
      expect(loginRes.cookies.get(SESSION_COOKIE)).toBeDefined();
    }
  });

  it('11. Registered users and password hashes persist across requests', async () => {
    const email = `persisted_${Date.now()}@testcompany.org`;
    const password = 'PersistPassword123!';

    await registerRoute(
      post('/api/auth/register', {
        full_name: 'Persistent User',
        email,
        password,
        role: 'owner',
      })
    );

    // Query directly from local-db authoritative store
    const userInDb = findUserByEmail(email);
    expect(userInDb).toBeDefined();
    expect(userInDb?.email).toBe(email.toLowerCase());

    // Query password record from passwords authoritative store
    const cred = getPasswordRecord(userInDb!.id);
    expect(cred).toBeDefined();
    expect(cred?.salt).toHaveLength(32);
    expect(cred?.hash).toHaveLength(128);

    // Verify password matches with scrypt
    const matches = verifyPassword(password, cred!);
    expect(matches).toBe(true);

    const wrongMatches = verifyPassword('WrongPassword', cred!);
    expect(wrongMatches).toBe(false);
  });
});
