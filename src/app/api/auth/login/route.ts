import { createClient, isSupabaseConfigured } from '@/lib/supabase/server';
import { logAuditEvent } from '@/lib/audit';
import { getRequestMeta } from '@/lib/auth';
import { DEMO_IDS, findUserByEmail } from '@/lib/local-db';
import { getPasswordRecord, savePasswordRecord, verifyPassword } from '@/lib/passwords';
import {
  createSessionToken,
  SESSION_COOKIE,
  SessionConfigError,
} from '@/lib/session';
import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { createHash, timingSafeEqual } from 'node:crypto';
import { checkRateLimit, csrfRejection } from '@/lib/security';

const loginSchema = z.object({
  email: z.string().trim().email('Invalid email address').max(254),
  password: z.string().min(1, 'Password is required').max(200),
});

function passwordMatches(candidate: string, expected: string): boolean {
  const a = createHash('sha256').update(candidate).digest();
  const b = createHash('sha256').update(expected).digest();
  return timingSafeEqual(a, b);
}

function sessionCookie(token: string) {
  return {
    name: SESSION_COOKIE,
    value: token,
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax' as const,
    path: '/',
    maxAge: 86400,
  };
}

export async function POST(request: NextRequest) {
  const crossOrigin = csrfRejection(request);
  if (crossOrigin) return crossOrigin;

  const { ipAddress, userAgent } = await getRequestMeta();

  const rateLimit = checkRateLimit(
    `login:${ipAddress || 'unknown-client'}`,
    10,
    60_000
  );

  if (!rateLimit.allowed) {
    await logAuditEvent({
      actorId: null,
      actorEmail: null,
      action: 'login_failure',
      result: 'denied',
      ipAddress,
      userAgent,
      details: { reason: 'Rate limit exceeded' },
    });

    return NextResponse.json(
      {
        success: false,
        error: 'Too many login attempts. Please try again later.',
      },
      {
        status: 429,
        headers: {
          'Retry-After': String(Math.ceil(rateLimit.resetMs / 1000)),
        },
      }
    );
  }

  try {
    const body = await request.json();
    const parsed = loginSchema.safeParse(body);

    if (!parsed.success) {
      return NextResponse.json(
        { success: false, error: 'Invalid email or password format' },
        { status: 400 }
      );
    }

    const email = parsed.data.email.toLowerCase();
    const password = parsed.data.password;

    if (!isSupabaseConfigured()) {
      let user = findUserByEmail(email);

      if (!user) {
        try {
          const { findCookieAccount } = await import('@/lib/cookie-accounts');
          const cookieAccount = findCookieAccount(request, email);
          if (cookieAccount) {
            user = cookieAccount.user;
          }
        } catch {
          // ignore
        }
      }

      if (!user) {
        try {
          const { getMongoDb, isMongoConfigured } = await import('@/lib/mongodb');
          if (isMongoConfigured()) {
            const db = await getMongoDb();
            const mongoUser = await db.collection('users').findOne({ email });
            if (mongoUser) {
              const cleanUser = { ...mongoUser };
              delete (cleanUser as Record<string, unknown>)._id;
              user = cleanUser as typeof user;
            }
          }
        } catch {
          // ignore
        }
      }

      const demoPassword = (process.env.DEMO_PASSWORD || 'TrustVault2024!').trim();
      if (!demoPassword) {
        return NextResponse.json(
          {
            success: false,
            error: 'Demo sign-in is disabled. Configure DEMO_PASSWORD.',
          },
          { status: 503 }
        );
      }

      let credential = user ? getPasswordRecord(user.id) : undefined;
      if (!credential && user) {
        try {
          const { findCookieAccount } = await import('@/lib/cookie-accounts');
          const cookieAccount = findCookieAccount(request, email);
          if (cookieAccount) {
            credential = { salt: cookieAccount.salt, hash: cookieAccount.hash };
          }
        } catch {
          // ignore
        }
      }

      if (!credential && user) {
        try {
          const { getMongoDb, isMongoConfigured } = await import('@/lib/mongodb');
          if (isMongoConfigured()) {
            const db = await getMongoDb();
            const doc = await db.collection('credentials').findOne({ user_id: user.id });
            if (doc && doc.salt && doc.hash) {
              credential = { salt: doc.salt, hash: doc.hash };
              savePasswordRecord(user.id, credential);
            }
          }
        } catch {
          // ignore
        }
      }

      const seededDemoIds: string[] = [
        DEMO_IDS.admin,
        DEMO_IDS.owner,
        DEMO_IDS.viewer,
        'b1141308-259c-4ebe-85bc-10056166b582',
      ];

      const isSeededDemo =
        !!user && seededDemoIds.includes(user.id);

      let validPassword = false;

      if (credential) {
        validPassword = verifyPassword(password, credential);
        if (!validPassword && isSeededDemo) {
          validPassword = passwordMatches(password.trim(), demoPassword);
        }
      } else if (isSeededDemo) {
        validPassword = passwordMatches(
          password.trim(),
          demoPassword
        );
      }

      if (user && user.is_active && validPassword) {
        await logAuditEvent({
          actorId: user.id,
          actorEmail: user.email,
          action: 'login',
          result: 'allowed',
          ipAddress,
          userAgent,
        });

        const token = await createSessionToken(user);

        const response = NextResponse.json({
          success: true,
          data: {
            user: {
              id: user.id,
              email: user.email,
              role: user.role,
              full_name: user.full_name,
            },
          },
        });

        response.cookies.set(sessionCookie(token));
        return response;
      }

      await logAuditEvent({
        actorId: null,
        actorEmail: email,
        action: 'login_failure',
        result: 'denied',
        ipAddress,
        userAgent,
        details: { reason: 'Invalid credentials' },
      });

      return NextResponse.json(
        { success: false, error: 'Invalid credentials' },
        { status: 401 }
      );
    }

    const supabase = await createClient();

    const { data, error } = await supabase.auth.signInWithPassword({
      email,
      password,
    });

    if (error || !data.user) {
      await logAuditEvent({
        actorId: null,
        actorEmail: email,
        action: 'login_failure',
        result: 'denied',
        ipAddress,
        userAgent,
        details: { reason: 'Invalid credentials' },
      });

      return NextResponse.json(
        { success: false, error: 'Invalid credentials' },
        { status: 401 }
      );
    }

   
const { data: profile, error: profileError } = await supabase
  .from('users')
  .select('*')
  .eq('id', data.user.id)
  .maybeSingle();

if (profileError || !profile) {
  await supabase.auth.signOut();

  await logAuditEvent({
    actorId: data.user.id,
    actorEmail: email,
    action: 'login_failure',
    result: 'denied',
    ipAddress,
    userAgent,
    details: { reason: 'Missing or unreadable user profile' },
  });

  return NextResponse.json(
    { success: false, error: 'Unable to verify account. Contact an administrator.' },
    { status: 403 }
  );
}
    if (profile && profile.is_active === false) {
      await supabase.auth.signOut();

      await logAuditEvent({
        actorId: data.user.id,
        actorEmail: email,
        action: 'login_failure',
        result: 'denied',
        ipAddress,
        userAgent,
        details: { reason: 'Inactive account' },
      });

      return NextResponse.json(
        { success: false, error: 'This account is inactive.' },
        { status: 403 }
      );
    }
const sessionUser = profile;
    
    await logAuditEvent({
      actorId: data.user.id,
      actorEmail: email,
      action: 'login',
      result: 'allowed',
      ipAddress,
      userAgent,
    });

    const token = await createSessionToken(sessionUser);

    const response = NextResponse.json({
      success: true,
      data: {
        user: {
          id: data.user.id,
          email: data.user.email || email,
          role: sessionUser.role,
          full_name: sessionUser.full_name,
        },
      },
    });

    response.cookies.set(sessionCookie(token));
    return response;
  } catch (err) {
    if (err instanceof SessionConfigError) {
      console.error('[SECURITY] Login session configuration error.');

      return NextResponse.json(
        {
          success: false,
          error: 'Server session signing is not configured. Set SESSION_SECRET.',
        },
        { status: 503 }
      );
    }

    console.error('[AUTH] Login failed:', err);

    return NextResponse.json(
      { success: false, error: 'Internal server error' },
      { status: 500 }
    );
  }
}