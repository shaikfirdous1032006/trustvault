import { createClient, isSupabaseConfigured } from '@/lib/supabase/server';
import { logAuditEvent } from '@/lib/audit';
import { getRequestMeta } from '@/lib/auth';
import { DEMO_IDS, findUserByEmail } from '@/lib/local-db';
import { getPasswordRecordAsync, verifyPassword } from '@/lib/passwords';
import {
  createSessionToken,
  SESSION_COOKIE,
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
      action: 'LOGIN_FAILED',
      result: 'denied',
      ipAddress,
      userAgent,
      details: { reason: 'Rate limit exceeded', status: 'Failed', outcome: 'FAILED', action_label: 'Login Failed' },
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

    const normalizedEmail = parsed.data.email.trim().toLowerCase();
    const password = parsed.data.password;

    if (!isSupabaseConfigured()) {
      const user = findUserByEmail(normalizedEmail);

      if (!user) {
        await logAuditEvent({
          actorId: null,
          actorEmail: normalizedEmail,
          action: 'LOGIN_FAILED',
          result: 'denied',
          ipAddress,
          userAgent,
          details: { reason: 'User not found', status: 'Failed', outcome: 'FAILED', action_label: 'Login Failed' },
        });

        return NextResponse.json(
          { success: false, error: 'Invalid email or password' },
          { status: 401 }
        );
      }

      const credential = await getPasswordRecordAsync(user.id);
      const seededDemoIds: string[] = [
        DEMO_IDS.admin,
        DEMO_IDS.owner,
        DEMO_IDS.viewer,
      ];
      const isSeededDemo = seededDemoIds.includes(user.id);

      let validPassword = false;

      if (credential) {
        validPassword = verifyPassword(password, credential);
      } else if (isSeededDemo) {
        const demoPassword = (process.env.DEMO_PASSWORD || 'TrustVault2024!').trim();
        if (demoPassword) {
          validPassword = passwordMatches(password.trim(), demoPassword);
        }
      }

      if (!validPassword) {
        await logAuditEvent({
          actorId: null,
          actorEmail: normalizedEmail,
          action: 'LOGIN_FAILED',
          result: 'denied',
          ipAddress,
          userAgent,
          details: { reason: 'Incorrect password', status: 'Failed', outcome: 'FAILED', action_label: 'Login Failed' },
        });

        return NextResponse.json(
          { success: false, error: 'Invalid email or password' },
          { status: 401 }
        );
      }

      if (!user.is_active) {
        await logAuditEvent({
          actorId: user.id,
          actorEmail: user.email,
          action: 'LOGIN_FAILED',
          result: 'denied',
          ipAddress,
          userAgent,
          details: { reason: 'Account inactive', status: 'Failed', outcome: 'FAILED', action_label: 'Login Failed' },
        });

        return NextResponse.json(
          { success: false, error: 'Account is deactivated. Please contact support.' },
          { status: 403 }
        );
      }

      await logAuditEvent({
        actorId: user.id,
        actorEmail: user.email,
        action: 'LOGIN_SUCCESS',
        result: 'allowed',
        ipAddress,
        userAgent,
        details: { status: 'Success', outcome: 'SUCCESS', action_label: 'Signed In', role: user.role },
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

    // Supabase Mode
    const supabase = await createClient();

    const { data, error } = await supabase.auth.signInWithPassword({
      email: normalizedEmail,
      password,
    });

    if (error || !data.user) {
      await logAuditEvent({
        actorId: null,
        actorEmail: normalizedEmail,
        action: 'LOGIN_FAILED',
        result: 'denied',
        ipAddress,
        userAgent,
        details: { reason: 'Invalid credentials', status: 'Failed', outcome: 'FAILED', action_label: 'Login Failed' },
      });

      return NextResponse.json(
        { success: false, error: 'Invalid email or password' },
        { status: 401 }
      );
    }

    const { data: profile } = await supabase
      .from('users')
      .select('*')
      .eq('id', data.user.id)
      .single();

    if (!profile || profile.is_active === false) {
      await logAuditEvent({
        actorId: data.user.id,
        actorEmail: data.user.email || normalizedEmail,
        action: 'LOGIN_FAILED',
        result: 'denied',
        ipAddress,
        userAgent,
        details: { reason: 'Account inactive', status: 'Failed', outcome: 'FAILED', action_label: 'Login Failed' },
      });

      return NextResponse.json(
        { success: false, error: 'Account is deactivated. Please contact support.' },
        { status: 403 }
      );
    }

    await logAuditEvent({
      actorId: data.user.id,
      actorEmail: data.user.email || normalizedEmail,
      action: 'LOGIN_SUCCESS',
      result: 'allowed',
      ipAddress,
      userAgent,
      details: { status: 'Success', outcome: 'SUCCESS', action_label: 'Signed In', role: profile.role || 'viewer' },
    });

    const token = await createSessionToken({
      id: data.user.id,
      email: data.user.email || normalizedEmail,
      role: profile.role || 'viewer',
      full_name: profile.full_name || null,
      is_active: true,
    });

    const response = NextResponse.json({
      success: true,
      data: {
        user: {
          id: data.user.id,
          email: data.user.email,
          role: profile.role || 'viewer',
          full_name: profile.full_name,
        },
      },
    });

    response.cookies.set(sessionCookie(token));
    return response;
  } catch (error) {
    console.error('Login error:', error);
    return NextResponse.json(
      { success: false, error: 'An unexpected error occurred during sign-in' },
      { status: 500 }
    );
  }
}