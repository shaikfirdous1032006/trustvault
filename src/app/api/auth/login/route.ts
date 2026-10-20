import { createClient, isSupabaseConfigured } from '@/lib/supabase/server';
import { logAuditEvent } from '@/lib/audit';
import { getRequestMeta } from '@/lib/auth';
import { findUserByEmail } from '@/lib/local-db';
import { createSessionToken, SESSION_COOKIE } from '@/lib/session';
import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';

import { checkRateLimit } from '@/lib/security';

const loginSchema = z.object({
  email: z.string().email('Invalid email address'),
  password: z.string().min(6, 'Password must be at least 6 characters'),
});

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
  const { ipAddress, userAgent } = await getRequestMeta();

  // Enforce rate limiting: 10 attempts per minute per IP
  const clientKey = ipAddress || 'unknown-client';
  const rateLimit = checkRateLimit(`login:${clientKey}`, 10, 60_000);
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
      { success: false, error: 'Too many login attempts. Please try again later.' },
      {
        status: 429,
        headers: { 'Retry-After': Math.ceil(rateLimit.resetMs / 1000).toString() },
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

    const { email, password } = parsed.data;

    if (!isSupabaseConfigured()) {
      const demoUser = findUserByEmail(email);
      const validPassword = process.env.DEMO_PASSWORD || 'TrustVault2024!';

      if (demoUser && demoUser.is_active && password === validPassword) {
        await logAuditEvent({
          actorId: demoUser.id,
          actorEmail: email,
          action: 'login',
          result: 'allowed',
          ipAddress,
          userAgent,
        });

        const token = await createSessionToken(demoUser);
        const res = NextResponse.json({
          success: true,
          data: {
            user: {
              id: demoUser.id,
              email: demoUser.email,
              role: demoUser.role,
              full_name: demoUser.full_name,
            },
          },
        });
        res.cookies.set(sessionCookie(token));
        return res;
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
        details: { reason: error?.message || 'Unknown error' },
      });

      return NextResponse.json(
        { success: false, error: 'Invalid credentials' },
        { status: 401 }
      );
    }

    const { data: profile } = await supabase
      .from('users')
      .select('*')
      .eq('id', data.user.id)
      .single();

    await logAuditEvent({
      actorId: data.user.id,
      actorEmail: email,
      action: 'login',
      result: 'allowed',
      ipAddress,
      userAgent,
    });

    const token = await createSessionToken(
      profile || {
        id: data.user.id,
        email: data.user.email || email,
        role: 'viewer',
        full_name: null,
        is_active: true,
      }
    );

    const res = NextResponse.json({
      success: true,
      data: {
        user: {
          id: data.user.id,
          email: data.user.email,
          role: profile?.role,
          full_name: profile?.full_name,
        },
      },
    });
    res.cookies.set(sessionCookie(token));
    return res;
  } catch {
    return NextResponse.json(
      { success: false, error: 'Internal server error' },
      { status: 500 }
    );
  }
}
