import { createClient } from '@/lib/supabase/server';
import { logAuditEvent } from '@/lib/audit';
import { getRequestMeta } from '@/lib/auth';
import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';

const loginSchema = z.object({
  email: z.string().email('Invalid email address'),
  password: z.string().min(6, 'Password must be at least 6 characters'),
});

/**
 * POST /api/auth/login
 * Public endpoint. Authenticates user with email/password.
 * Audit: logs login and login_failure events.
 */
export async function POST(request: NextRequest) {
  const { ipAddress, userAgent } = await getRequestMeta();

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
    const supabase = await createClient();

    const { data, error } = await supabase.auth.signInWithPassword({
      email,
      password,
    });

    if (error || !data.user) {
      // Log failed login attempt
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

    // Log successful login
    await logAuditEvent({
      actorId: data.user.id,
      actorEmail: email,
      action: 'login',
      result: 'allowed',
      ipAddress,
      userAgent,
    });

    return NextResponse.json({
      success: true,
      data: {
        user: {
          id: data.user.id,
          email: data.user.email,
        },
      },
    });
  } catch {
    return NextResponse.json(
      { success: false, error: 'Internal server error' },
      { status: 500 }
    );
  }
}
