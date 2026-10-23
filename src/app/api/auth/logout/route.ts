import { csrfRejection } from '@/lib/security';
import { createClient, isSupabaseConfigured } from '@/lib/supabase/server';
import { logAuditEvent } from '@/lib/audit';
import { getRequestMeta, getAuthenticatedUser } from '@/lib/auth';
import { SESSION_COOKIE } from '@/lib/session';
import { NextRequest, NextResponse } from 'next/server';

export async function POST(request: NextRequest) {
  const crossOrigin = csrfRejection(request);
  if (crossOrigin) return crossOrigin;
  const { ipAddress, userAgent } = await getRequestMeta();

  try {
    const user = await getAuthenticatedUser();

    if (user) {
      await logAuditEvent({
        actorId: user.id,
        actorEmail: user.email,
        action: 'LOGOUT_SUCCESS',
        result: 'allowed',
        ipAddress,
        userAgent,
        details: { status: 'Success', outcome: 'SUCCESS', action_label: 'Signed Out' },
      });
    }

    if (isSupabaseConfigured()) {
      try {
        const supabase = await createClient();
        await supabase.auth.signOut();
      } catch {
        // ignore
      }
    }

    const res = NextResponse.json({ success: true, message: 'Logged out' });
    res.cookies.delete(SESSION_COOKIE);
    res.cookies.delete('trustvault_demo_session');
    return res;
  } catch {
    const res = NextResponse.json(
      { success: false, error: 'Internal server error' },
      { status: 500 }
    );
    res.cookies.delete(SESSION_COOKIE);
    return res;
  }
}
