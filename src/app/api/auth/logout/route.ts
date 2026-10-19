import { createClient } from '@/lib/supabase/server';
import { logAuditEvent } from '@/lib/audit';
import { getRequestMeta, getAuthenticatedUser } from '@/lib/auth';
import { NextRequest, NextResponse } from 'next/server';

/**
 * POST /api/auth/logout
 * Authenticated endpoint. Signs out the current user.
 * Audit: logs logout event.
 */
export async function POST(request: NextRequest) {
  const { ipAddress, userAgent } = await getRequestMeta();

  try {
    const user = await getAuthenticatedUser();
    const supabase = await createClient();

    await supabase.auth.signOut();

    if (user) {
      await logAuditEvent({
        actorId: user.id,
        actorEmail: user.email,
        action: 'logout',
        result: 'allowed',
        ipAddress,
        userAgent,
      });
    }

    return NextResponse.json({ success: true, message: 'Logged out' });
  } catch {
    return NextResponse.json(
      { success: false, error: 'Internal server error' },
      { status: 500 }
    );
  }
}
