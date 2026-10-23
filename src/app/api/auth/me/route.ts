import { NextRequest, NextResponse } from 'next/server';
import { getAuthenticatedUser, getRequestMeta } from '@/lib/auth';
import { logAuditEvent } from '@/lib/audit';
import { isSupabaseConfigured, createClient } from '@/lib/supabase/server';
import { mutateStore } from '@/lib/local-db';
import { csrfRejection } from '@/lib/security';
import { z } from 'zod';

export const dynamic = 'force-dynamic';

const profileSchema = z.object({
  full_name: z.string().trim().min(1, 'Name cannot be empty').max(100),
});

export async function GET() {
  try {
    const user = await getAuthenticatedUser();
    if (!user) {
      return NextResponse.json({ success: false, error: 'Unauthorized' }, { status: 401 });
    }
    if (!user.is_active) {
      return NextResponse.json({ success: false, error: 'Account is deactivated' }, { status: 403 });
    }

    return NextResponse.json({
      success: true,
      data: {
        id: user.id,
        email: user.email,
        full_name: user.full_name,
        role: user.role,
      },
    });
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : 'Server error';
    return NextResponse.json({ success: false, error: message }, { status: 500 });
  }
}

export async function PATCH(request: NextRequest) {
  const crossOrigin = csrfRejection(request);
  if (crossOrigin) return crossOrigin;

  const { ipAddress, userAgent } = await getRequestMeta();

  try {
    const user = await getAuthenticatedUser();
    if (!user) {
      await logAuditEvent({
        actorId: null,
        actorEmail: null,
        action: 'profile_update',
        result: 'denied',
        ipAddress,
        userAgent,
        details: { reason: 'Unauthenticated attempt' },
      });
      return NextResponse.json({ success: false, error: 'Unauthorized' }, { status: 401 });
    }

    if (!user.is_active) {
      await logAuditEvent({
        actorId: user.id,
        actorEmail: user.email,
        action: 'profile_update',
        result: 'denied',
        ipAddress,
        userAgent,
        details: { reason: 'Account deactivated' },
      });
      return NextResponse.json({ success: false, error: 'Account is deactivated' }, { status: 403 });
    }

    const body = await request.json();
    const parsed = profileSchema.safeParse(body);
    if (!parsed.success) {
      return NextResponse.json(
        { success: false, error: parsed.error.issues[0]?.message || 'Invalid profile data' },
        { status: 400 }
      );
    }

    const newFullName = parsed.data.full_name;
    const oldFullName = user.full_name;

    if (!isSupabaseConfigured()) {
      await mutateStore((store) => {
        const u = store.users.find((usr) => usr.id === user.id);
        if (u) {
          u.full_name = newFullName;
          u.updated_at = new Date().toISOString();
        }
      });
    } else {
      const supabase = await createClient();
      const { error } = await supabase
        .from('users')
        .update({ full_name: newFullName, updated_at: new Date().toISOString() })
        .eq('id', user.id);

      if (error) {
        await logAuditEvent({
          actorId: user.id,
          actorEmail: user.email,
          action: 'profile_update',
          result: 'denied',
          ipAddress,
          userAgent,
          targetResourceType: 'user',
          targetResourceId: user.id,
          details: { error: error.message },
        });
        return NextResponse.json({ success: false, error: 'Failed to update profile' }, { status: 500 });
      }
    }

    await logAuditEvent({
      actorId: user.id,
      actorEmail: user.email,
      action: 'profile_update',
      result: 'allowed',
      ipAddress,
      userAgent,
      targetResourceType: 'user',
      targetResourceId: user.id,
      description: `${user.email} updated profile full name to "${newFullName}"`,
      details: {
        previous_name: oldFullName,
        new_name: newFullName,
      },
    });

    return NextResponse.json({
      success: true,
      data: {
        id: user.id,
        email: user.email,
        full_name: newFullName,
        role: user.role,
      },
      message: 'Profile updated successfully',
    });
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : 'Server error';
    return NextResponse.json({ success: false, error: message }, { status: 500 });
  }
}

