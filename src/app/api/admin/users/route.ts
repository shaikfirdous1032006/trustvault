import { createClient, createAdminClient, isSupabaseConfigured } from '@/lib/supabase/server';
import { requireRole, AuthorizationError, getRequestMeta } from '@/lib/auth';
import { NextRequest, NextResponse } from 'next/server';
import { getStore, mutateStore } from '@/lib/local-db';
import { logAuditEvent } from '@/lib/audit';
import { z } from 'zod';
import { randomUUID } from 'node:crypto';
import { hashPassword, savePasswordRecord } from '@/lib/passwords';
import type { User, UserRole } from '@/lib/types';

const updateSchema = z.object({
  userId: z.string().min(1),
  role: z.enum(['admin', 'owner', 'viewer']).optional(),
  is_active: z.boolean().optional(),
});

const createUserSchema = z.object({
  email: z.string().trim().email('Invalid email address').max(254),
  full_name: z.string().trim().min(1, 'Name cannot be empty').max(100),
  role: z.enum(['admin', 'owner', 'viewer']),
  password: z.string().min(8, 'Password must be at least 8 characters').optional(),
});

export async function GET(request: NextRequest) {
  try {
    await requireRole(['admin']);
    const searchParams = request.nextUrl.searchParams;
    const page = parseInt(searchParams.get('page') || '1');
    const pageSize = Math.min(parseInt(searchParams.get('pageSize') || '50'), 100);
    const offset = (page - 1) * pageSize;

    if (!isSupabaseConfigured()) {
      const users = getStore().users.slice().sort((a, b) => b.created_at.localeCompare(a.created_at));
      return NextResponse.json({
        success: true,
        data: users.slice(offset, offset + pageSize),
        total: users.length,
        page,
        pageSize,
      });
    }

    const supabase = await createClient();
    const { data: users, count, error } = await supabase
      .from('users')
      .select('*', { count: 'exact' })
      .order('created_at', { ascending: false })
      .range(offset, offset + pageSize - 1);

    if (error) {
      return NextResponse.json({ success: false, error: 'Failed to fetch users' }, { status: 500 });
    }

    return NextResponse.json({
      success: true,
      data: users || [],
      total: count || 0,
      page,
      pageSize,
    });
  } catch (err: unknown) {
    if (err instanceof AuthorizationError) {
      return NextResponse.json({ success: false, error: err.message }, { status: err.statusCode });
    }
    return NextResponse.json({ success: false, error: 'Internal server error' }, { status: 500 });
  }
}

export async function PATCH(request: NextRequest) {
  const { ipAddress, userAgent } = await getRequestMeta();

  try {
    const adminUser = await requireRole(['admin']);
    const body = await request.json();
    const parsed = updateSchema.safeParse(body);

    if (!parsed.success) {
      return NextResponse.json(
        { success: false, error: 'Invalid user update payload', details: parsed.error.flatten() },
        { status: 400 }
      );
    }

    const { userId, role, is_active } = parsed.data;

    // Prevent self-lockout
    if (userId === adminUser.id) {
      if (is_active === false) {
        return NextResponse.json(
          { success: false, error: 'Administrators cannot deactivate their own account' },
          { status: 400 }
        );
      }
      if (role && role !== 'admin') {
        return NextResponse.json(
          { success: false, error: 'Administrators cannot demote their own role' },
          { status: 400 }
        );
      }
    }

    if (!isSupabaseConfigured()) {
      const store = getStore();
      const targetUser = store.users.find((u) => u.id === userId);
      if (!targetUser) {
        return NextResponse.json({ success: false, error: 'User not found' }, { status: 404 });
      }

      const prevRole = targetUser.role;
      const prevActive = targetUser.is_active;

      await mutateStore((s) => {
        const u = s.users.find((usr) => usr.id === userId);
        if (u) {
          if (role !== undefined) u.role = role as UserRole;
          if (is_active !== undefined) u.is_active = is_active;
          u.updated_at = new Date().toISOString();
        }
      });

      if (role !== undefined && role !== prevRole) {
        await logAuditEvent({
          actorId: adminUser.id,
          actorEmail: adminUser.email,
          action: 'role_change',
          result: 'allowed',
          ipAddress,
          userAgent,
          targetResourceType: 'user',
          targetResourceId: userId,
          description: `Admin ${adminUser.email} changed role of ${targetUser.email} from ${prevRole} to ${role}`,
          details: {
            target_user_id: userId,
            target_user_email: targetUser.email,
            previous_role: prevRole,
            new_role: role,
          },
        });
      }

      if (is_active !== undefined && is_active !== prevActive) {
        await logAuditEvent({
          actorId: adminUser.id,
          actorEmail: adminUser.email,
          action: is_active ? 'account_activated' : 'account_deactivated',
          result: 'allowed',
          ipAddress,
          userAgent,
          targetResourceType: 'user',
          targetResourceId: userId,
          description: `Admin ${adminUser.email} ${is_active ? 'activated' : 'deactivated'} account for ${targetUser.email}`,
          details: {
            target_user_id: userId,
            target_user_email: targetUser.email,
            is_active,
          },
        });
      }

      return NextResponse.json({
        success: true,
        data: { id: userId, role: role ?? prevRole, is_active: is_active ?? prevActive },
        message: 'User updated successfully',
      });
    }

    const supabaseAdmin = createAdminClient();
    const { data: targetUser, error: fetchErr } = await supabaseAdmin
      .from('users')
      .select('id, email, role, is_active')
      .eq('id', userId)
      .single();

    if (fetchErr || !targetUser) {
      return NextResponse.json({ success: false, error: 'User not found' }, { status: 404 });
    }

    const updates: Record<string, unknown> = { updated_at: new Date().toISOString() };
    if (role !== undefined) updates.role = role;
    if (is_active !== undefined) updates.is_active = is_active;

    const { error: updateErr } = await supabaseAdmin
      .from('users')
      .update(updates)
      .eq('id', userId);

    if (updateErr) {
      await logAuditEvent({
        actorId: adminUser.id,
        actorEmail: adminUser.email,
        action: 'admin_action',
        result: 'denied',
        ipAddress,
        userAgent,
        targetResourceType: 'user',
        targetResourceId: userId,
        description: `Failed to update user ${targetUser.email}: ${updateErr.message}`,
        details: { target_user_id: userId, error: updateErr.message },
      });

      return NextResponse.json({ success: false, error: 'Failed to update user' }, { status: 500 });
    }

    if (role !== undefined && role !== targetUser.role) {
      await logAuditEvent({
        actorId: adminUser.id,
        actorEmail: adminUser.email,
        action: 'role_change',
        result: 'allowed',
        ipAddress,
        userAgent,
        targetResourceType: 'user',
        targetResourceId: userId,
        description: `Admin ${adminUser.email} changed role of ${targetUser.email} from ${targetUser.role} to ${role}`,
        details: {
          target_user_id: userId,
          target_user_email: targetUser.email,
          previous_role: targetUser.role,
          new_role: role,
        },
      });
    }

    if (is_active !== undefined && is_active !== targetUser.is_active) {
      await logAuditEvent({
        actorId: adminUser.id,
        actorEmail: adminUser.email,
        action: is_active ? 'account_activated' : 'account_deactivated',
        result: 'allowed',
        ipAddress,
        userAgent,
        targetResourceType: 'user',
        targetResourceId: userId,
        description: `Admin ${adminUser.email} ${is_active ? 'activated' : 'deactivated'} account for ${targetUser.email}`,
        details: {
          target_user_id: userId,
          target_user_email: targetUser.email,
          is_active,
        },
      });
    }

    return NextResponse.json({
      success: true,
      data: { id: userId, role: role ?? targetUser.role, is_active: is_active ?? targetUser.is_active },
      message: 'User updated successfully',
    });
  } catch (err: unknown) {
    if (err instanceof AuthorizationError) {
      return NextResponse.json({ success: false, error: err.message }, { status: err.statusCode });
    }
    return NextResponse.json({ success: false, error: 'Internal server error' }, { status: 500 });
  }
}

export async function POST(request: NextRequest) {
  const { ipAddress, userAgent } = await getRequestMeta();

  try {
    const adminUser = await requireRole(['admin']);
    const body = await request.json();
    const parsed = createUserSchema.safeParse(body);

    if (!parsed.success) {
      const errorMsg = parsed.error.issues[0]?.message || 'Invalid user creation payload';
      return NextResponse.json(
        { success: false, error: errorMsg, details: parsed.error.flatten() },
        { status: 400 }
      );
    }

    const { email, full_name, role } = parsed.data;
    const normalizedEmail = email.trim().toLowerCase();
    const rawPassword = parsed.data.password || 'TrustVault2024!';

    if (!isSupabaseConfigured()) {
      const store = getStore();
      const existing = store.users.find((u) => u.email.trim().toLowerCase() === normalizedEmail);

      if (existing) {
        await logAuditEvent({
          actorId: adminUser.id,
          actorEmail: adminUser.email,
          action: 'user_created',
          result: 'denied',
          ipAddress,
          userAgent,
          targetResourceType: 'user',
          description: `Admin ${adminUser.email} failed to create user ${normalizedEmail}: email already in use`,
          details: { target_user_email: normalizedEmail, reason: 'Email already exists' },
        });

        return NextResponse.json({ success: false, error: 'User with this email already exists' }, { status: 409 });
      }

      const now = new Date().toISOString();
      const newUserId = randomUUID();
      const newUser: User = {
        id: newUserId,
        email: normalizedEmail,
        full_name,
        role,
        is_active: true,
        created_at: now,
        updated_at: now,
      };

      const passwordRecord = hashPassword(rawPassword);
      savePasswordRecord(newUserId, passwordRecord);

      await mutateStore((s) => {
        s.users.push(newUser);
      });

      await logAuditEvent({
        actorId: adminUser.id,
        actorEmail: adminUser.email,
        action: 'user_created',
        result: 'allowed',
        ipAddress,
        userAgent,
        targetResourceType: 'user',
        targetResourceId: newUserId,
        description: `Admin ${adminUser.email} created user ${normalizedEmail} with role ${role}`,
        details: {
          target_user_id: newUserId,
          target_user_email: normalizedEmail,
          assigned_role: role,
          operation: 'admin_user_creation',
        },
      });

      return NextResponse.json(
        { success: true, data: newUser, message: 'User created successfully' },
        { status: 201 }
      );
    }

    const supabaseAdmin = createAdminClient();
    const { data: authData, error: authError } = await supabaseAdmin.auth.admin.createUser({
      email: normalizedEmail,
      password: rawPassword,
      email_confirm: true,
      user_metadata: {
        full_name,
        role,
      },
    });

    if (authError || !authData?.user) {
      const reason = authError?.message || 'Failed to create user in authentication directory';
      await logAuditEvent({
        actorId: adminUser.id,
        actorEmail: adminUser.email,
        action: 'user_created',
        result: 'denied',
        ipAddress,
        userAgent,
        targetResourceType: 'user',
        description: `Admin ${adminUser.email} failed to create user ${normalizedEmail}: ${reason}`,
        details: { target_user_email: normalizedEmail, reason },
      });

      return NextResponse.json({ success: false, error: reason }, { status: 400 });
    }

    await logAuditEvent({
      actorId: adminUser.id,
      actorEmail: adminUser.email,
      action: 'user_created',
      result: 'allowed',
      ipAddress,
      userAgent,
      targetResourceType: 'user',
      targetResourceId: authData.user.id,
      description: `Admin ${adminUser.email} created user ${normalizedEmail} with role ${role}`,
      details: {
        target_user_id: authData.user.id,
        target_user_email: normalizedEmail,
        assigned_role: role,
        operation: 'admin_user_creation',
      },
    });

    return NextResponse.json(
      {
        success: true,
        data: {
          id: authData.user.id,
          email: normalizedEmail,
          full_name,
          role,
          is_active: true,
        },
        message: 'User created successfully',
      },
      { status: 201 }
    );
  } catch (err: unknown) {
    if (err instanceof AuthorizationError) {
      return NextResponse.json({ success: false, error: err.message }, { status: err.statusCode });
    }
    return NextResponse.json({ success: false, error: 'Internal server error' }, { status: 500 });
  }
}

