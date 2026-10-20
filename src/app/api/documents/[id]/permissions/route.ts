import { createClient, createAdminClient, isSupabaseConfigured } from '@/lib/supabase/server';
import { requireAuth, isDocumentOwner, getRequestMeta, AuthorizationError } from '@/lib/auth';
import { logAuditEvent } from '@/lib/audit';
import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { randomUUID } from 'crypto';
import {
  findUserByEmail,
  getStore,
  mutateStore,
  withPermissionUsers,
} from '@/lib/local-db';

type RouteParams = { params: Promise<{ id: string }> };

const grantSchema = z.object({
  user_email: z.string().email('Invalid email'),
  permission_level: z.enum(['read', 'edit']),
  expires_at: z.string().datetime().optional(),
  ai_suggested: z.boolean().optional(),
  ai_rationale: z.string().optional(),
});

function denyNotFound() {
  return NextResponse.json({ success: false, error: 'Document not found' }, { status: 404 });
}

export async function GET(request: NextRequest, { params }: RouteParams) {
  const { id } = await params;

  try {
    const user = await requireAuth();
    const ownerCheck = await isDocumentOwner(user.id, id);

    if (!ownerCheck && user.role !== 'admin') {
      return NextResponse.json(
        { success: false, error: 'Only the document owner can view permissions' },
        { status: 403 }
      );
    }

    if (!isSupabaseConfigured()) {
      const store = getStore();
      const permissions = store.permissions
        .filter((p) => p.document_id === id)
        .map((p) => withPermissionUsers(p, store))
        .sort((a, b) => b.granted_at.localeCompare(a.granted_at));
      return NextResponse.json({ success: true, data: permissions });
    }

    const supabase = await createClient();
    const { data: permissions, error } = await supabase
      .from('document_permissions')
      .select('*, user:users!document_permissions_user_id_fkey(id, email, full_name), grantor:users!document_permissions_granted_by_fkey(id, email, full_name)')
      .eq('document_id', id)
      .order('granted_at', { ascending: false });

    if (error) {
      return NextResponse.json({ success: false, error: 'Failed to fetch permissions' }, { status: 500 });
    }

    return NextResponse.json({ success: true, data: permissions || [] });
  } catch (err: unknown) {
    if (err instanceof AuthorizationError) {
      return NextResponse.json({ success: false, error: err.message }, { status: err.statusCode });
    }
    return NextResponse.json({ success: false, error: 'Internal server error' }, { status: 500 });
  }
}

export async function POST(request: NextRequest, { params }: RouteParams) {
  const { id } = await params;
  const { ipAddress, userAgent } = await getRequestMeta();

  try {
    const user = await requireAuth();
    const ownerCheck = await isDocumentOwner(user.id, id);

    if (!ownerCheck) {
      await logAuditEvent({
        actorId: user.id,
        actorEmail: user.email,
        documentId: id,
        action: 'permission_grant',
        result: 'denied',
        ipAddress,
        userAgent,
        details: { reason: 'Not document owner' },
      });
      return NextResponse.json(
        { success: false, error: 'Only the document owner can grant permissions' },
        { status: 403 }
      );
    }

    const body = await request.json();
    const parsed = grantSchema.safeParse(body);

    if (!parsed.success) {
      return NextResponse.json(
        { success: false, error: 'Invalid permission data', details: parsed.error.flatten() },
        { status: 400 }
      );
    }

    if (!isSupabaseConfigured()) {
      const targetUser = findUserByEmail(parsed.data.user_email);
      if (!targetUser) {
        return NextResponse.json({ success: false, error: 'User not found' }, { status: 404 });
      }
      if (targetUser.id === user.id) {
        return NextResponse.json({ success: false, error: 'Cannot grant permission to yourself' }, { status: 400 });
      }

      const perm = await mutateStore((store) => {
        const existing = store.permissions.find(
          (p) =>
            p.document_id === id &&
            p.user_id === targetUser.id &&
            p.permission_level === parsed.data.permission_level
        );
        const now = new Date().toISOString();
        if (existing) {
          if (!existing.revoked_at) {
            return { conflict: true as const, perm: existing };
          }
          existing.revoked_at = null;
          existing.revoked_by = null;
          existing.granted_by = user.id;
          existing.granted_at = now;
          existing.expires_at = parsed.data.expires_at || null;
          return { conflict: false as const, perm: existing, reactivated: true };
        }
        const created = {
          id: randomUUID(),
          document_id: id,
          user_id: targetUser.id,
          permission_level: parsed.data.permission_level,
          granted_by: user.id,
          granted_at: now,
          revoked_at: null,
          revoked_by: null,
          expires_at: parsed.data.expires_at || null,
        };
        store.permissions.push(created);
        return { conflict: false as const, perm: created };
      });

      if ('conflict' in perm && perm.conflict) {
        return NextResponse.json({ success: false, error: 'Permission already exists for this user' }, { status: 409 });
      }

      await logAuditEvent({
        actorId: user.id,
        actorEmail: user.email,
        documentId: id,
        action: 'permission_grant',
        result: 'allowed',
        ipAddress,
        userAgent,
        details: {
          target_user_email: parsed.data.user_email,
          permission_level: parsed.data.permission_level,
          reactivated: 'reactivated' in perm && perm.reactivated,
          ai_suggested: parsed.data.ai_suggested || false,
          ai_rationale: parsed.data.ai_rationale || null,
          decision: 'human_confirmed',
        },
      });

      return NextResponse.json({ success: true, data: perm.perm }, { status: 201 });
    }

    const supabaseAdmin = createAdminClient();
    const { data: targetUser } = await supabaseAdmin
      .from('users')
      .select('id, email')
      .eq('email', parsed.data.user_email)
      .single();

    if (!targetUser) {
      return NextResponse.json({ success: false, error: 'User not found' }, { status: 404 });
    }

    if (targetUser.id === user.id) {
      return NextResponse.json({ success: false, error: 'Cannot grant permission to yourself' }, { status: 400 });
    }

    const { data: existing } = await supabaseAdmin
      .from('document_permissions')
      .select('id, revoked_at')
      .eq('document_id', id)
      .eq('user_id', targetUser.id)
      .eq('permission_level', parsed.data.permission_level)
      .is('revoked_at', null)
      .maybeSingle();

    if (existing) {
      return NextResponse.json({ success: false, error: 'Permission already exists for this user' }, { status: 409 });
    }

    const supabase = await createClient();
    const { data: granted, error } = await supabase
      .from('document_permissions')
      .insert({
        document_id: id,
        user_id: targetUser.id,
        permission_level: parsed.data.permission_level,
        granted_by: user.id,
        expires_at: parsed.data.expires_at || null,
      })
      .select('*, user:users!document_permissions_user_id_fkey(id, email, full_name)')
      .single();

    if (error) {
      if (error.code === '23505') {
        const { data: reactivated, error: upsertError } = await supabase
          .from('document_permissions')
          .update({
            revoked_at: null,
            revoked_by: null,
            granted_by: user.id,
            granted_at: new Date().toISOString(),
            expires_at: parsed.data.expires_at || null,
          })
          .eq('document_id', id)
          .eq('user_id', targetUser.id)
          .eq('permission_level', parsed.data.permission_level)
          .select()
          .single();

        if (upsertError) {
          return NextResponse.json({ success: false, error: 'Failed to grant permission' }, { status: 500 });
        }

        await logAuditEvent({
          actorId: user.id,
          actorEmail: user.email,
          documentId: id,
          action: 'permission_grant',
          result: 'allowed',
          ipAddress,
          userAgent,
          details: {
            target_user_email: parsed.data.user_email,
            permission_level: parsed.data.permission_level,
            reactivated: true,
          },
        });

        return NextResponse.json({ success: true, data: reactivated }, { status: 201 });
      }

      return NextResponse.json({ success: false, error: 'Failed to grant permission' }, { status: 500 });
    }

    await logAuditEvent({
      actorId: user.id,
      actorEmail: user.email,
      documentId: id,
      action: 'permission_grant',
      result: 'allowed',
      ipAddress,
      userAgent,
      details: {
        target_user_email: parsed.data.user_email,
        permission_level: parsed.data.permission_level,
        ai_suggested: parsed.data.ai_suggested || false,
        ai_rationale: parsed.data.ai_rationale || null,
        decision: 'human_confirmed',
      },
    });

    return NextResponse.json({ success: true, data: granted }, { status: 201 });
  } catch (err: unknown) {
    if (err instanceof AuthorizationError) {
      return NextResponse.json({ success: false, error: err.message }, { status: err.statusCode });
    }
    return NextResponse.json({ success: false, error: 'Internal server error' }, { status: 500 });
  }
}
