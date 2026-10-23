import { NextRequest, NextResponse } from 'next/server';
import { getAuthenticatedUser } from '@/lib/auth';
import { createAdminClient, isSupabaseConfigured } from '@/lib/supabase/server';
import { getMongoDb, isMongoConfigured } from '@/lib/mongodb';
import { getStore } from '@/lib/local-db';
import { formatAuditDescription } from '@/lib/audit';
import type { ActivityFeedItem, AuditAction, AuditResult } from '@/lib/types';

export const dynamic = 'force-dynamic';

const CATEGORY_ACTIONS: Record<string, string[]> = {
  auth: ['login', 'logout', 'login_failure', 'register', 'register_failure'],
  documents: ['upload', 'download', 'preview', 'update', 'delete', 'restore', 'version_upload'],
  permissions: [
    'permission_grant',
    'permission_revoke',
    'permission_update',
    'share_link_created',
    'share_link_revoked',
    'share_link_viewed',
    'share_link_denied',
  ],
  admin: ['admin_action', 'role_change', 'account_activated', 'account_deactivated'],
  security: ['security_alert', 'login_failure', 'share_link_denied'],
};

export async function GET(request: NextRequest) {
  try {
    const user = await getAuthenticatedUser();
    if (!user) {
      return NextResponse.json({ success: false, error: 'Unauthorized' }, { status: 401 });
    }

    const { searchParams } = new URL(request.url);
    const page = Math.max(1, parseInt(searchParams.get('page') || '1', 10));
    const pageSize = Math.min(50, Math.max(1, parseInt(searchParams.get('pageSize') || '10', 10)));
    const search = searchParams.get('search')?.trim().toLowerCase() || '';
    const category = searchParams.get('category') || 'all';
    const action = searchParams.get('action') || 'all';
    const result = searchParams.get('result') || 'all';
    const dateFrom = searchParams.get('dateFrom') || '';
    const dateTo = searchParams.get('dateTo') || '';

    // =========================================================================
    // 1. SUPABASE MODE
    // =========================================================================
    if (isSupabaseConfigured()) {
      const supabaseAdmin = createAdminClient();

      // Determine document visibility for role
      let permittedDocIds: string[] | null = null;
      if (user.role === 'owner') {
        const { data: ownedDocs } = await supabaseAdmin
          .from('documents')
          .select('id')
          .eq('owner_id', user.id);
        permittedDocIds = (ownedDocs || []).map((d) => d.id);
      } else if (user.role === 'viewer') {
        const { data: grants } = await supabaseAdmin
          .from('document_permissions')
          .select('document_id')
          .eq('user_id', user.id)
          .is('revoked_at', null);
        permittedDocIds = (grants || []).map((g) => g.document_id);
      }

      let query = supabaseAdmin
        .from('audit_events')
        .select('*', { count: 'exact' });

      // Apply role-based visibility filter
      if (user.role === 'viewer') {
        if (permittedDocIds && permittedDocIds.length > 0) {
          query = query.or(`actor_id.eq.${user.id},actor_email.eq.${user.email},document_id.in.(${permittedDocIds.join(',')})`);
        } else {
          query = query.or(`actor_id.eq.${user.id},actor_email.eq.${user.email}`);
        }
      } else if (user.role === 'owner') {
        if (permittedDocIds && permittedDocIds.length > 0) {
          query = query.or(`actor_id.eq.${user.id},actor_email.eq.${user.email},document_id.in.(${permittedDocIds.join(',')})`);
        } else {
          query = query.or(`actor_id.eq.${user.id},actor_email.eq.${user.email}`);
        }
      }
      // Admins have no role-based restriction: full oversight

      // Filter by result
      if (result && result !== 'all') {
        query = query.eq('result', result);
      }

      // Filter by action or category
      if (action && action !== 'all') {
        query = query.eq('action', action);
      } else if (category && category !== 'all' && CATEGORY_ACTIONS[category]) {
        if (category === 'security') {
          query = query.or('result.eq.denied,action.eq.security_alert,action.eq.login_failure');
        } else {
          query = query.in('action', CATEGORY_ACTIONS[category]);
        }
      }

      // Filter by date range
      if (dateFrom) {
        query = query.gte('occurred_at', dateFrom);
      }
      if (dateTo) {
        query = query.lte('occurred_at', dateTo.includes('T') ? dateTo : `${dateTo}T23:59:59.999Z`);
      }

      // Ordering and pagination
      const offset = (page - 1) * pageSize;
      query = query
        .order('occurred_at', { ascending: false })
        .range(offset, offset + pageSize - 1);

      const { data: rows, count, error } = await query;
      if (error) {
        console.error('[API activity] Supabase query error:', error);
        return NextResponse.json({ success: false, error: 'Failed to fetch activity records' }, { status: 500 });
      }

      // Resolve document titles for rows that have document_id
      const docIds = Array.from(new Set((rows || []).map((r) => r.document_id).filter(Boolean)));
      const docTitleMap = new Map<string, string>();

      if (docIds.length > 0) {
        const { data: docs } = await supabaseAdmin
          .from('documents')
          .select('id, title')
          .in('id', docIds);
        (docs || []).forEach((d) => docTitleMap.set(d.id, d.title));
      }

      let items: ActivityFeedItem[] = (rows || []).map((row) => {
        const details = (row.details_jsonb as Record<string, unknown>) || {};
        const docTitle = row.document_id ? docTitleMap.get(row.document_id) || (details.file_name as string) || (details.title as string) || null : null;
        const description = (details.description as string) || formatAuditDescription({
          actorId: row.actor_id,
          actorEmail: row.actor_email,
          documentId: row.document_id,
          action: row.action as AuditAction,
          result: row.result as AuditResult,
          details: { ...details, title: docTitle },
        });

        return {
          id: row.id,
          action: row.action,
          result: row.result,
          occurred_at: row.occurred_at,
          actor_id: row.actor_id,
          actor_email: row.actor_email,
          document_id: row.document_id,
          document_title: docTitle,
          description,
          target_resource_type: (details.target_resource_type as string) || (row.document_id ? 'document' : 'system'),
          target_resource_id: (details.target_resource_id as string) || row.document_id || null,
          details,
        };
      });

      // Filter by search keyword in memory if search query provided
      if (search) {
        items = items.filter((item) =>
          (item.actor_email || '').toLowerCase().includes(search) ||
          item.description.toLowerCase().includes(search) ||
          (item.document_title || '').toLowerCase().includes(search) ||
          item.action.toLowerCase().includes(search)
        );
      }

      const totalCount = count ?? items.length;

      return NextResponse.json({
        success: true,
        data: items,
        total: totalCount,
        page,
        pageSize,
        hasMore: offset + items.length < totalCount,
        timestamp: new Date().toISOString(),
      });
    }

    // =========================================================================
    // 2. STANDALONE (MONGODB ATLAS & LOCAL STORE) MODE
    // =========================================================================
    const store = getStore();
    const docMap = new Map<string, string>();
    store.documents.forEach((d) => docMap.set(d.id, d.title));

    let rawEvents: Array<{
      id: string;
      action: string;
      result: string;
      occurred_at: string;
      actor_id?: string | null;
      actor_email?: string | null;
      document_id?: string | null;
      details_jsonb?: Record<string, unknown>;
    }> = [];

    if (isMongoConfigured()) {
      try {
        const db = await getMongoDb();
        const mongoEvents = await db
          .collection('audit')
          .find({})
          .sort({ occurred_at: -1 })
          .toArray();

        const mongoDocs = await db.collection('documents').find({}).toArray();
        mongoDocs.forEach((d: Record<string, unknown>) => {
          if (d.id && d.title) docMap.set(String(d.id), String(d.title));
        });

        rawEvents = mongoEvents.map((e: Record<string, unknown>) => ({
          id: (e.id as string) || String(e._id),
          action: (e.action as string) || 'action',
          result: (e.result as string) || 'allowed',
          occurred_at: (e.occurred_at as string) || new Date().toISOString(),
          actor_id: (e.actor_id as string) || null,
          actor_email: (e.actor_email as string) || null,
          document_id: (e.document_id as string) || null,
          details_jsonb: (e.details_jsonb as Record<string, unknown>) || {},
        }));
      } catch (err) {
        console.warn('Failed to query MongoDB Atlas audit, using store:', err);
      }
    }

    if (rawEvents.length === 0) {
      rawEvents = store.audit.slice();
    }

    // Role-based visibility filtering
    let visibleEvents = rawEvents;
    if (user.role === 'viewer') {
      const permittedDocIds = new Set(
        store.permissions
          .filter((p) => p.user_id === user.id && !p.revoked_at)
          .map((p) => p.document_id)
      );
      visibleEvents = visibleEvents.filter(
        (e) =>
          e.actor_email === user.email ||
          e.actor_id === user.id ||
          (e.document_id && permittedDocIds.has(e.document_id))
      );
    } else if (user.role === 'owner') {
      const ownedDocIds = new Set(
        store.documents.filter((d) => d.owner_id === user.id).map((d) => d.id)
      );
      visibleEvents = visibleEvents.filter(
        (e) =>
          e.actor_email === user.email ||
          e.actor_id === user.id ||
          (e.document_id && ownedDocIds.has(e.document_id))
      );
    }

    // Apply result filter
    if (result && result !== 'all') {
      visibleEvents = visibleEvents.filter((e) => e.result === result);
    }

    // Apply action or category filter
    if (action && action !== 'all') {
      visibleEvents = visibleEvents.filter((e) => e.action === action);
    } else if (category && category !== 'all' && CATEGORY_ACTIONS[category]) {
      if (category === 'security') {
        visibleEvents = visibleEvents.filter(
          (e) => e.result === 'denied' || e.action === 'security_alert' || e.action === 'login_failure'
        );
      } else {
        const allowedActions = CATEGORY_ACTIONS[category];
        visibleEvents = visibleEvents.filter((e) => allowedActions.includes(e.action));
      }
    }

    // Apply date filters
    if (dateFrom) {
      visibleEvents = visibleEvents.filter((e) => e.occurred_at >= dateFrom);
    }
    if (dateTo) {
      const endBoundary = dateTo.includes('T') ? dateTo : `${dateTo}T23:59:59.999Z`;
      visibleEvents = visibleEvents.filter((e) => e.occurred_at <= endBoundary);
    }

    // Map to ActivityFeedItem
    let items: ActivityFeedItem[] = visibleEvents.map((e) => {
      const details = e.details_jsonb || {};
      const docTitle = e.document_id ? docMap.get(e.document_id) || (details.file_name as string) || (details.title as string) || null : null;
      const description = (details.description as string) || formatAuditDescription({
        actorId: e.actor_id ?? null,
        actorEmail: e.actor_email ?? null,
        documentId: e.document_id ?? null,
        action: e.action as AuditAction,
        result: e.result as AuditResult,
        details: { ...details, title: docTitle },
      });

      return {
        id: e.id,
        action: e.action,
        result: e.result,
        occurred_at: e.occurred_at,
        actor_id: e.actor_id ?? null,
        actor_email: e.actor_email ?? null,
        document_id: e.document_id ?? null,
        document_title: docTitle,
        description,
        target_resource_type: (details.target_resource_type as string) || (e.document_id ? 'document' : 'system'),
        target_resource_id: (details.target_resource_id as string) || e.document_id || null,
        details,
      };
    });

    // Apply search filter
    if (search) {
      items = items.filter((item) =>
        (item.actor_email || '').toLowerCase().includes(search) ||
        item.description.toLowerCase().includes(search) ||
        (item.document_title || '').toLowerCase().includes(search) ||
        item.action.toLowerCase().includes(search)
      );
    }

    // Sort descending by timestamp
    items.sort((a, b) => b.occurred_at.localeCompare(a.occurred_at));

    const total = items.length;
    const offset = (page - 1) * pageSize;
    const paginatedItems = items.slice(offset, offset + pageSize);

    return NextResponse.json({
      success: true,
      data: paginatedItems,
      total,
      page,
      pageSize,
      hasMore: offset + paginatedItems.length < total,
      timestamp: new Date().toISOString(),
    });
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : 'Failed to fetch activities';
    return NextResponse.json({ success: false, error: message }, { status: 500 });
  }
}
