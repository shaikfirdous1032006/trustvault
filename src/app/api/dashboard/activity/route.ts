import { NextResponse } from 'next/server';
import { getAuthenticatedUser } from '@/lib/auth';
import { getMongoDb, isMongoConfigured } from '@/lib/mongodb';
import { getStore } from '@/lib/local-db';

export const dynamic = 'force-dynamic';

export async function GET() {
  try {
    const user = await getAuthenticatedUser();
    if (!user) {
      return NextResponse.json({ success: false, error: 'Unauthorized' }, { status: 401 });
    }

    const store = getStore();
    const docMap = new Map<string, string>();
    store.documents.forEach((d) => docMap.set(d.id, d.title));

    interface ActivityItem {
      id: string;
      action: string;
      result: string;
      occurred_at: string;
      actor_id?: string | null;
      actor_email?: string | null;
      document_id?: string | null;
      document_title?: string | null;
      details?: Record<string, unknown>;
    }

    let events: ActivityItem[] = [];

    if (isMongoConfigured()) {
      try {
        const db = await getMongoDb();
        const mongoEvents = await db
          .collection('audit')
          .find({})
          .sort({ occurred_at: -1 })
          .limit(25)
          .toArray();

        // Also fetch any documents from MongoDB to resolve titles
        const mongoDocs = await db.collection('documents').find({}).toArray();
        mongoDocs.forEach((d: Record<string, unknown>) => {
          if (d.id && d.title) docMap.set(String(d.id), String(d.title));
        });

        events = mongoEvents.map((e: Record<string, unknown>) => ({
          id: (e.id as string) || String(e._id),
          action: (e.action as string) || 'action',
          result: (e.result as string) || 'allowed',
          occurred_at: (e.occurred_at as string) || new Date().toISOString(),
          actor_id: (e.actor_id as string) || null,
          actor_email: (e.actor_email as string) || null,
          document_id: (e.document_id as string) || null,
          document_title: e.document_id ? docMap.get(String(e.document_id)) || null : null,
          details: (e.details_jsonb as Record<string, unknown>) || {},
        }));
      } catch (err) {
        console.warn('Failed to query audit from MongoDB, falling back to local store:', err);
      }
    }

    if (events.length === 0) {
      events = store.audit
        .slice()
        .sort((a, b) => b.occurred_at.localeCompare(a.occurred_at))
        .slice(0, 25)
        .map((e) => ({
          id: e.id,
          action: e.action,
          result: e.result,
          occurred_at: e.occurred_at,
          actor_id: e.actor_id,
          actor_email: e.actor_email,
          document_id: e.document_id,
          document_title: e.document_id ? docMap.get(e.document_id) || null : null,
          details: e.details_jsonb || {},
        }));
    }

    // Role-based visibility:
    // Admin and Owner see all platform & document activity
    // Viewer sees activity related to themselves or documents shared with them
    if (user.role === 'viewer') {
      events = events.filter(
        (e) => e.actor_email === user.email || (e.document_id && store.permissions.some((p) => p.document_id === e.document_id && p.user_id === user.id))
      );
    }

    return NextResponse.json({
      success: true,
      data: events,
      timestamp: new Date().toISOString(),
    });
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : 'Failed to fetch activities';
    return NextResponse.json(
      { success: false, error: message },
      { status: 500 }
    );
  }
}
