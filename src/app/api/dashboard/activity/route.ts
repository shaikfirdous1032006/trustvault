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

    let events: any[] = [];

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
        mongoDocs.forEach((d: any) => {
          if (d.id && d.title) docMap.set(d.id, d.title);
        });

        events = mongoEvents.map((e: any) => ({
          id: e.id || String(e._id),
          action: e.action,
          result: e.result,
          occurred_at: e.occurred_at,
          actor_id: e.actor_id,
          actor_email: e.actor_email,
          document_id: e.document_id,
          document_title: e.document_id ? docMap.get(e.document_id) || null : null,
          details: e.details_jsonb || {},
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
  } catch (error: any) {
    return NextResponse.json(
      { success: false, error: error?.message || 'Failed to fetch activities' },
      { status: 500 }
    );
  }
}
