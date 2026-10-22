import { NextResponse } from 'next/server';
import { checkMongoConnection, isMongoConfigured, getMongoDb } from '@/lib/mongodb';
import { getStore, syncMongoStore } from '@/lib/local-db';
import { getAuthenticatedUser } from '@/lib/auth';

export async function GET() {
  const isConfigured = isMongoConfigured();
  if (!isConfigured) {
    return NextResponse.json({
      success: true,
      configured: false,
      message: 'MongoDB is not configured.',
    });
  }

  const check = await checkMongoConnection();
  const store = getStore();

  let counts: Record<string, number> = {};
  if (check.connected) {
    try {
      const db = await getMongoDb();
      const [u, d, p, v, l, a] = await Promise.all([
        db.collection('users').countDocuments(),
        db.collection('documents').countDocuments(),
        db.collection('permissions').countDocuments(),
        db.collection('versions').countDocuments(),
        db.collection('share_links').countDocuments(),
        db.collection('audit').countDocuments(),
      ]);
      counts = {
        users: u,
        documents: d,
        permissions: p,
        versions: v,
        share_links: l,
        audit: a,
      };
    } catch {
      // fallback to in-memory counts
      counts = {
        users: store.users.length,
        documents: store.documents.length,
        permissions: store.permissions.length,
        versions: store.versions.length,
        share_links: store.share_links.length,
        audit: store.audit.length,
      };
    }
  }

  return NextResponse.json({
    success: true,
    configured: true,
    connected: check.connected,
    cluster: check.cluster,
    dbName: check.dbName,
    latencyMs: check.latencyMs,
    collections: check.collections,
    counts,
    error: check.error,
  });
}

export async function POST() {
  const user = await getAuthenticatedUser();
  if (!user || user.role !== 'admin') {
    return NextResponse.json(
      { success: false, error: 'Unauthorized: Admin role required for database operations' },
      { status: 403 }
    );
  }

  const success = await syncMongoStore();
  const check = await checkMongoConnection();

  return NextResponse.json({
    success,
    message: success ? 'Synchronized with MongoDB Atlas successfully' : 'Sync failed',
    check,
  });
}
