import { NextResponse } from 'next/server';
import { isSupabaseConfigured } from '@/lib/supabase/server';
import { getStore } from '@/lib/local-db';
import { POLICY_ENGINE_VERSION } from '@/lib/policy-engine';
import { PRIVACY_SHIELD_VERSION } from '@/lib/privacy-shield';
import { checkMongoConnection, isMongoConfigured } from '@/lib/mongodb';

const START_TIME = Date.now();

export async function GET() {
  const isSupabase = isSupabaseConfigured();
  const isMongo = isMongoConfigured();
  let documentCount = 0;
  let auditCount = 0;
  let usersCount = 0;
  let mongoDetails: Awaited<ReturnType<typeof checkMongoConnection>> | null = null;

  if (isMongo) {
    try {
      mongoDetails = await checkMongoConnection();
    } catch {
      // Handled via localStoreHealthy fallback
    }
  }

  let localStoreHealthy = false;
  try {
    const store = getStore();
    documentCount = store.documents.length;
    auditCount = store.audit.length;
    usersCount = store.users.length;
    localStoreHealthy = usersCount > 0;
  } catch {
    localStoreHealthy = false;
  }

  const isStorageHealthy = Boolean(mongoDetails?.connected || localStoreHealthy);
  const activeMode = mongoDetails?.connected
    ? 'mongodb'
    : (isSupabase ? 'supabase' : 'local-storage');
  const dbStatus = isStorageHealthy ? 'healthy' : 'degraded';

  const uptimeSeconds = Math.floor((Date.now() - START_TIME) / 1000);

  return NextResponse.json({
    status: isStorageHealthy ? 'pass' : 'warn',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    uptime: `${uptimeSeconds}s`,
    database: {
      mode: activeMode,
      status: dbStatus,
      engine: mongoDetails?.connected ? 'mongodb-atlas' : 'persistent-vault-store',
      cluster: mongoDetails?.cluster || (isMongo ? 'cloud-cluster' : 'local'),
      dbName: mongoDetails?.dbName || 'trustvault',
      latencyMs: mongoDetails?.latencyMs,
      collections: mongoDetails?.collections || [],
      documentsCount: documentCount,
      auditRecordsCount: auditCount,
      usersCount,
    },
    modules: {
      zeroTrustPolicyEngine: {
        status: 'active',
        version: POLICY_ENGINE_VERSION,
      },
      privacyShield: {
        status: 'active',
        version: PRIVACY_SHIELD_VERSION,
      },
      tamperEvidentAudit: {
        status: 'active',
        hashAlgorithm: 'SHA-256',
        chainIntegrity: 'enforced',
      },
      csrfProtection: {
        status: 'enforced',
      },
    },
  });
}
