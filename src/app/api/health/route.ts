import { NextResponse } from 'next/server';
import { isSupabaseConfigured } from '@/lib/supabase/server';
import { getStore } from '@/lib/local-db';
import { POLICY_ENGINE_VERSION } from '@/lib/policy-engine';
import { PRIVACY_SHIELD_VERSION } from '@/lib/privacy-shield';

const START_TIME = Date.now();

export async function GET() {
  const isConfigured = isSupabaseConfigured();
  let dbStatus = 'healthy';
  let documentCount = 0;
  let auditCount = 0;

  try {
    if (!isConfigured) {
      const store = getStore();
      documentCount = store.documents.length;
      auditCount = store.audit.length;
    }
  } catch {
    dbStatus = 'degraded';
  }

  const uptimeSeconds = Math.floor((Date.now() - START_TIME) / 1000);

  return NextResponse.json({
    status: dbStatus === 'healthy' ? 'pass' : 'warn',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    uptime: `${uptimeSeconds}s`,
    database: {
      mode: isConfigured ? 'supabase' : 'local-storage',
      status: dbStatus,
      documentsCount: documentCount,
      auditRecordsCount: auditCount,
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
