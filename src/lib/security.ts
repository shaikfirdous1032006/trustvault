import { NextRequest, NextResponse } from 'next/server';

interface RateLimitRecord {
  count: number;
  resetAt: number;
}

const rateLimitStore = new Map<string, RateLimitRecord>();

/**
 * In-memory sliding window rate limiter for security-sensitive operations.
 */
export function checkRateLimit(
  key: string,
  limit: number = 10,
  windowMs: number = 60_000
): { allowed: boolean; remaining: number; resetMs: number } {
  const now = Date.now();
  const record = rateLimitStore.get(key);

  if (!record || now > record.resetAt) {
    rateLimitStore.set(key, {
      count: 1,
      resetAt: now + windowMs,
    });
    return {
      allowed: true,
      remaining: limit - 1,
      resetMs: windowMs,
    };
  }

  if (record.count >= limit) {
    return {
      allowed: false,
      remaining: 0,
      resetMs: Math.max(0, record.resetAt - now),
    };
  }

  record.count += 1;
  return {
    allowed: true,
    remaining: limit - record.count,
    resetMs: Math.max(0, record.resetAt - now),
  };
}

/**
 * Resets rate limit for a key (e.g., in tests).
 */
export function resetRateLimit(key?: string): void {
  if (key) {
    rateLimitStore.delete(key);
  } else {
    rateLimitStore.clear();
  }
}

/**
 * Cross-origin request rejection for state-changing calls.
 *
 * Sessions are cookies with SameSite=Lax, which already blocks the classic
 * cross-site form POST; this check is the second layer and the one that also
 * covers fetch() from a page on another origin. There is intentionally no
 * development-mode bypass: a guard that only works in production is a guard that
 * nobody tests, and every browser sends Origin on a same-origin POST, PATCH, PUT
 * or DELETE, so requiring it costs the real client nothing.
 */
export function verifyCsrf(request: NextRequest): { valid: boolean; reason?: string } {
  const method = request.method.toUpperCase();
  if (['GET', 'HEAD', 'OPTIONS'].includes(method)) {
    return { valid: true };
  }

  // A browser that knows the request is cross-site says so. Trust it immediately.
  if (request.headers.get('sec-fetch-site') === 'cross-site') {
    return { valid: false, reason: 'Sec-Fetch-Site reports a cross-site request' };
  }

  const host = request.headers.get('host') || new URL(request.url).host;
  const origin = request.headers.get('origin');
  const referer = request.headers.get('referer');

  if (!origin && !referer) {
    return { valid: false, reason: 'State-changing request carried no Origin or Referer' };
  }

  for (const [headerName, value] of [
    ['Origin', origin],
    ['Referer', referer],
  ] as const) {
    if (!value) continue;
    let candidateHost: string;
    try {
      candidateHost = new URL(value).host;
    } catch {
      return { valid: false, reason: `Malformed ${headerName} header` };
    }
    if (candidateHost !== host) {
      return { valid: false, reason: `${headerName} host '${candidateHost}' does not match '${host}'` };
    }
  }

  return { valid: true };
}

/**
 * One-call guard for a mutating route handler. Returns a response the caller must
 * send, or null when the request may proceed.
 */
export function csrfRejection(request: NextRequest): NextResponse | null {
  const decision = verifyCsrf(request);
  if (decision.valid) return null;
  return NextResponse.json(
    { success: false, error: 'Cross-origin request rejected', reason: decision.reason },
    { status: 403, headers: { 'Cache-Control': 'no-store' } }
  );
}
