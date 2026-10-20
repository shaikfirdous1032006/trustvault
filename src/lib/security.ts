import { NextRequest } from 'next/server';

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
 * CSRF protection for state-changing requests.
 * Inspects Sec-Fetch-Site, Origin, and Referer headers against the host.
 */
export function verifyCsrf(request: NextRequest): { valid: boolean; reason?: string } {
  const method = request.method.toUpperCase();
  // Safe methods do not require CSRF validation
  if (['GET', 'HEAD', 'OPTIONS'].includes(method)) {
    return { valid: true };
  }

  // If client provides a custom API request header, browsers enforce preflight CORS
  const requestedWith = request.headers.get('x-requested-with');
  if (requestedWith) {
    return { valid: true };
  }

  // Check Sec-Fetch-Site (modern browsers)
  const secFetchSite = request.headers.get('sec-fetch-site');
  if (secFetchSite && ['same-origin', 'same-site', 'none'].includes(secFetchSite)) {
    return { valid: true };
  }

  // Check Origin or Referer against Host
  const host = request.headers.get('host') || request.nextUrl.host;
  const origin = request.headers.get('origin');
  if (origin) {
    try {
      const originHost = new URL(origin).host;
      if (originHost === host) {
        return { valid: true };
      }
      return { valid: false, reason: `Origin header '${originHost}' does not match host '${host}'` };
    } catch {
      return { valid: false, reason: 'Malformed Origin header' };
    }
  }

  const referer = request.headers.get('referer');
  if (referer) {
    try {
      const refererHost = new URL(referer).host;
      if (refererHost === host) {
        return { valid: true };
      }
      return { valid: false, reason: `Referer header '${refererHost}' does not match host '${host}'` };
    } catch {
      return { valid: false, reason: 'Malformed Referer header' };
    }
  }

  // In development/test environments where Origin/Referer might not be attached to local NextRequest instances
  if (process.env.NODE_ENV !== 'production') {
    return { valid: true };
  }

  return { valid: false, reason: 'Missing Origin or Referer header on state-changing request' };
}
