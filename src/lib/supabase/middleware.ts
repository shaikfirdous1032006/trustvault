
import { createServerClient } from '@supabase/ssr';
import { NextResponse, type NextRequest } from 'next/server';
import { SESSION_COOKIE, verifySessionToken } from '@/lib/session';

export async function updateSession(request: NextRequest) {
  let supabaseResponse = NextResponse.next({ request });

  const pathname = request.nextUrl.pathname;

  // Public routes that do not require an existing login.
  const publicPaths = [
    '/login',
    '/api/auth/login',
    '/api/auth/register',
    '/api/auth/callback',
    '/api/auth/logout',
    '/share',
    '/api/public/',
    '/api/health',
  ];

  const isPublicPath = publicPaths.some((path) =>
    path.endsWith('/')
      ? pathname.startsWith(path)
      : pathname === path || pathname.startsWith(`${path}/`)
  );

  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const key = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;

  const isConfigured = Boolean(
    url &&
      key &&
      !url.includes('your-project') &&
      !url.includes('mock-trustvault')
  );

  let authenticated = false;

  const token = request.cookies.get(SESSION_COOKIE)?.value;

  if (token) {
    const sessionUser = await verifySessionToken(token);
    authenticated = Boolean(sessionUser);
  }

  if (isConfigured && !authenticated) {
    try {
      const supabase = createServerClient(url!, key!, {
        cookies: {
          getAll() {
            return request.cookies.getAll();
          },
          setAll(cookiesToSet) {
            cookiesToSet.forEach(({ name, value }) => {
              request.cookies.set(name, value);
            });

            supabaseResponse = NextResponse.next({ request });

            cookiesToSet.forEach(({ name, value, options }) => {
              supabaseResponse.cookies.set(name, value, options);
            });
          },
        },
      });

      const { data: authData } = await supabase.auth.getUser();

      if (authData?.user) {
        authenticated = true;
      }
    } catch {
      // Continue as unauthenticated if Supabase verification fails.
    }
  }

  // Allow public pages and public API endpoints without an existing session.
  if (!authenticated && !isPublicPath) {
    if (pathname.startsWith('/api/')) {
      return NextResponse.json(
        { success: false, error: 'Authentication required' },
        {
          status: 401,
          headers: { 'Cache-Control': 'no-store' },
        }
      );
    }

    const loginUrl = request.nextUrl.clone();
    loginUrl.pathname = '/login';

    return NextResponse.redirect(loginUrl);
  }

  // Send already-authenticated users from login to the dashboard.
  if (authenticated && pathname === '/login') {
    const dashUrl = request.nextUrl.clone();
    dashUrl.pathname = '/dashboard';

    return NextResponse.redirect(dashUrl);
  }

  return supabaseResponse;
}