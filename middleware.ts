import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

// Note: Middleware runs in Edge Runtime, so we can't use Node.js crypto
// We'll do basic token presence check here, and full verification in API routes

// Public paths that don't require authentication
const publicPaths = [
  '/login',
  '/signup',
  '/api/auth/login',
  '/api/auth/signup',
  '/api/auth/me',
  '/api/upload',
  '/api/chat',
  '/_next',
  '/favicon.ico',
  '/public'
];

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;

  // Check if the path is public
  if (publicPaths.some(path => pathname.startsWith(path))) {
    return NextResponse.next();
  }

  const token = request.cookies.get('token')?.value;

  // API routes - let them handle their own auth (they run in Node.js runtime)
  // We just check if token exists for protected routes
  if (pathname.startsWith('/api/') && !publicPaths.some(path => pathname.startsWith(path))) {
    if (!token) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }
    // Token exists, let the API route verify it
    return NextResponse.next();
  }

  // Protected pages - just check if token exists
  // Full verification happens client-side or in API routes
  if (!token) {
    // Don't redirect if already on login/signup page
    if (pathname === '/login' || pathname === '/signup') {
      return NextResponse.next();
    }
    const url = new URL('/login', request.url);
    url.searchParams.set('from', pathname);
    return NextResponse.redirect(url);
  }

  // Token exists, allow access (full verification in API routes)
  return NextResponse.next();
}

export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     * - public folder
     */
    '/((?!_next/static|_next/image|favicon.ico|public/).*)',
  ],
}; 