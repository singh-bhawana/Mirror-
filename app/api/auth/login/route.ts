import { NextResponse } from 'next/server';
import { cookies } from 'next/headers';
import { sign } from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// For demo purposes, we'll use a simple user object
const DEMO_USER = {
  id: '1',
  email: 'demo@example.com',
  password: 'demo123',
  name: 'Demo User'
};

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const email = body.email?.trim().toLowerCase();
    const password = body.password?.trim();

    // Validate input
    if (!email || !password) {
      return NextResponse.json(
        { error: 'Email and password are required' },
        { status: 400 }
      );
    }

    // For demo purposes, we'll use a simple email/password check
    // Compare email case-insensitively and password exactly
    const emailMatch = email.toLowerCase() === DEMO_USER.email.toLowerCase();
    const passwordMatch = password === DEMO_USER.password;

    if (emailMatch && passwordMatch) {
      // Create token with structure matching verifyToken expectations
      const token = sign(
        { 
          id: DEMO_USER.id, 
          email: DEMO_USER.email,
          name: DEMO_USER.name
        },
        JWT_SECRET,
        { expiresIn: '24h' }
      );

      // Set cookie with proper configuration
      const cookieStore = cookies();
      cookieStore.set('token', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: 86400, // 24 hours
        path: '/',
        domain: undefined // Let browser set domain
      });

      return NextResponse.json({ 
        success: true,
        user: {
          id: DEMO_USER.id,
          email: DEMO_USER.email,
          name: DEMO_USER.name
        }
      });
    }

    return NextResponse.json(
      { error: 'Invalid email or password' },
      { status: 401 }
    );
  } catch (error) {
    console.error('Login error:', error);
    return NextResponse.json(
      { error: 'Authentication failed. Please try again.' },
      { status: 500 }
    );
  }
} 