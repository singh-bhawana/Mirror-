import { NextResponse } from 'next/server';
import { verifyToken } from '@/lib/jwt';
import { cookies } from 'next/headers';

export async function GET() {
  try {
    const token = cookies().get('token')?.value;

    if (!token) {
      return NextResponse.json(null);
    }

    const decoded = verifyToken(token);

    if (!decoded) {
      return NextResponse.json(null);
    }

    // Return user info from token (for demo purposes)
    return NextResponse.json({
      id: decoded.id,
      email: decoded.email,
      name: decoded.name || 'Demo User'
    });
  } catch (error) {
    console.error('Session error:', error);
    return NextResponse.json(null);
  }
} 