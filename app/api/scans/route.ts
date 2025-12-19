import { NextResponse } from 'next/server';
import { scanStorage } from '@/lib/scanStorage';

export async function GET() {
  try {
    const scans = scanStorage.getAllScans();
    const statistics = scanStorage.getStatistics();

    return NextResponse.json({ 
      scans,
      statistics
    });
  } catch (error) {
    console.error('Error fetching scans:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
} 