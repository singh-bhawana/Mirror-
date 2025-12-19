import { NextResponse } from 'next/server';

export async function POST(request: Request) {
  try {
    // Get the form data
    const formData = await request.formData();
    const file = formData.get('file') as File;
    const fileName = formData.get('fileName') as string || file?.name;
    const fileType = formData.get('fileType') as string || file?.type;

    if (!file && !fileName) {
      return NextResponse.json({ error: 'Missing file data' }, { status: 400 });
    }

    // Simulate file analysis (replace with actual analysis in production)
    const findings = [
      {
        id: 1,
        category: 'Security',
        severity: 'High',
        description: 'Potential security vulnerability detected',
        location: 'Page 1, Paragraph 2'
      },
      {
        id: 2,
        category: 'Privacy',
        severity: 'Medium',
        description: 'Personal information found',
        location: 'Page 2'
      },
      {
        id: 3,
        category: 'Phishing',
        severity: 'Low',
        description: 'Suspicious link detected',
        location: 'Page 3'
      }
    ];

    const mirrorScore = Math.floor(Math.random() * 5) + 3;

    // Prepare response (without database for demo)
    const response = {
      scan: {
        id: Date.now().toString(),
        fileName: fileName || 'uploaded-file',
        findings: findings
      },
      summary: {
        mirrorScore: mirrorScore,
        totalFindings: findings.length,
        findingsByCategory: {
          phishing: findings.filter(f => f.category === 'Phishing').length,
          privacy: findings.filter(f => f.category === 'Privacy').length,
          security: findings.filter(f => f.category === 'Security').length
        },
        severityBreakdown: {
          high: findings.filter(f => f.severity === 'High').length,
          medium: findings.filter(f => f.severity === 'Medium').length,
          low: findings.filter(f => f.severity === 'Low').length
        }
      }
    };

    return NextResponse.json(response);
  } catch (error) {
    console.error('Scan error:', error);
    return NextResponse.json(
      { error: 'An error occurred during file analysis' },
      { status: 500 }
    );
  }
} 