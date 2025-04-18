'use server';

import { NextResponse } from 'next/server';
import { PrismaClient } from '@prisma/client';

// Create a single PrismaClient instance
const prisma = new PrismaClient();

interface Finding {
  category: string;
  severity: 'High' | 'Medium' | 'Low';
  description: string;
  location: string;
  score_impact: number;
}

function analyzePhishingIndicators(content: string): Finding[] {
  const findings: Finding[] = [];
  
  // Enhanced phishing patterns
  const phishingPatterns = [
    {
      pattern: /urgent|immediate action|account.*suspended|limited time/i,
      description: 'Urgency or pressure tactics detected',
      score_impact: 15
    },
    {
      pattern: /verify.*account|confirm.*identity|update.*payment|banking.*details/i,
      description: 'Request for account verification or payment update',
      score_impact: 12
    },
    {
      pattern: /congratulations.*winner|you.*won|prize.*claim|lottery|inheritance/i,
      description: 'Suspicious prize or lottery claims',
      score_impact: 10
    },
    {
      pattern: /password.*expired|security.*breach|unusual.*activity|suspicious.*login/i,
      description: 'Security-related urgency indicators',
      score_impact: 15
    },
    {
      pattern: /dear.*valued.*customer|dear.*account.*holder/i,
      description: 'Generic greeting commonly used in phishing',
      score_impact: 5
    },
    {
      pattern: /account.*terminated|service.*suspended|immediate.*action.*required/i,
      description: 'Account termination threats',
      score_impact: 20
    }
  ];

  phishingPatterns.forEach(({ pattern, description, score_impact }) => {
    if (content.match(pattern)) {
      findings.push({
        category: 'Phishing',
        severity: 'High',
        description,
        location: 'Document content',
        score_impact
      });
    }
  });

  return findings;
}

function analyzeSensitiveInformation(content: string): Finding[] {
  const findings: Finding[] = [];

  // Enhanced patterns for sensitive information
  const patterns = [
    {
      pattern: /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/,
      description: 'Potential credit card number detected',
      severity: 'High' as const,
      score_impact: 20
    },
    {
      pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
      description: 'Email address detected',
      severity: 'Medium' as const,
      score_impact: 8
    },
    {
      pattern: /\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/,
      description: 'Phone number detected',
      severity: 'Medium' as const,
      score_impact: 5
    },
    {
      pattern: /\b\d{3}[-]?\d{2}[-]?\d{4}\b/,
      description: 'Potential Social Security Number detected',
      severity: 'High' as const,
      score_impact: 25
    },
    {
      pattern: /password|passwd|pwd|secret/i,
      description: 'Potential password or secret detected',
      severity: 'High' as const,
      score_impact: 15
    }
  ];

  patterns.forEach(({ pattern, description, severity, score_impact }) => {
    const matches = content.match(pattern);
    if (matches) {
      findings.push({
        category: 'Privacy',
        severity,
        description: matches.length > 1 ? `${matches.length} instances of ${description}` : description,
        location: 'Document content',
        score_impact
      });
    }
  });

  return findings;
}

function analyzeSecurityThreats(content: string): Finding[] {
  const findings: Finding[] = [];

  // Enhanced security threat detection
  const securityChecks = [
    {
      check: (url: string) => !url.startsWith('https://'),
      description: 'Insecure HTTP link detected',
      severity: 'High' as const,
      score_impact: 10
    },
    {
      check: (url: string) => url.match(/\.(xyz|tk|ml|ga|cf|gq|pw)\//i),
      description: 'Potentially malicious domain detected',
      severity: 'High' as const,
      score_impact: 15
    },
    {
      check: (url: string) => url.match(/\.(ru|cn|su|tk)\//i),
      description: 'High-risk domain TLD detected',
      severity: 'High' as const,
      score_impact: 20
    }
  ];

  // URL analysis
  const urls = content.match(/https?:\/\/[^\s]+/g) || [];
  urls.forEach(url => {
    securityChecks.forEach(({ check, description, severity, score_impact }) => {
      if (check(url)) {
        findings.push({
          category: 'Security',
          severity,
          description,
          location: url,
          score_impact
        });
      }
    });
  });

  // Script injection checks
  if (content.match(/<script|javascript:|data:text\/html|base64/i)) {
    findings.push({
      category: 'Security',
      severity: 'High',
      description: 'Potential script injection or encoded content detected',
      location: 'Document content',
      score_impact: 25
    });
  }

  // Additional security checks
  const additionalThreats = [
    {
      pattern: /eval\(|setTimeout\(|setInterval\(|new Function\(/,
      description: 'Potentially dangerous JavaScript execution',
      score_impact: 20
    },
    {
      pattern: /document\.cookie|localStorage|sessionStorage/,
      description: 'Suspicious data access attempts',
      score_impact: 15
    },
    {
      pattern: /\\x[0-9a-f]{2}|%[0-9a-f]{2}|\\u[0-9a-f]{4}/i,
      description: 'Encoded or obfuscated content detected',
      score_impact: 10
    }
  ];

  additionalThreats.forEach(({ pattern, description, score_impact }) => {
    if (content.match(pattern)) {
      findings.push({
        category: 'Security',
        severity: 'High',
        description,
        location: 'Document content',
        score_impact
      });
    }
  });

  return findings;
}

function calculateMirrorScore(findings: Finding[]): number {
  // Base score starts at 100
  let score = 100;

  // Calculate weighted deductions based on findings
  findings.forEach(finding => {
    const severityMultiplier = finding.severity === 'High' ? 1.5 :
                              finding.severity === 'Medium' ? 1.0 : 0.5;
    score -= finding.score_impact * severityMultiplier;
  });

  // Apply diminishing returns for multiple findings
  if (findings.length > 5) {
    score *= 0.9;
  }
  if (findings.length > 10) {
    score *= 0.8;
  }

  // Ensure score stays within 0-100 range
  return Math.max(0, Math.min(100, Math.round(score)));
}

export async function POST(request: Request) {
  try {
    const formData = await request.formData();
    const file = formData.get('file') as File;
    
    if (!file) {
      return NextResponse.json(
        { error: 'No file provided' },
        { status: 400 }
      );
    }

    // Read file content
    const buffer = await file.arrayBuffer();
    const content = Buffer.from(buffer).toString();

    // Perform comprehensive analysis
    const phishingFindings = analyzePhishingIndicators(content);
    const privacyFindings = analyzeSensitiveInformation(content);
    const securityFindings = analyzeSecurityThreats(content);

    // Combine all findings
    const allFindings = [...phishingFindings, ...privacyFindings, ...securityFindings];

    // Calculate MirrorScore
    const mirrorScore = calculateMirrorScore(allFindings);

    try {
      // Save scan results
      const scan = await prisma.scan.create({
        data: {
          fileName: file.name,
          fileType: file.type,
          mirrorScore,
          userId: 'user-id', // TODO: Get from auth session
          findings: {
            create: allFindings.map(f => ({
              category: f.category,
              severity: f.severity,
              description: f.description,
              location: f.location,
            })),
          },
        },
        include: {
          findings: true,
        },
      });

      return NextResponse.json({
        scan,
        summary: {
          mirrorScore,
          totalFindings: allFindings.length,
          findingsByCategory: {
            phishing: phishingFindings.length,
            privacy: privacyFindings.length,
            security: securityFindings.length,
          },
          severityBreakdown: {
            high: allFindings.filter(f => f.severity === 'High').length,
            medium: allFindings.filter(f => f.severity === 'Medium').length,
            low: allFindings.filter(f => f.severity === 'Low').length,
          },
        },
      });
    } catch (dbError) {
      console.error('Database error:', dbError);
      // Return scan results even if database save fails
      return NextResponse.json({
        scan: {
          id: 'temp-' + Date.now(),
          fileName: file.name,
          findings: allFindings.map(f => ({
            id: 'temp-' + Math.random(),
            ...f
          })),
        },
        summary: {
          mirrorScore,
          totalFindings: allFindings.length,
          findingsByCategory: {
            phishing: phishingFindings.length,
            privacy: privacyFindings.length,
            security: securityFindings.length,
          },
          severityBreakdown: {
            high: allFindings.filter(f => f.severity === 'High').length,
            medium: allFindings.filter(f => f.severity === 'Medium').length,
            low: allFindings.filter(f => f.severity === 'Low').length,
          },
        },
      });
    }
  } catch (error) {
    console.error('Scan error:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
} 