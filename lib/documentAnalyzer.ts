// Document Analysis Engine
// Analyzes PDF, DOC, DOCX, and TXT files for security, privacy, and compliance issues

interface Finding {
  id: number;
  category: string;
  severity: 'High' | 'Medium' | 'Low';
  description: string;
  location: string;
}

interface AnalysisResult {
  mirrorScore: number;
  findings: Finding[];
  textContent: string;
  metadata: {
    wordCount: number;
    linkCount: number;
    emailCount: number;
    phoneCount: number;
  };
}

// Extract text from file buffer
async function extractTextFromFile(file: File): Promise<string> {
  const buffer = await file.arrayBuffer();
  const fileName = file.name.toLowerCase();
  
  // For PDF files - extract text from PDF
  if (fileName.endsWith('.pdf')) {
    try {
      const uint8Array = new Uint8Array(buffer);
      const textDecoder = new TextDecoder('utf-8', { fatal: false });
      let text = textDecoder.decode(uint8Array);
      
      // Extract readable text from PDF structure
      // PDF text is often in format: (text) or [text] or /Text
      const extractedParts: string[] = [];
      
      // Method 1: Extract text from parentheses (common PDF text format)
      const parenMatches = text.match(/\((.*?)\)/g) || [];
      parenMatches.forEach(match => {
        const content = match.slice(1, -1);
        // Filter out binary data and keep readable text
        if (content.length > 1 && /[a-zA-Z0-9]/.test(content) && content.length < 200) {
          extractedParts.push(content);
        }
      });
      
      // Method 2: Extract text from brackets
      const bracketMatches = text.match(/\[(.*?)\]/g) || [];
      bracketMatches.forEach(match => {
        const content = match.slice(1, -1);
        if (content.length > 1 && /[a-zA-Z0-9]/.test(content) && content.length < 200) {
          extractedParts.push(content);
        }
      });
      
      // Method 3: Extract readable ASCII text directly
      const asciiText = text
        .replace(/[^\x20-\x7E\n\r]/g, ' ') // Remove non-printable
        .replace(/\s+/g, ' ') // Normalize whitespace
        .substring(0, 50000); // Limit size
      
      // Combine all extracted text
      let extractedText = extractedParts.join(' ');
      
      // If we didn't get much from structured extraction, use ASCII text
      if (extractedText.length < 100) {
        extractedText = asciiText;
      } else {
        // Combine both for better coverage
        extractedText = extractedText + ' ' + asciiText.substring(0, 10000);
      }
      
      // Clean up the text
      extractedText = extractedText
        .replace(/\s+/g, ' ')
        .trim();
      
      return extractedText.substring(0, 50000); // Limit to 50k chars
    } catch (error) {
      console.error('PDF extraction error:', error);
      return '';
    }
  }
  
  // For DOCX files
  if (fileName.endsWith('.docx')) {
    try {
      // DOCX is a ZIP file containing XML
      // Extract readable text from the XML structure
      const textDecoder = new TextDecoder('utf-8', { fatal: false });
      const text = textDecoder.decode(buffer);
      
      // Extract text from XML tags (DOCX uses <w:t> tags for text)
      const xmlTextMatches = text.match(/<w:t[^>]*>(.*?)<\/w:t>/gi) || [];
      const extractedText = xmlTextMatches
        .map(match => {
          // Extract content between tags
          const content = match.replace(/<[^>]+>/g, '');
          // Decode XML entities
          return content
            .replace(/&amp;/g, '&')
            .replace(/&lt;/g, '<')
            .replace(/&gt;/g, '>')
            .replace(/&quot;/g, '"')
            .replace(/&#39;/g, "'");
        })
        .filter(t => t.trim().length > 0)
        .join(' ');
      
      // If XML extraction didn't work, try direct ASCII extraction
      if (extractedText.length < 50) {
        const asciiText = text
          .replace(/[^\x20-\x7E\n\r]/g, ' ')
          .replace(/\s+/g, ' ')
          .substring(0, 50000);
        return asciiText;
      }
      
      return extractedText.substring(0, 50000);
    } catch (error) {
      console.error('DOCX extraction error:', error);
      return '';
    }
  }
  
  // For TXT files
  if (fileName.endsWith('.txt')) {
    const textDecoder = new TextDecoder('utf-8', { fatal: false });
    return textDecoder.decode(buffer);
  }
  
  // For DOC files (legacy format - harder to parse)
  if (fileName.endsWith('.doc')) {
    const textDecoder = new TextDecoder('utf-8', { fatal: false });
    const text = textDecoder.decode(buffer);
    // Extract readable text
    return text.replace(/[^\x20-\x7E\n\r]/g, ' ').substring(0, 10000);
  }
  
  return '';
}

// Detect insecure HTTP links
function detectInsecureLinks(text: string): Finding[] {
  const findings: Finding[] = [];
  const httpLinkRegex = /https?:\/\/[^\s<>"{}|\\^`\[\]]+/gi;
  const matches = text.matchAll(httpLinkRegex);
  let id = 1;
  
  for (const match of matches) {
    const url = match[0];
    if (url.toLowerCase().startsWith('http://') && !url.toLowerCase().includes('localhost')) {
      // Skip common metadata URLs that are typically safe
      const safeDomains = [
        'www.w3.org',
        'ns.adobe.com',
        'purl.org',
        'schemas.microsoft.com',
        'xmlns.com'
      ];
      
      const isSafeDomain = safeDomains.some(domain => url.toLowerCase().includes(domain));
      
      if (!isSafeDomain) {
        findings.push({
          id: id++,
          category: 'Security',
          severity: 'High',
          description: 'Insecure HTTP link detected (should use HTTPS)',
          location: url.length > 80 ? url.substring(0, 80) + '...' : url
        });
      }
    }
  }
  
  return findings;
}

// Detect personal information
function detectPersonalInformation(text: string): Finding[] {
  const findings: Finding[] = [];
  let id = 100;
  
  // Email addresses
  const emailRegex = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g;
  const emails = text.match(emailRegex) || [];
  if (emails.length > 0) {
    const uniqueEmails = [...new Set(emails)];
    uniqueEmails.forEach((email, index) => {
      if (index < 5) { // Limit to first 5 emails
        findings.push({
          id: id++,
          category: 'Privacy',
          severity: 'Medium',
          description: `Email address detected: ${email}`,
          location: `Found in document content`
        });
      }
    });
  }
  
  // Phone numbers (US format)
  const phoneRegex = /\b(\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b/g;
  const phones = text.match(phoneRegex) || [];
  if (phones.length > 0) {
    const uniquePhones = [...new Set(phones)];
    uniquePhones.forEach((phone, index) => {
      if (index < 3) { // Limit to first 3 phone numbers
        findings.push({
          id: id++,
          category: 'Privacy',
          severity: 'Medium',
          description: `Phone number detected: ${phone}`,
          location: `Found in document content`
        });
      }
    });
  }
  
  // Social Security Numbers (SSN)
  const ssnRegex = /\b\d{3}-?\d{2}-?\d{4}\b/g;
  const ssns = text.match(ssnRegex) || [];
  if (ssns.length > 0) {
    ssns.forEach((ssn, index) => {
      if (index < 2) {
        findings.push({
          id: id++,
          category: 'Privacy',
          severity: 'High',
          description: `Potential SSN detected: ${ssn.substring(0, 3)}-XX-XXXX`,
          location: `Found in document content`
        });
      }
    });
  }
  
  // Credit card numbers (basic pattern)
  const ccRegex = /\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/g;
  const ccs = text.match(ccRegex) || [];
  if (ccs.length > 0) {
    ccs.forEach((cc, index) => {
      if (index < 2) {
        findings.push({
          id: id++,
          category: 'Privacy',
          severity: 'High',
          description: `Potential credit card number detected`,
          location: `Found in document content`
        });
      }
    });
  }
  
  return findings;
}

// Detect suspicious patterns
function detectSuspiciousPatterns(text: string): Finding[] {
  const findings: Finding[] = [];
  let id = 200;
  
  // Suspicious URLs (shortened links, suspicious domains)
  const suspiciousDomains = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd',
    'free-gift', 'click-here', 'urgent-action', 'claim-now'
  ];
  
  const urlRegex = /https?:\/\/[^\s<>"{}|\\^`\[\]]+/gi;
  const urls = text.match(urlRegex) || [];
  const foundDomains = new Set<string>();
  
  urls.forEach(url => {
    const lowerUrl = url.toLowerCase();
    const matchedDomain = suspiciousDomains.find(domain => lowerUrl.includes(domain));
    if (matchedDomain && !foundDomains.has(matchedDomain)) {
      foundDomains.add(matchedDomain);
      findings.push({
        id: id++,
        category: 'Phishing',
        severity: 'Medium',
        description: `Suspicious URL shortening service detected: ${matchedDomain}`,
        location: url.length > 80 ? url.substring(0, 80) + '...' : url
      });
    }
  });
  
  // Typosquatting detection (common phishing technique)
  const typosquattingPatterns = [
    /microsoftt?\.com/gi,
    /paypall?\.com/gi,
    /amazonn?\.com/gi,
    /googIe\.com/gi, // I instead of l
    /faceb00k\.com/gi // 0 instead of o
  ];
  
  typosquattingPatterns.forEach(regex => {
    if (regex.test(text)) {
      findings.push({
        id: id++,
        category: 'Phishing',
        severity: 'High',
        description: 'Potential typosquatting domain detected (common phishing technique)',
        location: 'Found in document content'
      });
      return;
    }
  });
  
  return findings;
}

// Detect compliance issues
function detectComplianceIssues(text: string): Finding[] {
  const findings: Finding[] = [];
  let id = 300;
  
  // Check for GDPR-related content without disclaimers
  const gdprKeywords = ['personal data', 'data processing', 'consent', 'data subject'];
  const hasGdprContent = gdprKeywords.some(keyword => text.toLowerCase().includes(keyword));
  const hasDisclaimer = text.toLowerCase().includes('privacy policy') || 
                        text.toLowerCase().includes('data protection') ||
                        text.toLowerCase().includes('gdpr');
  
  if (hasGdprContent && !hasDisclaimer) {
    findings.push({
      id: id++,
      category: 'Compliance',
      severity: 'Medium',
      description: 'GDPR-related content detected without privacy disclaimer',
      location: 'Document should include privacy policy or data protection notice'
    });
  }
  
  // Check for financial information without disclaimers
  const financialKeywords = ['investment', 'financial advice', 'returns', 'guaranteed'];
  const hasFinancialContent = financialKeywords.some(keyword => text.toLowerCase().includes(keyword));
  const hasFinancialDisclaimer = text.toLowerCase().includes('not financial advice') ||
                                text.toLowerCase().includes('disclaimer') ||
                                text.toLowerCase().includes('risk');
  
  if (hasFinancialContent && !hasFinancialDisclaimer) {
    findings.push({
      id: id++,
      category: 'Compliance',
      severity: 'Low',
      description: 'Financial content detected without appropriate disclaimer',
      location: 'Document should include financial disclaimer'
    });
  }
  
  return findings;
}

// Enhanced phishing detection
function detectPhishingAttempts(text: string): Finding[] {
  const findings: Finding[] = [];
  let id = 250;
  const lowerText = text.toLowerCase();
  
  // Phishing indicators with severity
  const phishingPatterns = [
    {
      keywords: ['urgent action required', 'immediate action needed', 'act now or account will be closed'],
      severity: 'High' as const,
      description: 'Urgent action phishing language detected'
    },
    {
      keywords: ['verify your account', 'confirm your identity', 'update your information'],
      severity: 'High' as const,
      description: 'Account verification phishing attempt detected'
    },
    {
      keywords: ['click here to claim', 'limited time offer', 'free gift', 'you have won'],
      severity: 'Medium' as const,
      description: 'Suspicious promotional language detected'
    },
    {
      keywords: ['suspended', 'locked', 'expired', 'terminated'],
      severity: 'Medium' as const,
      description: 'Account status threat language detected'
    },
    {
      keywords: ['wire transfer', 'send money', 'bitcoin', 'cryptocurrency'],
      severity: 'High' as const,
      description: 'Financial transaction request detected'
    }
  ];
  
  phishingPatterns.forEach(pattern => {
    const found = pattern.keywords.some(keyword => lowerText.includes(keyword));
    if (found) {
      findings.push({
        id: id++,
        category: 'Phishing',
        severity: pattern.severity,
        description: pattern.description,
        location: 'Found in document content'
      });
    }
  });
  
  // Suspicious email domains
  const suspiciousEmailDomains = [
    'gmail-support', 'microsoft-security', 'paypal-security',
    'amazon-verify', 'bank-security', 'irs-gov'
  ];
  
  const emailRegex = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g;
  const emails = text.match(emailRegex) || [];
  emails.forEach(email => {
    const domain = email.split('@')[1]?.toLowerCase();
    if (domain && suspiciousEmailDomains.some(sus => domain.includes(sus))) {
      findings.push({
        id: id++,
        category: 'Phishing',
        severity: 'High',
        description: `Suspicious email domain detected: ${email}`,
        location: 'Found in document content'
      });
    }
  });
  
  return findings;
}

// Data breach detection - exposed credentials and sensitive data
function detectDataBreachRisks(text: string): Finding[] {
  const findings: Finding[] = [];
  let id = 350;
  
  // API keys and tokens
  const apiKeyPatterns = [
    {
      regex: /(api[_-]?key|apikey)\s*[:=]\s*['"]?([a-zA-Z0-9]{20,})['"]?/gi,
      severity: 'High' as const,
      description: 'API key or token exposed'
    },
    {
      regex: /(secret|password|pwd)\s*[:=]\s*['"]?([a-zA-Z0-9]{8,})['"]?/gi,
      severity: 'High' as const,
      description: 'Password or secret exposed in plain text'
    },
    {
      regex: /(aws[_-]?access[_-]?key|aws[_-]?secret)/gi,
      severity: 'High' as const,
      description: 'AWS credentials detected'
    },
    {
      regex: /(sk_live_|pk_live_)[a-zA-Z0-9]{24,}/gi,
      severity: 'High' as const,
      description: 'Stripe API key detected'
    }
  ];
  
  apiKeyPatterns.forEach(pattern => {
    const matches = text.matchAll(pattern.regex);
    for (const match of matches) {
      findings.push({
        id: id++,
        category: 'Security',
        severity: pattern.severity,
        description: pattern.description,
        location: 'Found in document content - remove immediately'
      });
      break; // Only report once per pattern
    }
  });
  
  // Database connection strings
  const dbConnectionRegex = /(mongodb|mysql|postgresql|sqlserver):\/\/[^\s]+/gi;
  const dbConnections = text.match(dbConnectionRegex) || [];
  if (dbConnections.length > 0) {
    findings.push({
      id: id++,
      category: 'Security',
      severity: 'High',
      description: 'Database connection string exposed',
      location: 'Found in document content - contains credentials'
    });
  }
  
  // IP addresses (could indicate infrastructure exposure)
  const ipRegex = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
  const ips = text.match(ipRegex) || [];
  const privateIPs = ips.filter(ip => {
    const parts = ip.split('.').map(Number);
    return !(
      parts[0] === 10 ||
      (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
      (parts[0] === 192 && parts[1] === 168)
    );
  });
  
  if (privateIPs.length > 3) {
    findings.push({
      id: id++,
      category: 'Security',
      severity: 'Medium',
      description: 'Multiple public IP addresses detected',
      location: 'May expose infrastructure details'
    });
  }
  
  // Exposed file paths that could indicate system structure
  const sensitivePaths = [
    /\/etc\/passwd/gi,
    /\/etc\/shadow/gi,
    /C:\\Users\\/gi,
    /\/home\/[^\/]+\//gi
  ];
  
  sensitivePaths.forEach(regex => {
    if (regex.test(text)) {
      findings.push({
        id: id++,
        category: 'Security',
        severity: 'Medium',
        description: 'System file path exposed',
        location: 'May reveal system structure'
      });
      return;
    }
  });
  
  return findings;
}

// Calculate MirrorScore based on findings - STRICT SCORING
function calculateMirrorScore(findings: Finding[]): number {
  if (findings.length === 0) {
    return 9.5; // Near-perfect score for clean documents
  }
  
  let score = 10; // Start with perfect score
  
  // Count findings by severity
  const highCount = findings.filter(f => f.severity === 'High').length;
  const mediumCount = findings.filter(f => f.severity === 'Medium').length;
  const lowCount = findings.filter(f => f.severity === 'Low').length;
  
  // Deduct points based on severity (more strict)
  score -= highCount * 2.5; // High severity: -2.5 each
  score -= mediumCount * 1.2; // Medium severity: -1.2 each
  score -= lowCount * 0.4; // Low severity: -0.4 each
  
  // Additional penalties for multiple issues
  if (highCount >= 3) {
    score -= 1.5; // Multiple high-severity issues
  }
  if (findings.length >= 10) {
    score -= 1.0; // Too many findings overall
  }
  
  // Category-specific penalties
  const phishingCount = findings.filter(f => f.category === 'Phishing').length;
  const securityCount = findings.filter(f => f.category === 'Security').length;
  const privacyCount = findings.filter(f => f.category === 'Privacy').length;
  
  if (phishingCount >= 2) {
    score -= 1.0; // Multiple phishing indicators
  }
  if (securityCount >= 5) {
    score -= 1.5; // Multiple security issues
  }
  if (privacyCount >= 3) {
    score -= 1.0; // Multiple privacy concerns
  }
  
  // Ensure score is between 0 and 10
  score = Math.max(0, Math.min(10, score));
  
  // Round to 1 decimal place
  return Math.round(score * 10) / 10;
}

// Main analysis function
export async function analyzeDocument(file: File): Promise<AnalysisResult> {
  try {
    console.log(`[Analyzer] Starting analysis for: ${file.name}`);
    
    // Extract text from document
    const textContent = await extractTextFromFile(file);
    console.log(`[Analyzer] Extracted ${textContent.length} characters of text`);
    
    if (!textContent || textContent.trim().length < 10) {
      console.log(`[Analyzer] Insufficient text extracted, returning limited analysis`);
      // If we can't extract meaningful text, return findings indicating analysis limitation
      return {
        mirrorScore: 6.0, // Moderate score due to inability to analyze
        findings: [
          {
            id: 1,
            category: 'Security',
            severity: 'Medium',
            description: 'Unable to extract text content for complete analysis',
            location: 'Document may be encrypted, image-based, or in unsupported format'
          },
          {
            id: 2,
            category: 'Security',
            severity: 'Low',
            description: 'Limited analysis capability - cannot verify document security',
            location: 'Recommend manual review of document content'
          }
        ],
        textContent: '',
        metadata: {
          wordCount: 0,
          linkCount: 0,
          emailCount: 0,
          phoneCount: 0
        }
      };
    }
    
    // Perform various analyses
    console.log(`[Analyzer] Running security analysis...`);
    const insecureLinks = detectInsecureLinks(textContent);
    console.log(`[Analyzer] Found ${insecureLinks.length} insecure links`);
    
    const personalInfo = detectPersonalInformation(textContent);
    console.log(`[Analyzer] Found ${personalInfo.length} personal information items`);
    
    const suspiciousPatterns = detectSuspiciousPatterns(textContent);
    console.log(`[Analyzer] Found ${suspiciousPatterns.length} suspicious patterns`);
    
    const phishingAttempts = detectPhishingAttempts(textContent);
    console.log(`[Analyzer] Found ${phishingAttempts.length} phishing attempts`);
    
    const dataBreachRisks = detectDataBreachRisks(textContent);
    console.log(`[Analyzer] Found ${dataBreachRisks.length} data breach risks`);
    
    const complianceIssues = detectComplianceIssues(textContent);
    console.log(`[Analyzer] Found ${complianceIssues.length} compliance issues`);
    
    // Combine all findings
    const allFindings = [
      ...insecureLinks,
      ...personalInfo,
      ...suspiciousPatterns,
      ...phishingAttempts,
      ...dataBreachRisks,
      ...complianceIssues
    ];
    
    console.log(`[Analyzer] Total findings: ${allFindings.length}`);
    
    // Calculate metadata
    const wordCount = textContent.split(/\s+/).filter(w => w.length > 0).length;
    const linkCount = (textContent.match(/https?:\/\/[^\s]+/gi) || []).length;
    const emailCount = (textContent.match(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g) || []).length;
    const phoneCount = (textContent.match(/\b(\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b/g) || []).length;
    
    // Add baseline risk assessment
    // Documents with links, emails, or personal info have inherent risk
    if (allFindings.length === 0) {
      // Even "clean" documents have some baseline considerations
      if (linkCount > 0 || emailCount > 0 || phoneCount > 0) {
        // Document contains potentially sensitive elements but no issues detected
        // This is actually good, but we'll keep score realistic
        allFindings.push({
          id: 999,
          category: 'Security',
          severity: 'Low',
          description: 'Document contains links or contact information - ensure proper handling',
          location: 'General document review recommended'
        });
      }
    }
    
    // Calculate MirrorScore
    const mirrorScore = calculateMirrorScore(allFindings);
    
    return {
      mirrorScore,
      findings: allFindings,
      textContent: textContent.substring(0, 5000), // Limit stored text
      metadata: {
        wordCount,
        linkCount,
        emailCount,
        phoneCount
      }
    };
  } catch (error) {
    console.error('Document analysis error:', error);
    throw new Error('Failed to analyze document');
  }
}

