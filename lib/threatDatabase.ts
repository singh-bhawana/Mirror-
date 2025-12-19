// Comprehensive Threat Database
// Contains patterns, keywords, and indicators for various security, privacy, and compliance threats

export interface ThreatPattern {
  pattern: RegExp | string;
  category: 'Security' | 'Privacy' | 'Phishing' | 'Compliance' | 'Data Breach';
  severity: 'High' | 'Medium' | 'Low';
  description: string;
  weight: number; // For scoring calculation
}

// Security Threats
export const securityThreats: ThreatPattern[] = [
  // Insecure protocols
  {
    pattern: /http:\/\/(?!localhost|127\.0\.0\.1|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)[^\s]+/gi,
    category: 'Security',
    severity: 'High',
    description: 'Insecure HTTP link detected (should use HTTPS)',
    weight: 2.5
  },
  {
    pattern: /ftp:\/\/[^\s]+/gi,
    category: 'Security',
    severity: 'High',
    description: 'Unencrypted FTP link detected',
    weight: 2.0
  },
  
  // Exposed credentials
  {
    pattern: /(password|pwd|passwd)\s*[:=]\s*['"]?([^\s'"]{6,})['"]?/gi,
    category: 'Security',
    severity: 'High',
    description: 'Password exposed in plain text',
    weight: 3.0
  },
  {
    pattern: /(api[_-]?key|apikey|access[_-]?key)\s*[:=]\s*['"]?([a-zA-Z0-9_-]{20,})['"]?/gi,
    category: 'Security',
    severity: 'High',
    description: 'API key or access token exposed',
    weight: 3.0
  },
  {
    pattern: /(secret|secret[_-]?key|private[_-]?key)\s*[:=]\s*['"]?([a-zA-Z0-9+/=]{20,})['"]?/gi,
    category: 'Security',
    severity: 'High',
    description: 'Secret key or private key exposed',
    weight: 3.5
  },
  
  // Cloud service credentials
  {
    pattern: /AKIA[0-9A-Z]{16}/gi,
    category: 'Security',
    severity: 'High',
    description: 'AWS Access Key ID detected',
    weight: 3.5
  },
  {
    pattern: /(aws[_-]?secret[_-]?access[_-]?key|aws[_-]?secret)\s*[:=]\s*['"]?([a-zA-Z0-9+/=]{40,})['"]?/gi,
    category: 'Security',
    severity: 'High',
    description: 'AWS Secret Access Key exposed',
    weight: 4.0
  },
  {
    pattern: /(sk_live_|pk_live_|sk_test_|pk_test_)[a-zA-Z0-9]{24,}/gi,
    category: 'Security',
    severity: 'High',
    description: 'Stripe API key detected',
    weight: 3.5
  },
  {
    pattern: /(ghp_|gho_|ghu_|ghs_|ghr_)[a-zA-Z0-9]{36,}/gi,
    category: 'Security',
    severity: 'High',
    description: 'GitHub token detected',
    weight: 3.5
  },
  {
    pattern: /xox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{32}/gi,
    category: 'Security',
    severity: 'High',
    description: 'Slack token detected',
    weight: 3.0
  },
  
  // Database connections
  {
    pattern: /(mongodb|mysql|postgresql|postgres|sqlserver|mssql):\/\/[^\s]+/gi,
    category: 'Security',
    severity: 'High',
    description: 'Database connection string with credentials exposed',
    weight: 3.5
  },
  {
    pattern: /(jdbc|odbc):[^\s]+/gi,
    category: 'Security',
    severity: 'High',
    description: 'JDBC/ODBC connection string detected',
    weight: 3.0
  },
  
  // SSH keys
  {
    pattern: /-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----/gi,
    category: 'Security',
    severity: 'High',
    description: 'SSH private key exposed',
    weight: 4.0
  },
  
  // JWT tokens
  {
    pattern: /eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*/g,
    category: 'Security',
    severity: 'Medium',
    description: 'JWT token detected (may contain sensitive claims)',
    weight: 2.0
  },
  
  // OAuth tokens
  {
    pattern: /(ya29\.|1//)[a-zA-Z0-9_-]+/gi,
    category: 'Security',
    severity: 'High',
    description: 'OAuth token detected',
    weight: 3.0
  },
  
  // Exposed infrastructure
  {
    pattern: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
    category: 'Security',
    severity: 'Medium',
    description: 'IP address detected (may expose infrastructure)',
    weight: 1.0
  },
  {
    pattern: /(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}/g,
    category: 'Security',
    severity: 'Medium',
    description: 'IPv6 address detected',
    weight: 1.0
  },
  
  // System paths
  {
    pattern: /(\/etc\/|\/var\/|\/usr\/|\/root\/|C:\\Windows\\|C:\\Program Files\\)/gi,
    category: 'Security',
    severity: 'Medium',
    description: 'System file path exposed',
    weight: 1.5
  },
  {
    pattern: /(\/home\/[^\/]+\/|C:\\Users\\[^\\]+\\)/gi,
    category: 'Security',
    severity: 'Low',
    description: 'User directory path exposed',
    weight: 0.8
  },
  
  // Weak encryption indicators
  {
    pattern: /(md5|sha1|des|rc4)\s*[:=]\s*['"]?[a-zA-Z0-9]+['"]?/gi,
    category: 'Security',
    severity: 'Medium',
    description: 'Weak encryption algorithm detected',
    weight: 1.5
  },
  
  // Hardcoded secrets
  {
    pattern: /(hardcoded|hard[_-]?coded|embedded)\s+(password|secret|key|token)/gi,
    category: 'Security',
    severity: 'High',
    description: 'Hardcoded credentials mentioned',
    weight: 2.5
  }
];

// Privacy Threats
export const privacyThreats: ThreatPattern[] = [
  // Email addresses
  {
    pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
    category: 'Privacy',
    severity: 'Medium',
    description: 'Email address detected',
    weight: 1.2
  },
  
  // Phone numbers (multiple formats)
  {
    pattern: /\b(\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b/g,
    category: 'Privacy',
    severity: 'Medium',
    description: 'Phone number detected',
    weight: 1.2
  },
  {
    pattern: /\b\+?[1-9]\d{1,14}\b/g,
    category: 'Privacy',
    severity: 'Medium',
    description: 'International phone number detected',
    weight: 1.2
  },
  
  // Social Security Numbers
  {
    pattern: /\b\d{3}-?\d{2}-?\d{4}\b/g,
    category: 'Privacy',
    severity: 'High',
    description: 'Potential Social Security Number (SSN) detected',
    weight: 3.0
  },
  {
    pattern: /\b\d{9}\b/g,
    category: 'Privacy',
    severity: 'Medium',
    description: 'Potential 9-digit identifier (may be SSN)',
    weight: 2.0
  },
  
  // Credit/Debit Cards
  {
    pattern: /\b(?:\d{4}[-\s]?){3}\d{4}\b/g,
    category: 'Privacy',
    severity: 'High',
    description: 'Potential credit/debit card number detected',
    weight: 3.5
  },
  {
    pattern: /\b\d{13,19}\b/g,
    category: 'Privacy',
    severity: 'Medium',
    description: 'Potential payment card number (13-19 digits)',
    weight: 2.5
  },
  
  // Bank account numbers
  {
    pattern: /(account[_-]?number|acct[_-]?no|bank[_-]?account)\s*[:=]\s*['"]?(\d{8,})['"]?/gi,
    category: 'Privacy',
    severity: 'High',
    description: 'Bank account number detected',
    weight: 3.5
  },
  {
    pattern: /\b\d{8,12}\b/g,
    category: 'Privacy',
    severity: 'Low',
    description: 'Potential account number (8-12 digits)',
    weight: 1.0
  },
  
  // Driver's License
  {
    pattern: /(driver['']?s?\s*license|dl[_-]?number)\s*[:=]\s*['"]?([A-Z0-9]{6,})['"]?/gi,
    category: 'Privacy',
    severity: 'High',
    description: 'Driver\'s license number detected',
    weight: 3.0
  },
  
  // Passport numbers
  {
    pattern: /(passport[_-]?number|passport[_-]?no)\s*[:=]\s*['"]?([A-Z0-9]{6,})['"]?/gi,
    category: 'Privacy',
    severity: 'High',
    description: 'Passport number detected',
    weight: 3.0
  },
  
  // Date of Birth
  {
    pattern: /(date[_-]?of[_-]?birth|dob|birth[_-]?date)\s*[:=]\s*['"]?(\d{1,2}[-\/]\d{1,2}[-\/]\d{2,4})['"]?/gi,
    category: 'Privacy',
    severity: 'Medium',
    description: 'Date of birth detected',
    weight: 1.5
  },
  
  // Medical information
  {
    pattern: /(medical[_-]?record|patient[_-]?id|health[_-]?insurance)\s*[:=]\s*['"]?([A-Z0-9-]+)['"]?/gi,
    category: 'Privacy',
    severity: 'High',
    description: 'Medical/health information detected',
    weight: 3.0
  },
  
  // Financial information
  {
    pattern: /(routing[_-]?number|aba[_-]?number)\s*[:=]\s*['"]?(\d{9})['"]?/gi,
    category: 'Privacy',
    severity: 'High',
    description: 'Bank routing number detected',
    weight: 3.0
  },
  {
    pattern: /(cvv|cvc|cvv2)\s*[:=]\s*['"]?(\d{3,4})['"]?/gi,
    category: 'Privacy',
    severity: 'High',
    description: 'Credit card CVV/CVC detected',
    weight: 3.5
  },
  
  // Tax ID / EIN
  {
    pattern: /(tax[_-]?id|ein|employer[_-]?identification)\s*[:=]\s*['"]?(\d{2}-?\d{7})['"]?/gi,
    category: 'Privacy',
    severity: 'High',
    description: 'Tax ID or EIN detected',
    weight: 3.0
  },
  
  // Physical addresses
  {
    pattern: /\d+\s+[A-Za-z0-9\s,.-]+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Parkway|Pkwy)[\s,]+[A-Za-z\s]+,\s*[A-Z]{2}\s+\d{5}(?:-\d{4})?/gi,
    category: 'Privacy',
    severity: 'Medium',
    description: 'Physical address detected',
    weight: 1.5
  },
  
  // IP addresses (can be PII in some contexts)
  {
    pattern: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
    category: 'Privacy',
    severity: 'Low',
    description: 'IP address detected (may be personal information)',
    weight: 0.8
  },
  
  // MAC addresses
  {
    pattern: /\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b/g,
    category: 'Privacy',
    severity: 'Low',
    description: 'MAC address detected',
    weight: 0.8
  }
];

// Phishing Threats
export const phishingThreats: ThreatPattern[] = [
  // Urgent action language
  {
    pattern: /(urgent|immediate|asap|right away|act now|expires? soon)/gi,
    category: 'Phishing',
    severity: 'High',
    description: 'Urgent action language detected (common phishing tactic)',
    weight: 2.5
  },
  {
    pattern: /(your account (?:will be|is) (?:suspended|locked|closed|terminated|deleted))/gi,
    category: 'Phishing',
    severity: 'High',
    description: 'Account threat language detected',
    weight: 2.5
  },
  
  // Verification requests
  {
    pattern: /(verify|confirm|validate|update)\s+(?:your\s+)?(?:account|identity|information|details|credentials)/gi,
    category: 'Phishing',
    severity: 'High',
    description: 'Account verification request detected',
    weight: 2.5
  },
  {
    pattern: /(click (?:here|below|link) to (?:verify|confirm|update|access))/gi,
    category: 'Phishing',
    severity: 'High',
    description: 'Suspicious verification link request',
    weight: 2.5
  },
  
  // Promotional scams
  {
    pattern: /(you (?:have|are) (?:won|selected|chosen)|congratulations|free (?:gift|prize|money|trial))/gi,
    category: 'Phishing',
    severity: 'Medium',
    description: 'Suspicious promotional language detected',
    weight: 1.5
  },
  {
    pattern: /(limited time|act now|don't miss|exclusive offer|one time only)/gi,
    category: 'Phishing',
    severity: 'Medium',
    description: 'High-pressure sales language detected',
    weight: 1.5
  },
  
  // Financial scams
  {
    pattern: /(wire transfer|send money|bitcoin|cryptocurrency|western union|money gram)/gi,
    category: 'Phishing',
    severity: 'High',
    description: 'Financial transaction request detected',
    weight: 3.0
  },
  {
    pattern: /(tax refund|irs|government payment|stimulus check)/gi,
    category: 'Phishing',
    severity: 'High',
    description: 'Government payment scam language detected',
    weight: 2.5
  },
  
  // Suspicious domains
  {
    pattern: /(bit\.ly|tinyurl\.com|goo\.gl|t\.co|ow\.ly|is\.gd|short\.link)/gi,
    category: 'Phishing',
    severity: 'Medium',
    description: 'URL shortening service detected (often used in phishing)',
    weight: 1.5
  },
  
  // Typosquatting
  {
    pattern: /(microsoftt?|paypall?|amazonn?|googIe|faceb00k|appIe)\.(com|net|org)/gi,
    category: 'Phishing',
    severity: 'High',
    description: 'Potential typosquatting domain detected',
    weight: 3.0
  },
  
  // Suspicious email patterns
  {
    pattern: /[a-zA-Z0-9._%+-]+@(?:gmail|microsoft|paypal|amazon|bank|irs|gov)[_-]?(?:support|security|verify|update|service)\.(?:com|net|org)/gi,
    category: 'Phishing',
    severity: 'High',
    description: 'Suspicious email domain (impersonating legitimate service)',
    weight: 3.0
  },
  
  // Social engineering
  {
    pattern: /(dear (?:valued|customer|user)|we noticed|we detected|unusual activity)/gi,
    category: 'Phishing',
    severity: 'Medium',
    description: 'Social engineering language detected',
    weight: 1.5
  },
  
  // Fake urgency
  {
    pattern: /(within (?:24|48) hours?|by (?:end of|tomorrow)|deadline|expires? (?:today|soon))/gi,
    category: 'Phishing',
    severity: 'Medium',
    description: 'Artificial urgency created',
    weight: 1.5
  }
];

// Data Breach Indicators
export const dataBreachThreats: ThreatPattern[] = [
  // Exposed credentials
  {
    pattern: /(username|user[_-]?name|login|user[_-]?id)\s*[:=]\s*['"]?([^\s'"]{3,})['"]?\s*(?:password|pwd|pass)/gi,
    category: 'Data Breach',
    severity: 'High',
    description: 'Username and password combination exposed',
    weight: 3.5
  },
  
  // Configuration files
  {
    pattern: /(config|configuration|\.env|\.config)\s*[:=]\s*\{[^}]*['"]?(?:password|secret|key|token)['"]?/gi,
    category: 'Data Breach',
    severity: 'High',
    description: 'Configuration file with credentials detected',
    weight: 3.0
  },
  
  // Backup files
  {
    pattern: /(backup|dump|export|\.bak|\.sql|\.dump)\s+(?:file|database|data)/gi,
    category: 'Data Breach',
    severity: 'Medium',
    description: 'Backup file mentioned (may contain sensitive data)',
    weight: 2.0
  },
  
  // Log files with sensitive data
  {
    pattern: /(log|logs|\.log)\s+(?:file|contains|includes)\s+(?:password|token|key|secret)/gi,
    category: 'Data Breach',
    severity: 'High',
    description: 'Log file may contain sensitive credentials',
    weight: 2.5
  },
  
  // Exposed session data
  {
    pattern: /(session[_-]?id|session[_-]?token|cookie)\s*[:=]\s*['"]?([a-zA-Z0-9+/=]{20,})['"]?/gi,
    category: 'Data Breach',
    severity: 'High',
    description: 'Session identifier or token exposed',
    weight: 2.5
  },
  
  // Database dumps
  {
    pattern: /(database|db)\s+(?:dump|export|backup|snapshot)/gi,
    category: 'Data Breach',
    severity: 'High',
    description: 'Database dump mentioned (may contain sensitive data)',
    weight: 3.0
  },
  
  // Exposed API endpoints
  {
    pattern: /(api[_-]?endpoint|api[_-]?url)\s*[:=]\s*['"]?(https?:\/\/[^\s'"]+)['"]?/gi,
    category: 'Data Breach',
    severity: 'Medium',
    description: 'API endpoint exposed (may reveal infrastructure)',
    weight: 1.5
  },
  
  // Error messages with sensitive info
  {
    pattern: /(error|exception|traceback|stack[_-]?trace).*?(?:password|token|key|secret|credential)/gi,
    category: 'Data Breach',
    severity: 'Medium',
    description: 'Error message may expose sensitive information',
    weight: 2.0
  }
];

// Compliance Threats
export const complianceThreats: ThreatPattern[] = [
  // GDPR violations
  {
    pattern: /(personal data|personal information|pii|personally identifiable)/gi,
    category: 'Compliance',
    severity: 'Medium',
    description: 'Personal data mentioned without privacy policy',
    weight: 1.5
  },
  {
    pattern: /(data processing|data collection|data storage)/gi,
    category: 'Compliance',
    severity: 'Medium',
    description: 'Data processing mentioned without consent language',
    weight: 1.5
  },
  
  // Financial disclaimers
  {
    pattern: /(investment|financial advice|returns|guaranteed|profit|dividend)/gi,
    category: 'Compliance',
    severity: 'Low',
    description: 'Financial content without appropriate disclaimer',
    weight: 0.8
  },
  
  // Medical disclaimers
  {
    pattern: /(medical advice|health information|diagnosis|treatment)/gi,
    category: 'Compliance',
    severity: 'Medium',
    description: 'Medical content without appropriate disclaimer',
    weight: 1.5
  },
  
  // Legal disclaimers
  {
    pattern: /(legal advice|attorney|lawyer|counsel)/gi,
    category: 'Compliance',
    severity: 'Low',
    description: 'Legal content without appropriate disclaimer',
    weight: 0.8
  },
  
  // Copyright issues
  {
    pattern: /(copyright|©|all rights reserved)/gi,
    category: 'Compliance',
    severity: 'Low',
    description: 'Copyright notice may be missing or incomplete',
    weight: 0.5
  }
];

// Combine all threats
export const allThreats: ThreatPattern[] = [
  ...securityThreats,
  ...privacyThreats,
  ...phishingThreats,
  ...dataBreachThreats,
  ...complianceThreats
];

