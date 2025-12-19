import { NextResponse } from 'next/server';

interface Finding {
  id: number;
  category: string;
  severity: string;
  description: string;
  location: string;
}

interface Context {
  mirrorScore?: number;
  findings?: Finding[];
}

// AI Response Generator with context awareness
function generateAIResponse(message: string, context: Context | null, conversationHistory: any[] = []): string {
  const lowerMessage = message.toLowerCase().trim();
  const findings = context?.findings || [];
  const mirrorScore = context?.mirrorScore;
  
  // Greeting patterns
  if (lowerMessage.match(/^(hi|hello|hey|greetings|good morning|good afternoon|good evening)/)) {
    return "Hello! I'm MiAI, your document security assistant. I'm here to help you understand your document analysis results. How can I assist you today?";
  }

  // MirrorScore questions
  if (lowerMessage.includes('mirrorscore') || lowerMessage.includes('score') || lowerMessage.includes('rating')) {
    if (mirrorScore !== undefined) {
      const riskLevel = mirrorScore >= 8 ? 'low risk' : mirrorScore >= 5 ? 'medium risk' : 'high risk';
      return `Your document has a MirrorScore of ${mirrorScore} out of 10, which indicates a **${riskLevel}** level.\n\n` +
        `The MirrorScore evaluates:\n` +
        `• Security vulnerabilities\n` +
        `• Privacy concerns\n` +
        `• Compliance issues\n` +
        `• Overall document safety\n\n` +
        `${mirrorScore < 5 ? 'I recommend reviewing the high-severity findings to improve your score.' : 
          mirrorScore < 8 ? 'Your document has some areas that need attention. Would you like me to explain the specific findings?' :
          'Great! Your document shows good security practices. Keep up the good work!'}`;
    }
    return "I don't have a current document analysis. Please upload a document first, and I'll provide you with a detailed MirrorScore assessment.";
  }

  // Findings questions
  if (lowerMessage.includes('finding') || lowerMessage.includes('issue') || lowerMessage.includes('problem') || lowerMessage.includes('detected')) {
    if (findings.length === 0) {
      return "I don't have any findings to discuss yet. Please upload a document for analysis first.";
    }
    
    const highFindings = findings.filter(f => f.severity.toLowerCase() === 'high');
    const mediumFindings = findings.filter(f => f.severity.toLowerCase() === 'medium');
    const lowFindings = findings.filter(f => f.severity.toLowerCase() === 'low');
    
    let response = `I found **${findings.length} total findings** in your document:\n\n`;
    
    if (highFindings.length > 0) {
      response += `🔴 **${highFindings.length} High Severity** - These require immediate attention\n`;
    }
    if (mediumFindings.length > 0) {
      response += `🟡 **${mediumFindings.length} Medium Severity** - Should be addressed soon\n`;
    }
    if (lowFindings.length > 0) {
      response += `🟢 **${lowFindings.length} Low Severity** - Minor issues to consider\n\n`;
    }
    
    response += "Would you like me to explain any specific finding in detail?";
    return response;
  }

  // Security questions
  if (lowerMessage.includes('security') || lowerMessage.includes('secure') || lowerMessage.includes('vulnerability') || lowerMessage.includes('threat')) {
    const securityFindings = findings.filter(f => f.category.toLowerCase() === 'security');
    if (securityFindings.length === 0) {
      return "I didn't detect any security issues in your document. That's great! However, I recommend regular security audits to maintain document safety.";
    }
    
    const highSecurity = securityFindings.filter(f => f.severity.toLowerCase() === 'high');
    let response = `I found **${securityFindings.length} security-related findings**:\n\n`;
    
    if (highSecurity.length > 0) {
      response += `⚠️ **Critical Issues (${highSecurity.length}):**\n`;
      highSecurity.slice(0, 3).forEach((f, i) => {
        response += `${i + 1}. ${f.description}\n   Location: ${f.location}\n\n`;
      });
      response += "These high-severity security issues should be addressed immediately to protect sensitive information.\n\n";
    }
    
    response += "Would you like specific recommendations on how to fix these security issues?";
    return response;
  }

  // Privacy questions
  if (lowerMessage.includes('privacy') || lowerMessage.includes('personal data') || lowerMessage.includes('pii') || lowerMessage.includes('gdpr')) {
    const privacyFindings = findings.filter(f => f.category.toLowerCase() === 'privacy');
    if (privacyFindings.length === 0) {
      return "I didn't detect any privacy concerns in your document. Great job on protecting personal information!";
    }
    
    let response = `I identified **${privacyFindings.length} privacy-related finding${privacyFindings.length > 1 ? 's' : ''}**:\n\n`;
    privacyFindings.forEach((f, i) => {
      response += `${i + 1}. **${f.description}**\n   Severity: ${f.severity}\n   Location: ${f.location}\n\n`;
    });
    response += "Privacy concerns may violate regulations like GDPR or CCPA. I recommend reviewing these areas and ensuring proper consent or anonymization.";
    return response;
  }

  // Phishing questions
  if (lowerMessage.includes('phishing') || lowerMessage.includes('suspicious') || lowerMessage.includes('link') || lowerMessage.includes('url')) {
    const phishingFindings = findings.filter(f => f.category.toLowerCase() === 'phishing');
    if (phishingFindings.length === 0) {
      return "I didn't detect any phishing-related issues in your document. Your links appear safe!";
    }
    
    let response = `I found **${phishingFindings.length} potential phishing concern${phishingFindings.length > 1 ? 's' : ''}**:\n\n`;
    phishingFindings.forEach((f, i) => {
      response += `${i + 1}. ${f.description}\n   Location: ${f.location}\n\n`;
    });
    response += "These may include suspicious links or patterns. I recommend verifying all URLs and ensuring they point to legitimate sources.";
    return response;
  }

  // Help questions
  if (lowerMessage.includes('help') || lowerMessage.includes('what can you') || lowerMessage.includes('how can you') || lowerMessage.includes('assist')) {
    return "I'm MiAI, your document security assistant! I can help you with:\n\n" +
      "📊 **Understanding your MirrorScore** - Learn what your score means and how to improve it\n" +
      "🔍 **Analyzing findings** - Get detailed explanations of security, privacy, and compliance issues\n" +
      "🛡️ **Security recommendations** - Receive guidance on fixing vulnerabilities\n" +
      "🔒 **Privacy guidance** - Understand privacy concerns and compliance requirements\n" +
      "📝 **Document analysis** - Get insights about your uploaded documents\n\n" +
      "Just ask me anything about your document analysis!";
  }

  // Explain/Detail questions
  if (lowerMessage.includes('explain') || lowerMessage.includes('detail') || lowerMessage.includes('tell me more') || lowerMessage.includes('what does')) {
    if (findings.length === 0) {
      return "I'd be happy to explain, but I need a document analysis first. Please upload a document and I'll provide detailed explanations of all findings.";
    }
    
    // Try to match specific finding
    const categoryMatch = findings.find(f => 
      lowerMessage.includes(f.category.toLowerCase()) || 
      lowerMessage.includes(f.severity.toLowerCase())
    );
    
    if (categoryMatch) {
      return `**${categoryMatch.category} Finding - ${categoryMatch.severity} Severity**\n\n` +
        `Description: ${categoryMatch.description}\n` +
        `Location: ${categoryMatch.location}\n\n` +
        `${categoryMatch.severity === 'High' ? 'This is a critical issue that should be addressed immediately. ' : 
          categoryMatch.severity === 'Medium' ? 'This should be reviewed and fixed soon. ' : 
          'This is a minor issue but worth addressing. '}` +
        `Would you like recommendations on how to fix this?`;
    }
    
    return `I found ${findings.length} findings in your document. Here's a summary:\n\n` +
      findings.slice(0, 5).map((f, i) => 
        `${i + 1}. **${f.category}** (${f.severity}): ${f.description}`
      ).join('\n\n') +
      (findings.length > 5 ? `\n\n...and ${findings.length - 5} more findings.` : '') +
      `\n\nWhich finding would you like me to explain in more detail?`;
  }

  // Recommendation/Fix questions
  if (lowerMessage.includes('fix') || lowerMessage.includes('recommend') || lowerMessage.includes('solution') || lowerMessage.includes('how to') || lowerMessage.includes('what should')) {
    if (findings.length === 0) {
      return "I don't have any findings to provide recommendations for. Please upload a document first.";
    }
    
    const highFindings = findings.filter(f => f.severity.toLowerCase() === 'high');
    if (highFindings.length > 0) {
      return `Here are my recommendations for addressing the **${highFindings.length} high-severity findings**:\n\n` +
        `1. **Review and remove sensitive data** - Check all high-severity locations and remove or redact sensitive information\n` +
        `2. **Update insecure links** - Replace HTTP links with HTTPS where possible\n` +
        `3. **Add security disclaimers** - Include appropriate warnings for sensitive content\n` +
        `4. **Encrypt sensitive sections** - Consider encrypting parts containing personal or confidential data\n` +
        `5. **Regular audits** - Schedule periodic security reviews\n\n` +
        `Would you like specific steps for any particular finding?`;
    }
    
    return "Your document has no critical issues! For the medium and low-severity findings, I recommend:\n\n" +
      "• Review privacy-related findings and ensure compliance\n" +
      "• Verify all external links are legitimate\n" +
      "• Add appropriate disclaimers where needed\n\n" +
      "Would you like more specific guidance?";
  }

  // Thank you responses
  if (lowerMessage.match(/^(thanks|thank you|appreciate|grateful)/)) {
    return "You're welcome! I'm here whenever you need help with your document security. Feel free to ask me anything!";
  }

  // Default intelligent response
  if (context && findings.length > 0) {
    return `I understand you're asking about "${message}". Based on your document analysis:\n\n` +
      `• Your MirrorScore is ${mirrorScore}/10\n` +
      `• I found ${findings.length} findings across ${new Set(findings.map(f => f.category)).size} categories\n` +
      `• There are ${findings.filter(f => f.severity.toLowerCase() === 'high').length} high-severity issues\n\n` +
      `I can help you understand:\n` +
      `• Specific findings and their implications\n` +
      `• How to improve your MirrorScore\n` +
      `• Recommendations for fixing issues\n` +
      `• Security and privacy best practices\n\n` +
      `What would you like to know more about?`;
  }

  // Default response when no context
  return "I'm MiAI, your document security assistant! I can help you understand your document analysis results.\n\n" +
    "To get started:\n" +
    "1. Upload a document for analysis\n" +
    "2. Ask me about the findings, MirrorScore, or security concerns\n" +
    "3. Get recommendations on how to improve your document security\n\n" +
    "What would you like to know?";
}

export async function POST(request: Request) {
  try {
    const { message, context, conversationHistory } = await request.json();

    if (!message) {
      return NextResponse.json({ error: 'Message is required' }, { status: 400 });
    }

    // Simulate AI processing time (more realistic)
    const processingTime = Math.random() * 500 + 300; // 300-800ms
    await new Promise(resolve => setTimeout(resolve, processingTime));

    // Generate intelligent AI response
    const response = generateAIResponse(message, context || null, conversationHistory || []);

    return NextResponse.json({ response });
  } catch (error) {
    console.error('Chat error:', error);
    return NextResponse.json(
      { error: 'Failed to process message' },
      { status: 500 }
    );
  }
} 