'use client';

import { useState, useCallback, useRef, useEffect } from 'react';
import { useDropzone } from 'react-dropzone';
import Link from 'next/link';
import ScanResults from '@/app/components/ScanResults';

interface Finding {
  id: number;
  category: string;
  severity: string;
  description: string;
  location: string;
}

interface Analysis {
  mirrorScore: number;
  findings: Finding[];
}

export default function Home() {
  const [messages, setMessages] = useState<{ text: string; isBot: boolean; timestamp?: Date }[]>([
    { text: 'Hi! I\'m MiAI, your document security assistant. Upload a document and I\'ll help you understand the analysis results!', isBot: true, timestamp: new Date() }
  ]);
  const [uploading, setUploading] = useState(false);
  const [currentAnalysis, setCurrentAnalysis] = useState<Analysis | null>(null);
  const [showScanResults, setShowScanResults] = useState(false);
  const [isTyping, setIsTyping] = useState(false);
  const [chatInput, setChatInput] = useState('');
  const messagesEndRef = useRef<HTMLDivElement>(null);

  // Auto-scroll to bottom when new messages arrive
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, isTyping]);

  const onDrop = useCallback(async (acceptedFiles: File[]) => {
    const file = acceptedFiles[0];
    if (!file) return;

    setUploading(true);
    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await fetch('/api/upload', {
        method: 'POST',
        body: formData
      });

      if (!response.ok) {
        throw new Error('Upload failed');
      }

      const analysis: Analysis = await response.json();
      setCurrentAnalysis(analysis);
      
      // Show scan results modal
      setShowScanResults(true);
      
      setMessages(prev => [...prev, {
        text: `I've analyzed "${file.name}" and found ${analysis.findings.length} potential issues. The document's MirrorScore is ${analysis.mirrorScore} out of 10, which indicates a ${analysis.mirrorScore >= 8 ? 'low' : analysis.mirrorScore >= 5 ? 'medium' : 'high'} risk level.\n\nWould you like me to explain the findings in detail?`,
        isBot: true,
        timestamp: new Date()
      }]);
    } catch (error) {
      console.error('Upload error:', error);
      setMessages(prev => [...prev, {
        text: 'Sorry, there was an error analyzing the document. Please try again.',
        isBot: true
      }]);
    } finally {
      setUploading(false);
    }
  }, []);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    multiple: false,
    accept: {
      'application/pdf': ['.pdf'],
      'application/msword': ['.doc'],
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document': ['.docx'],
      'text/plain': ['.txt']
    }
  });

  const sendMessage = async (message: string) => {
    if (!message.trim()) return;
    
    const userMessage = { text: message, isBot: false, timestamp: new Date() };
    setMessages(prev => [...prev, userMessage]);
    setChatInput('');
    setIsTyping(true);
    
    try {
      const response = await fetch('/api/chat', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          message,
          context: currentAnalysis,
          conversationHistory: messages.slice(-5) // Send last 5 messages for context
        })
      });

      if (!response.ok) {
        throw new Error('Chat failed');
      }

      const { response: aiResponse } = await response.json();
      setIsTyping(false);
      setMessages(prev => [...prev, { 
        text: aiResponse, 
        isBot: true, 
        timestamp: new Date() 
      }]);
    } catch (error) {
      console.error('Chat error:', error);
      setIsTyping(false);
      setMessages(prev => [...prev, {
        text: 'Sorry, I encountered an error. Please try again.',
        isBot: true,
        timestamp: new Date()
      }]);
    }
  };

  const getScanSummary = () => {
    if (!currentAnalysis) return null;
    
    const findingsByCategory = {
      phishing: currentAnalysis.findings.filter(f => f.category.toLowerCase() === 'phishing').length,
      privacy: currentAnalysis.findings.filter(f => f.category.toLowerCase() === 'privacy').length,
      security: currentAnalysis.findings.filter(f => f.category.toLowerCase() === 'security').length,
    };
    
    const severityBreakdown = {
      high: currentAnalysis.findings.filter(f => f.severity.toLowerCase() === 'high').length,
      medium: currentAnalysis.findings.filter(f => f.severity.toLowerCase() === 'medium').length,
      low: currentAnalysis.findings.filter(f => f.severity.toLowerCase() === 'low').length,
    };
    
    return {
      mirrorScore: currentAnalysis.mirrorScore,
      totalFindings: currentAnalysis.findings.length,
      findingsByCategory,
      severityBreakdown
    };
  };

  return (
    <main className="min-h-screen relative overflow-hidden">
      <div className="gradient-bg fixed inset-0 pointer-events-none" />
      
      {/* Background Purple Shapes */}
      <div className="fixed inset-0 pointer-events-none overflow-hidden">
        <div className="absolute -left-32 top-20 w-96 h-96 bg-purple-500/20 rounded-full blur-3xl"></div>
        <div className="absolute -right-32 bottom-20 w-96 h-96 bg-purple-600/20 rounded-full blur-3xl"></div>
        <div className="absolute right-20 top-1/2 w-72 h-72 bg-purple-400/10 rounded-full blur-3xl"></div>
      </div>
      
      {/* Navigation */}
      <nav className="relative flex justify-between items-center p-6 bg-black/20 backdrop-blur-sm z-10">
        <Link href="/" className="flex items-center gap-3">
          <div className="w-10 h-10 bg-white rounded-lg flex items-center justify-center">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none">
              <path d="M12 2L2 7L12 12L22 7L12 2Z" fill="#9747FF"/>
              <path d="M2 17L12 22L22 17" stroke="#9747FF" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
              <path d="M2 12L12 17L22 12" stroke="#9747FF" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
            </svg>
          </div>
          <div className="text-2xl font-bold text-white">Reveal the Red</div>
        </Link>
        <div className="flex gap-6 items-center">
          <Link href="/" className="text-white hover:text-purple-400 transition-colors font-medium">HOME</Link>
          <Link href="/" className="text-white hover:text-purple-400 transition-colors font-medium">SCAN US</Link>
          <Link href="/mirrorscore" className="text-white hover:text-purple-400 transition-colors font-medium">MIRRORSCORE</Link>
          <Link href="/history" className="text-white hover:text-purple-400 transition-colors font-medium">HISTORY</Link>
          <Link href="/login" className="btn-primary px-6 py-2">LOGIN</Link>
          <Link href="/signup" className="btn-primary px-6 py-2">SIGN UP</Link>
        </div>
      </nav>

      {/* Upload Section */}
      <div className="relative max-w-2xl mx-auto mt-32 p-4 z-10">
        <div 
          {...getRootProps()} 
          className="bg-black/40 backdrop-blur-sm border-2 border-white/10 rounded-2xl cursor-pointer hover:border-purple-500/40 transition-all p-16 text-center"
        >
          <input {...getInputProps()} />
          {/* Three Overlapping Documents Icon */}
          <div className="flex items-center justify-center gap-2 mb-6 relative">
            <div className="relative">
              <svg className="w-16 h-20 text-purple-500" viewBox="0 0 24 30" fill="none">
                <rect x="2" y="2" width="20" height="26" rx="2" stroke="currentColor" strokeWidth="2" fill="rgba(151, 71, 255, 0.1)"/>
                <circle cx="12" cy="10" r="2" fill="currentColor"/>
                <line x1="8" y1="16" x2="16" y2="16" stroke="currentColor" strokeWidth="2"/>
              </svg>
              <svg className="w-16 h-20 text-purple-400 absolute -top-1 -left-1" viewBox="0 0 24 30" fill="none" style={{ zIndex: -1 }}>
                <rect x="2" y="2" width="20" height="26" rx="2" stroke="currentColor" strokeWidth="2" fill="rgba(151, 71, 255, 0.1)"/>
                <text x="12" y="12" textAnchor="middle" fontSize="8" fill="currentColor">*</text>
              </svg>
              <svg className="w-16 h-20 text-purple-300 absolute -top-2 -left-2" viewBox="0 0 24 30" fill="none" style={{ zIndex: -2 }}>
                <rect x="2" y="2" width="20" height="26" rx="2" stroke="currentColor" strokeWidth="2" fill="rgba(151, 71, 255, 0.1)"/>
                <circle cx="12" cy="10" r="1.5" fill="currentColor"/>
              </svg>
            </div>
          </div>
          <p className="text-white mb-6 text-lg font-medium">
            {uploading ? 'Analyzing document...' : isDragActive ? 'Drop the file here' : 'Choose a file or drag & drop it here'}
          </p>
          <button 
            className="bg-purple-600 hover:bg-purple-700 text-white font-semibold px-12 py-4 rounded-xl transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            disabled={uploading}
          >
            {uploading ? 'Analyzing...' : 'Upload'}
          </button>
        </div>
      </div>

      {/* Chat Interface - Bottom Left */}
      <div className="fixed bottom-6 left-6 w-96 z-20">
        <div className="bg-black/70 backdrop-blur-md border border-white/10 rounded-2xl shadow-2xl flex flex-col h-[600px]">
          {/* Chat Header */}
          <div className="flex items-center gap-3 p-4 border-b border-white/10">
            <div className="w-10 h-10 rounded-full bg-gradient-to-br from-purple-600 to-purple-800 flex items-center justify-center">
              <svg className="w-6 h-6 text-white" viewBox="0 0 24 24" fill="currentColor">
                <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/>
              </svg>
            </div>
            <div className="flex-1">
              <h3 className="font-bold text-white text-lg">MiAI Assistant</h3>
              <p className="text-xs text-white/60">
                {isTyping ? 'Typing...' : 'Online'}
              </p>
            </div>
          </div>

          {/* Messages Area */}
          <div className="flex-1 overflow-y-auto p-4 space-y-4 custom-scrollbar">
            {messages.map((msg, i) => (
              <div
                key={i}
                className={`flex ${msg.isBot ? 'justify-start' : 'justify-end'}`}
              >
                <div
                  className={`max-w-[80%] rounded-2xl p-3 ${
                    msg.isBot
                      ? 'bg-purple-600/30 rounded-tl-none text-white'
                      : 'bg-purple-500/20 rounded-tr-none text-white'
                  }`}
                >
                  <p className="text-sm whitespace-pre-wrap leading-relaxed">{msg.text}</p>
                  {msg.timestamp && (
                    <p className="text-xs text-white/40 mt-1">
                      {msg.timestamp.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    </p>
                  )}
                </div>
              </div>
            ))}
            {isTyping && (
              <div className="flex justify-start">
                <div className="bg-purple-600/30 rounded-2xl rounded-tl-none p-3">
                  <div className="flex gap-1">
                    <div className="w-2 h-2 bg-white/60 rounded-full animate-bounce" style={{ animationDelay: '0ms' }}></div>
                    <div className="w-2 h-2 bg-white/60 rounded-full animate-bounce" style={{ animationDelay: '150ms' }}></div>
                    <div className="w-2 h-2 bg-white/60 rounded-full animate-bounce" style={{ animationDelay: '300ms' }}></div>
                  </div>
                </div>
              </div>
            )}
            <div ref={messagesEndRef} />
          </div>

          {/* Input Area */}
          <div className="p-4 border-t border-white/10">
            <div className="flex gap-2 items-center">
              <button 
                className="p-2 text-white/60 hover:text-white transition-colors"
                title="Attach file"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15.172 7l-6.586 6.586a2 2 0 102.828 2.828l6.414-6.586a4 4 0 00-5.656-5.656l-6.415 6.585a6 6 0 108.486 8.486L20.5 13" />
                </svg>
              </button>
              <input
                type="text"
                value={chatInput}
                onChange={(e) => setChatInput(e.target.value)}
                placeholder="Ask me anything about your document..."
                className="flex-1 bg-white/10 rounded-lg px-4 py-2 text-white placeholder-white/40 focus:outline-none focus:ring-2 focus:ring-purple-500 text-sm"
                onKeyPress={(e) => {
                  if (e.key === 'Enter' && chatInput.trim() && !isTyping) {
                    sendMessage(chatInput);
                  }
                }}
                disabled={isTyping}
              />
              <button
                onClick={() => chatInput.trim() && !isTyping && sendMessage(chatInput)}
                disabled={isTyping || !chatInput.trim()}
                className="p-2 text-white/60 hover:text-white transition-colors disabled:opacity-30 disabled:cursor-not-allowed"
                title="Send message"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8" />
                </svg>
              </button>
            </div>
            {currentAnalysis && (
              <p className="text-xs text-white/40 mt-2 text-center">
                💡 Ask about findings, MirrorScore, or security recommendations
              </p>
            )}
          </div>
        </div>
      </div>

      {/* Scan Results Modal */}
      {showScanResults && currentAnalysis && getScanSummary() && (
        <ScanResults
          findings={currentAnalysis.findings.map(f => ({
            id: f.id.toString(),
            category: f.category,
            severity: f.severity as 'High' | 'Medium' | 'Low',
            description: f.description,
            location: f.location
          }))}
          summary={getScanSummary()!}
          onClose={() => setShowScanResults(false)}
        />
      )}
    </main>
  );
} 