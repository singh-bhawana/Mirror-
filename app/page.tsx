'use client';

import { useState, useCallback } from 'react';
import { useDropzone } from 'react-dropzone';
import Image from 'next/image';
import Link from 'next/link';
import { useAuth } from './context/AuthContext';
import ScanResults from './components/ScanResults';

interface ScanResult {
  scan: {
    id: string;
    fileName: string;
    findings: Array<{
      id: string;
      category: string;
      severity: 'High' | 'Medium' | 'Low';
      description: string;
      location: string;
    }>;
  };
  summary: {
    mirrorScore: number;
    totalFindings: number;
    findingsByCategory: {
      phishing: number;
      privacy: number;
      security: number;
    };
    severityBreakdown: {
      high: number;
      medium: number;
      low: number;
    };
  };
}

export default function Home() {
  const [messages, setMessages] = useState<{ text: string; isBot: boolean }[]>([
    { text: 'Hi! do you need any help?', isBot: true }
  ]);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [uploading, setUploading] = useState(false);
  const { user } = useAuth();

  const onDrop = useCallback(async (acceptedFiles: File[]) => {
    const file = acceptedFiles[0];
    if (!file) return;

    setUploading(true);
    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await fetch('/api/scan', {
        method: 'POST',
        body: formData,
      });

      if (!response.ok) {
        throw new Error('Upload failed');
      }

      const result = await response.json();
      setScanResult(result);
      
      // Add chat message about the scan
      setMessages(prev => [...prev, {
        text: `I've analyzed "${file.name}" and found ${result.summary.totalFindings} potential issues. The document's MirrorScore is ${result.summary.mirrorScore}. Would you like me to explain the findings?`,
        isBot: true
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
    multiple: false
  });

  const sendMessage = async (message: string) => {
    setMessages(prev => [...prev, { text: message, isBot: false }]);
    
    try {
      const response = await fetch('/api/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message }),
      });

      if (!response.ok) {
        throw new Error('Chat request failed');
      }

      const data = await response.json();
      setMessages(prev => [...prev, { text: data.response, isBot: true }]);
    } catch (error) {
      console.error('Chat error:', error);
    }
  };

  return (
    <main className="min-h-screen p-4">
      <div className="gradient-bg" />
      
      {/* Navigation */}
      <nav className="flex justify-between items-center mb-8">
        <Link href="/" className="flex items-center gap-2">
          <Image src="/logo.svg" alt="Mirror Logo" width={40} height={40} />
          <span className="font-bold text-xl">Reveal the Real</span>
        </Link>
        <div className="flex gap-4">
          <Link href="/history" className="text-white/80 hover:text-white">HISTORY</Link>
          <Link href="/mirrorscore" className="text-white/80 hover:text-white">MIRRORSCORE</Link>
          {user ? (
            <button onClick={() => {}} className="btn-secondary">LOGOUT</button>
          ) : (
            <div className="flex gap-2">
              <Link href="/login" className="btn-secondary">LOGIN</Link>
              <Link href="/signup" className="btn-primary">SIGN UP</Link>
            </div>
          )}
        </div>
      </nav>

      {/* Upload Section */}
      <div className="max-w-2xl mx-auto text-center mb-12">
        <div {...getRootProps()} className="card cursor-pointer hover:border-[#9747FF]/40 transition-all">
          <input {...getInputProps()} />
          <Image src="/upload-icon.svg" alt="Upload" width={64} height={64} className="mx-auto mb-4" />
          {uploading ? (
            <div className="flex flex-col items-center">
              <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-[#9747FF] mb-2"></div>
              <p>Analyzing document...</p>
            </div>
          ) : isDragActive ? (
            <p>Drop the file here...</p>
          ) : (
            <p>Choose a file or drag & drop it here</p>
          )}
          <button className="btn-primary mt-4" disabled={uploading}>
            {uploading ? 'Uploading...' : 'Upload'}
          </button>
        </div>
      </div>

      {/* Scan Results Modal */}
      {scanResult && (
        <ScanResults
          findings={scanResult.scan.findings}
          summary={scanResult.summary}
          onClose={() => setScanResult(null)}
        />
      )}

      {/* Chatbot */}
      <div className="fixed bottom-4 right-4 w-80">
        <div className="card">
          <div className="flex items-center gap-2 mb-4">
            <Image src="/bot-avatar.svg" alt="MiAI" width={32} height={32} className="rounded-full" />
            <h3 className="font-bold">I'm MiAI!</h3>
          </div>
          <div className="h-64 overflow-y-auto mb-4 space-y-2">
            {messages.map((msg, i) => (
              <div key={i} className={`p-2 rounded-lg ${msg.isBot ? 'bg-[#9747FF]/20 mr-8' : 'bg-white/10 ml-8'}`}>
                {msg.text}
              </div>
            ))}
          </div>
          <form onSubmit={(e) => {
            e.preventDefault();
            const input = e.currentTarget.elements.namedItem('message') as HTMLInputElement;
            if (input.value.trim()) {
              sendMessage(input.value);
              input.value = '';
            }
          }} className="flex gap-2">
            <input
              type="text"
              name="message"
              placeholder="Type your message..."
              className="flex-1 bg-white/10 rounded-lg px-3 py-2 focus:outline-none focus:ring-2 focus:ring-[#9747FF]"
            />
            <button type="submit" className="btn-primary">Send</button>
          </form>
        </div>
      </div>
    </main>
  );
} 