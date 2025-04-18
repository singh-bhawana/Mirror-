'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';

interface Finding {
  id: string;
  category: string;
  severity: string;
  description: string;
  location: string;
}

interface Scan {
  id: string;
  fileName: string;
  fileType: string;
  uploadedAt: string;
  mirrorScore: number;
  findings: Finding[];
}

export default function History() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedScan, setSelectedScan] = useState<Scan | null>(null);

  useEffect(() => {
    const fetchScans = async () => {
      try {
        const response = await fetch('/api/scans');
        const data = await response.json();
        setScans(data.scans);
      } catch (error) {
        console.error('Error fetching scans:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchScans();
  }, []);

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-[#9747FF]"></div>
      </div>
    );
  }

  return (
    <main className="min-h-screen p-8">
      <div className="gradient-bg" />
      
      <div className="flex justify-between items-center mb-8">
        <h1 className="text-3xl font-bold">Scan History</h1>
        <Link href="/" className="btn-primary">
          New Scan
        </Link>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Scan List */}
        <div className="lg:col-span-1 space-y-4">
          {scans.map(scan => (
            <div
              key={scan.id}
              className={`card cursor-pointer transition-all ${
                selectedScan?.id === scan.id ? 'border-[#9747FF]' : ''
              }`}
              onClick={() => setSelectedScan(scan)}
            >
              <h3 className="font-semibold mb-2">{scan.fileName}</h3>
              <div className="flex justify-between items-center text-sm text-white/60">
                <span>{new Date(scan.uploadedAt).toLocaleDateString()}</span>
                <span className={`px-2 py-1 rounded ${
                  scan.mirrorScore >= 80 ? 'bg-green-500/20 text-green-400' :
                  scan.mirrorScore >= 60 ? 'bg-yellow-500/20 text-yellow-400' :
                  'bg-red-500/20 text-red-400'
                }`}>
                  Score: {scan.mirrorScore}
                </span>
              </div>
            </div>
          ))}
        </div>

        {/* Scan Details */}
        <div className="lg:col-span-2">
          {selectedScan ? (
            <div className="card">
              <div className="flex justify-between items-start mb-6">
                <div>
                  <h2 className="text-2xl font-bold mb-2">{selectedScan.fileName}</h2>
                  <p className="text-white/60">
                    Scanned on {new Date(selectedScan.uploadedAt).toLocaleString()}
                  </p>
                </div>
                <span className={`px-3 py-1 rounded-full text-lg ${
                  selectedScan.mirrorScore >= 80 ? 'bg-green-500/20 text-green-400' :
                  selectedScan.mirrorScore >= 60 ? 'bg-yellow-500/20 text-yellow-400' :
                  'bg-red-500/20 text-red-400'
                }`}>
                  Score: {selectedScan.mirrorScore}
                </span>
              </div>

              <div className="space-y-6">
                <div>
                  <h3 className="text-xl font-semibold mb-4">Findings</h3>
                  <div className="space-y-4">
                    {selectedScan.findings.map(finding => (
                      <div key={finding.id} className="p-4 rounded-lg bg-white/5">
                        <div className="flex justify-between items-start mb-2">
                          <span className="font-semibold">{finding.category}</span>
                          <span className={`px-2 py-1 rounded text-sm ${
                            finding.severity === 'High' ? 'bg-red-500/20 text-red-400' :
                            finding.severity === 'Medium' ? 'bg-yellow-500/20 text-yellow-400' :
                            'bg-blue-500/20 text-blue-400'
                          }`}>
                            {finding.severity}
                          </span>
                        </div>
                        <p className="text-white/80 mb-2">{finding.description}</p>
                        {finding.location && (
                          <p className="text-sm text-white/60">
                            Location: {finding.location}
                          </p>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          ) : (
            <div className="card flex items-center justify-center text-white/60 h-full">
              Select a scan to view details
            </div>
          )}
        </div>
      </div>
    </main>
  );
} 