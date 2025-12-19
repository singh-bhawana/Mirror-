'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { Doughnut, Bar } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend,
  ArcElement,
} from 'chart.js';

ChartJS.register(
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend,
  ArcElement
);

interface Finding {
  id: number | string;
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
        setScans(data.scans || []);
        // Auto-select first scan if available
        if (data.scans && data.scans.length > 0 && !selectedScan) {
          setSelectedScan(data.scans[0]);
        }
      } catch (error) {
        console.error('Error fetching scans:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchScans();
    // Refresh every 3 seconds to get new scans
    const interval = setInterval(fetchScans, 3000);
    return () => clearInterval(interval);
  }, []);

  const getSelectedScanCharts = () => {
    if (!selectedScan) return null;

    const categoryData = selectedScan.findings.reduce((acc, finding) => {
      const category = finding.category.toLowerCase();
      acc[category] = (acc[category] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    const severityData = selectedScan.findings.reduce((acc, finding) => {
      const severity = finding.severity.toLowerCase();
      acc[severity] = (acc[severity] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    return {
      category: {
        labels: Object.keys(categoryData).map(k => k.charAt(0).toUpperCase() + k.slice(1)),
        datasets: [{
          data: Object.values(categoryData),
          backgroundColor: ['#9747FF', '#FF4785', '#47B4FF', '#4ECDC4'],
          borderWidth: 2,
        }]
      },
      severity: {
        labels: ['High', 'Medium', 'Low'],
        datasets: [{
          label: 'Findings',
          data: [
            severityData.high || 0,
            severityData.medium || 0,
            severityData.low || 0,
          ],
          backgroundColor: ['#FF6B6B', '#FFD93D', '#6BCB77'],
          borderColor: ['#FF5555', '#FFD42D', '#5BBB67'],
          borderWidth: 2,
        }]
      }
    };
  };

  if (loading) {
    return (
      <main className="min-h-screen relative flex items-center justify-center">
        <div className="gradient-bg fixed inset-0 pointer-events-none" />
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-[#9747FF]"></div>
      </main>
    );
  }

  const charts = getSelectedScanCharts();

  return (
    <main className="min-h-screen relative p-8">
      <div className="gradient-bg fixed inset-0 pointer-events-none" />
      
      <div className="relative z-10">
        <div className="flex justify-between items-center mb-8">
          <h1 className="text-3xl font-bold text-white">Scan History</h1>
          <Link href="/" className="btn-primary px-6 py-2">
            New Scan
          </Link>
        </div>

        {scans.length === 0 ? (
          <div className="card bg-black/40 backdrop-blur-sm text-center py-16">
            <p className="text-xl text-white/80 mb-2">No scan history yet</p>
            <p className="text-white/60 mb-6">Upload a file to start scanning</p>
            <Link href="/" className="btn-primary inline-block">
              Upload File
            </Link>
          </div>
        ) : (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
            {/* Scan List */}
            <div className="lg:col-span-1 space-y-4">
              <h2 className="text-xl font-semibold text-white mb-4">All Scans ({scans.length})</h2>
              <div className="space-y-3 max-h-[80vh] overflow-y-auto custom-scrollbar">
                {scans.map(scan => (
                  <div
                    key={scan.id}
                    className={`card bg-black/40 backdrop-blur-sm cursor-pointer transition-all border-2 ${
                      selectedScan?.id === scan.id 
                        ? 'border-purple-500 bg-purple-500/10' 
                        : 'border-white/10 hover:border-purple-500/40'
                    }`}
                    onClick={() => setSelectedScan(scan)}
                  >
                    <div className="flex items-start justify-between mb-2">
                      <h3 className="font-semibold text-white text-sm flex-1 mr-2 truncate">{scan.fileName}</h3>
                      <span className={`px-2 py-1 rounded-full text-xs font-semibold whitespace-nowrap ${
                        scan.mirrorScore >= 8 ? 'bg-green-500/20 text-green-400 border border-green-500/40' :
                        scan.mirrorScore >= 5 ? 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/40' :
                        'bg-red-500/20 text-red-400 border border-red-500/40'
                      }`}>
                        {scan.mirrorScore}/10
                      </span>
                    </div>
                    <div className="flex justify-between items-center text-xs text-white/60">
                      <span>{new Date(scan.uploadedAt).toLocaleDateString()}</span>
                      <span>{scan.findings.length} findings</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Scan Details */}
            <div className="lg:col-span-2 space-y-6">
              {selectedScan ? (
                <>
                  {/* Scan Header */}
                  <div className="card bg-black/40 backdrop-blur-sm">
                    <div className="flex justify-between items-start mb-6">
                      <div className="flex-1">
                        <h2 className="text-2xl font-bold mb-2 text-white">{selectedScan.fileName}</h2>
                        <p className="text-white/60">
                          Scanned on {new Date(selectedScan.uploadedAt).toLocaleString()}
                        </p>
                      </div>
                      <div className="text-right">
                        <div className={`text-4xl font-bold mb-2 ${
                          selectedScan.mirrorScore >= 8 ? 'text-green-400' :
                          selectedScan.mirrorScore >= 5 ? 'text-yellow-400' :
                          'text-red-400'
                        }`}>
                          {selectedScan.mirrorScore}
                        </div>
                        <span className={`px-4 py-2 rounded-lg text-sm font-semibold ${
                          selectedScan.mirrorScore >= 8 ? 'bg-green-500/20 text-green-400 border border-green-500/40' :
                          selectedScan.mirrorScore >= 5 ? 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/40' :
                          'bg-red-500/20 text-red-400 border border-red-500/40'
                        }`}>
                          {selectedScan.mirrorScore >= 8 ? 'Low Risk' :
                           selectedScan.mirrorScore >= 5 ? 'Medium Risk' :
                           'High Risk'}
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Charts */}
                  {charts && (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                      <div className="card bg-black/40 backdrop-blur-sm">
                        <h3 className="text-lg font-semibold mb-4 text-white">Findings by Category</h3>
                        <div className="h-64">
                          <Doughnut 
                            data={charts.category} 
                            options={{
                              responsive: true,
                              maintainAspectRatio: false,
                              plugins: {
                                legend: {
                                  position: 'bottom',
                                  labels: { color: 'rgba(255, 255, 255, 0.8)', padding: 15 }
                                },
                                tooltip: {
                                  backgroundColor: 'rgba(0, 0, 0, 0.8)',
                                  titleColor: '#fff',
                                  bodyColor: '#fff',
                                }
                              },
                            }} 
                          />
                        </div>
                      </div>
                      <div className="card bg-black/40 backdrop-blur-sm">
                        <h3 className="text-lg font-semibold mb-4 text-white">Severity Distribution</h3>
                        <div className="h-64">
                          <Bar 
                            data={charts.severity} 
                            options={{
                              responsive: true,
                              maintainAspectRatio: false,
                              plugins: {
                                legend: {
                                  display: false
                                },
                                tooltip: {
                                  backgroundColor: 'rgba(0, 0, 0, 0.8)',
                                  titleColor: '#fff',
                                  bodyColor: '#fff',
                                }
                              },
                              scales: {
                                y: {
                                  beginAtZero: true,
                                  ticks: { color: 'rgba(255, 255, 255, 0.6)' },
                                  grid: { color: 'rgba(255, 255, 255, 0.1)' }
                                },
                                x: {
                                  ticks: { color: 'rgba(255, 255, 255, 0.6)' },
                                  grid: { display: false }
                                },
                              },
                            }} 
                          />
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Findings List */}
                  <div className="card bg-black/40 backdrop-blur-sm">
                    <h3 className="text-xl font-semibold mb-4 text-white">
                      Detailed Findings ({selectedScan.findings.length})
                    </h3>
                    <div className="space-y-3 max-h-[600px] overflow-y-auto custom-scrollbar">
                      {selectedScan.findings.map(finding => (
                        <div key={finding.id} className="bg-black/60 border border-white/10 rounded-lg p-4 hover:border-purple-500/40 transition-colors">
                          <div className="flex items-start justify-between gap-4">
                            <div className="flex items-start gap-3 flex-1">
                              <div className="mt-1">
                                {finding.category.toLowerCase() === 'security' ? (
                                  <svg className="w-5 h-5 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                                  </svg>
                                ) : finding.category.toLowerCase() === 'privacy' ? (
                                  <svg className="w-5 h-5 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                                  </svg>
                                ) : (
                                  <span className="text-xl">🎣</span>
                                )}
                              </div>
                              <div className="flex-1">
                                <div className="flex items-center gap-2 mb-1">
                                  <span className="font-semibold text-white">{finding.category}</span>
                                </div>
                                <p className="text-white/90 mb-2">{finding.description}</p>
                                {finding.location && (
                                  <p className="text-sm text-white/60 bg-white/5 p-2 rounded break-all">
                                    Location: {finding.location}
                                  </p>
                                )}
                              </div>
                            </div>
                            <span className={`px-3 py-1 rounded-full text-sm font-medium whitespace-nowrap ${
                              finding.severity === 'High' ? 'bg-red-500/20 text-red-400 border border-red-500/40' :
                              finding.severity === 'Medium' ? 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/40' :
                              'bg-blue-500/20 text-blue-400 border border-blue-500/40'
                            }`}>
                              {finding.severity}
                            </span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </>
              ) : (
                <div className="card bg-black/40 backdrop-blur-sm flex items-center justify-center text-white/60 h-96">
                  <div className="text-center">
                    <p className="text-lg mb-2">No scan selected</p>
                    <p className="text-sm">Select a scan from the list to view details</p>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </main>
  );
} 