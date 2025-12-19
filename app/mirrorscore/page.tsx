'use client';

import { useEffect, useState } from 'react';
import { Line, Doughnut, Bar } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  Title,
  Tooltip,
  Legend,
  ArcElement,
} from 'chart.js';

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  Title,
  Tooltip,
  Legend,
  ArcElement
);

interface ScanData {
  id: string;
  fileName: string;
  mirrorScore: number;
  uploadedAt: string;
  findings: {
    category: string;
    severity: string;
  }[];
}

interface Statistics {
  totalScans: number;
  avgScore: number;
  findingsByCategory: Record<string, number>;
  severityBreakdown: Record<string, number>;
}

export default function MirrorScore() {
  const [scans, setScans] = useState<ScanData[]>([]);
  const [statistics, setStatistics] = useState<Statistics | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchScans = async () => {
      try {
        const response = await fetch('/api/scans');
        const data = await response.json();
        setScans(data.scans || []);
        setStatistics(data.statistics || null);
      } catch (error) {
        console.error('Error fetching scans:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchScans();
    // Refresh every 5 seconds to get new scans
    const interval = setInterval(fetchScans, 5000);
    return () => clearInterval(interval);
  }, []);

  const lineChartData = {
    labels: scans.length > 0 
      ? scans.map(scan => new Date(scan.uploadedAt).toLocaleDateString())
      : ['No data'],
    datasets: [
      {
        label: 'Mirror Score',
        data: scans.length > 0 
          ? scans.map(scan => scan.mirrorScore)
          : [0],
        borderColor: '#9747FF',
        backgroundColor: 'rgba(151, 71, 255, 0.1)',
        tension: 0.4,
        fill: true,
      },
    ],
  };

  const findingsByCategory = statistics?.findingsByCategory || scans.reduce((acc, scan) => {
    scan.findings.forEach(finding => {
      const category = finding.category.toLowerCase();
      acc[category] = (acc[category] || 0) + 1;
    });
    return acc;
  }, {} as Record<string, number>);

  const doughnutData = {
    labels: Object.keys(findingsByCategory).length > 0 
      ? Object.keys(findingsByCategory).map(k => k.charAt(0).toUpperCase() + k.slice(1))
      : ['No data'],
    datasets: [
      {
        data: Object.values(findingsByCategory).length > 0
          ? Object.values(findingsByCategory)
          : [1],
        backgroundColor: [
          '#9747FF',
          '#FF4785',
          '#47B4FF',
          '#FFB347',
          '#4ECDC4',
        ],
        borderWidth: 2,
        borderColor: '#000',
      },
    ],
  };

  const severityData = {
    labels: ['High', 'Medium', 'Low'],
    datasets: [
      {
        label: 'Findings by Severity',
        data: [
          statistics?.severityBreakdown?.high || 0,
          statistics?.severityBreakdown?.medium || 0,
          statistics?.severityBreakdown?.low || 0,
        ],
        backgroundColor: ['#FF6B6B', '#FFD93D', '#6BCB77'],
        borderColor: ['#FF5555', '#FFD42D', '#5BBB67'],
        borderWidth: 2,
      },
    ],
  };

  if (loading) {
    return (
      <main className="min-h-screen relative flex items-center justify-center">
        <div className="gradient-bg fixed inset-0 pointer-events-none" />
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-[#9747FF]"></div>
      </main>
    );
  }

  return (
    <main className="min-h-screen relative p-8">
      <div className="gradient-bg fixed inset-0 pointer-events-none" />
      
      <div className="relative z-10">
        <h1 className="text-3xl font-bold mb-8 text-white">MirrorScore Dashboard</h1>

        {/* Statistics Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
          <div className="card bg-black/40 backdrop-blur-sm">
            <div className="text-white/60 text-sm mb-1">Total Scans</div>
            <div className="text-3xl font-bold text-white">{statistics?.totalScans || scans.length}</div>
          </div>
          <div className="card bg-black/40 backdrop-blur-sm">
            <div className="text-white/60 text-sm mb-1">Average Score</div>
            <div className={`text-3xl font-bold ${
              (statistics?.avgScore || 0) >= 8 ? 'text-green-400' :
              (statistics?.avgScore || 0) >= 5 ? 'text-yellow-400' :
              'text-red-400'
            }`}>
              {statistics?.avgScore.toFixed(1) || '0.0'}
            </div>
          </div>
          <div className="card bg-black/40 backdrop-blur-sm">
            <div className="text-white/60 text-sm mb-1">Total Findings</div>
            <div className="text-3xl font-bold text-white">
              {scans.reduce((sum, scan) => sum + scan.findings.length, 0)}
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-8 mb-8">
          {/* Score Trend */}
          <div className="card bg-black/40 backdrop-blur-sm">
            <h2 className="text-xl font-semibold mb-4 text-white">Score Trend Over Time</h2>
            <div className="h-64">
              <Line 
                data={lineChartData} 
                options={{
                  responsive: true,
                  maintainAspectRatio: false,
                  plugins: {
                    legend: {
                      labels: { color: 'rgba(255, 255, 255, 0.8)' }
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
                      max: 10,
                      ticks: { color: 'rgba(255, 255, 255, 0.6)' },
                      grid: { color: 'rgba(255, 255, 255, 0.1)' }
                    },
                    x: {
                      ticks: { color: 'rgba(255, 255, 255, 0.6)' },
                      grid: { color: 'rgba(255, 255, 255, 0.1)' }
                    },
                  },
                }} 
              />
            </div>
          </div>

          {/* Finding Categories */}
          <div className="card bg-black/40 backdrop-blur-sm">
            <h2 className="text-xl font-semibold mb-4 text-white">Findings by Category</h2>
            <div className="h-64">
              <Doughnut 
                data={doughnutData} 
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

          {/* Severity Distribution */}
          <div className="card bg-black/40 backdrop-blur-sm md:col-span-2">
            <h2 className="text-xl font-semibold mb-4 text-white">Severity Distribution</h2>
            <div className="h-64">
              <Bar 
                data={severityData} 
                options={{
                  responsive: true,
                  maintainAspectRatio: false,
                  plugins: {
                    legend: {
                      labels: { color: 'rgba(255, 255, 255, 0.8)' }
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

        {/* Recent Scans Table */}
        <div className="card bg-black/40 backdrop-blur-sm">
          <h2 className="text-xl font-semibold mb-4 text-white">Recent Scans</h2>
          {scans.length === 0 ? (
            <div className="text-center py-12 text-white/60">
              <p className="text-lg mb-2">No scans yet</p>
              <p className="text-sm">Upload a file to see your scan history</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-white/10">
                    <th className="text-left py-3 px-4 text-white/80 font-semibold">File Name</th>
                    <th className="text-left py-3 px-4 text-white/80 font-semibold">Score</th>
                    <th className="text-left py-3 px-4 text-white/80 font-semibold">Date</th>
                    <th className="text-left py-3 px-4 text-white/80 font-semibold">Findings</th>
                    <th className="text-left py-3 px-4 text-white/80 font-semibold">Risk Level</th>
                  </tr>
                </thead>
                <tbody>
                  {scans.map(scan => (
                    <tr key={scan.id} className="border-b border-white/5 hover:bg-white/5 transition-colors">
                      <td className="py-3 px-4 text-white">{scan.fileName}</td>
                      <td className="py-3 px-4">
                        <span className={`px-3 py-1 rounded-full text-sm font-semibold ${
                          scan.mirrorScore >= 8 ? 'bg-green-500/20 text-green-400 border border-green-500/40' :
                          scan.mirrorScore >= 5 ? 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/40' :
                          'bg-red-500/20 text-red-400 border border-red-500/40'
                        }`}>
                          {scan.mirrorScore}/10
                        </span>
                      </td>
                      <td className="py-3 px-4 text-white/80">{new Date(scan.uploadedAt).toLocaleString()}</td>
                      <td className="py-3 px-4 text-white/80">{scan.findings.length}</td>
                      <td className="py-3 px-4">
                        <span className={`px-3 py-1 rounded-full text-xs font-medium ${
                          scan.mirrorScore >= 8 ? 'bg-green-500/20 text-green-400' :
                          scan.mirrorScore >= 5 ? 'bg-yellow-500/20 text-yellow-400' :
                          'bg-red-500/20 text-red-400'
                        }`}>
                          {scan.mirrorScore >= 8 ? 'Low Risk' :
                           scan.mirrorScore >= 5 ? 'Medium Risk' :
                           'High Risk'}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </main>
  );
} 