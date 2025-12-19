'use client';

import { useEffect, useRef } from 'react';
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
  id: string;
  category: string;
  severity: 'High' | 'Medium' | 'Low';
  description: string;
  location: string;
}

interface ScanSummary {
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
}

interface ScanResultsProps {
  findings: Finding[];
  summary: ScanSummary;
  onClose?: () => void;
}

export default function ScanResults({ findings, summary, onClose }: ScanResultsProps) {
  const categoryData = {
    labels: ['Phishing', 'Privacy', 'Security'],
    datasets: [
      {
        data: [
          summary.findingsByCategory.phishing,
          summary.findingsByCategory.privacy,
          summary.findingsByCategory.security,
        ],
        backgroundColor: ['#FF6B6B', '#4ECDC4', '#45B7D1'],
        borderColor: ['#FF5555', '#3DBDB4', '#35A7C1'],
        borderWidth: 2,
      },
    ],
  };

  const severityData = {
    labels: ['High', 'Medium', 'Low'],
    datasets: [
      {
        label: 'Findings by Severity',
        data: [
          summary.severityBreakdown.high,
          summary.severityBreakdown.medium,
          summary.severityBreakdown.low,
        ],
        backgroundColor: '#FF6B6B',
        borderColor: '#FF5555',
        borderWidth: 1,
      },
    ],
  };

  const chartOptions = {
    responsive: true,
    plugins: {
      legend: {
        position: 'bottom' as const,
        labels: {
          color: 'rgba(255, 255, 255, 0.8)',
          padding: 20,
          font: {
            size: 12
          }
        }
      },
      tooltip: {
        backgroundColor: 'rgba(0, 0, 0, 0.8)',
        titleColor: 'rgba(255, 255, 255, 1)',
        bodyColor: 'rgba(255, 255, 255, 0.8)',
        padding: 12,
        cornerRadius: 4,
      }
    },
  };

  const barOptions = {
    ...chartOptions,
    scales: {
      y: {
        beginAtZero: true,
        ticks: {
          color: 'rgba(255, 255, 255, 0.8)',
          font: {
            size: 12
          }
        },
        grid: {
          color: 'rgba(255, 255, 255, 0.1)',
        },
      },
      x: {
        ticks: {
          color: 'rgba(255, 255, 255, 0.8)',
          font: {
            size: 12
          }
        },
        grid: {
          display: false,
        },
      },
    },
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'high':
        return 'bg-red-500/20 text-red-400 border-red-500/40';
      case 'medium':
        return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/40';
      case 'low':
        return 'bg-blue-500/20 text-blue-400 border-blue-500/40';
      default:
        return 'bg-gray-500/20 text-gray-400 border-gray-500/40';
    }
  };

  const getCategoryIcon = (category: string) => {
    switch (category.toLowerCase()) {
      case 'phishing':
        return <span className="text-xl">🎣</span>;
      case 'privacy':
        return <span className="text-xl">🔒</span>;
      case 'security':
        return (
          <svg className="w-5 h-5 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
          </svg>
        );
      default:
        return <span className="text-xl">⚠️</span>;
    }
  };

  return (
    <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center p-4 z-50">
      <div className="bg-black/90 rounded-xl border border-[#9747FF]/20 p-6 max-w-4xl w-full max-h-[90vh] overflow-y-auto">
        <div className="flex justify-between items-start mb-6">
          <div>
            <h2 className="text-2xl font-bold mb-2">Scan Results</h2>
            <p className="text-white/60">
              {summary.totalFindings} {summary.totalFindings === 1 ? 'finding' : 'findings'} detected
            </p>
          </div>
          {onClose && (
            <button
              onClick={onClose}
              className="text-white/60 hover:text-white transition-colors"
            >
              ✕
            </button>
          )}
        </div>

        {/* Mirror Score */}
        <div className="mb-8 bg-white/5 rounded-lg p-6">
          <div className="flex items-center gap-6">
            <div className={`text-7xl font-bold ${
              summary.mirrorScore >= 8 ? 'text-green-400' :
              summary.mirrorScore >= 5 ? 'text-yellow-400' :
              'text-red-500'
            }`}>
              {summary.mirrorScore}
            </div>
            <div>
              <div className="text-xl font-semibold mb-2 text-white">Mirror Score</div>
              <div className={`text-sm font-semibold px-4 py-2 rounded-lg inline-block ${
                summary.mirrorScore >= 8 ? 'bg-green-500/20 text-green-400 border border-green-500/40' :
                summary.mirrorScore >= 5 ? 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/40' :
                'bg-red-500/20 text-red-400 border border-red-500/40'
              }`}>
                {summary.mirrorScore >= 8 ? 'Low Risk' :
                 summary.mirrorScore >= 5 ? 'Medium Risk' :
                 'High Risk'}
              </div>
            </div>
          </div>
        </div>

        {/* Charts */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-8 mb-8">
          <div className="bg-white/5 rounded-lg p-6">
            <h3 className="text-lg font-semibold mb-4">Findings by Category</h3>
            <div className="h-64">
              <Doughnut
                data={categoryData}
                options={chartOptions}
              />
            </div>
          </div>

          <div className="bg-white/5 rounded-lg p-6">
            <h3 className="text-lg font-semibold mb-4">Severity Distribution</h3>
            <div className="h-64">
              <Bar
                data={severityData}
                options={barOptions}
              />
            </div>
          </div>
        </div>

        {/* Findings List */}
        <div className="bg-white/5 rounded-lg p-6">
          <h3 className="text-lg font-semibold mb-4">Detailed Findings</h3>
          <div className="space-y-4">
            {findings.map((finding) => (
              <div
                key={finding.id}
                className="bg-black/40 rounded-lg p-4 border border-white/10 hover:border-[#9747FF]/40 transition-colors"
              >
                <div className="flex justify-between items-start mb-3">
                  <div className="flex items-center gap-2">
                    <span className="text-purple-400">
                      {getCategoryIcon(finding.category)}
                    </span>
                    <span className="font-semibold">{finding.category}</span>
                  </div>
                  <span className={`px-3 py-1 rounded-full text-sm border ${getSeverityColor(finding.severity)}`}>
                    {finding.severity}
                  </span>
                </div>
                <p className="text-white/80 mb-2">{finding.description}</p>
                {finding.location && finding.location !== 'Document content' && (
                  <p className="text-sm text-white/60 bg-white/5 p-2 rounded">
                    Location: {finding.location}
                  </p>
                )}
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
} 