'use client';

import { useEffect, useState } from 'react';
import { Line, Doughnut } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
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

export default function MirrorScore() {
  const [scans, setScans] = useState<ScanData[]>([]);
  const [loading, setLoading] = useState(true);

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

  const lineChartData = {
    labels: scans.map(scan => new Date(scan.uploadedAt).toLocaleDateString()),
    datasets: [
      {
        label: 'Mirror Score',
        data: scans.map(scan => scan.mirrorScore),
        borderColor: '#9747FF',
        backgroundColor: 'rgba(151, 71, 255, 0.1)',
        tension: 0.4,
      },
    ],
  };

  const findingsByCategory = scans.reduce((acc, scan) => {
    scan.findings.forEach(finding => {
      acc[finding.category] = (acc[finding.category] || 0) + 1;
    });
    return acc;
  }, {} as Record<string, number>);

  const doughnutData = {
    labels: Object.keys(findingsByCategory),
    datasets: [
      {
        data: Object.values(findingsByCategory),
        backgroundColor: [
          '#9747FF',
          '#FF4785',
          '#47B4FF',
          '#FFB347',
        ],
      },
    ],
  };

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
      
      <h1 className="text-3xl font-bold mb-8">MirrorScore Dashboard</h1>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
        {/* Score Trend */}
        <div className="card">
          <h2 className="text-xl font-semibold mb-4">Score Trend</h2>
          <Line data={lineChartData} options={{
            responsive: true,
            scales: {
              y: {
                beginAtZero: true,
                max: 100,
              },
            },
          }} />
        </div>

        {/* Finding Categories */}
        <div className="card">
          <h2 className="text-xl font-semibold mb-4">Finding Categories</h2>
          <Doughnut data={doughnutData} options={{
            responsive: true,
            plugins: {
              legend: {
                position: 'bottom',
              },
            },
          }} />
        </div>

        {/* Recent Scans */}
        <div className="card col-span-full">
          <h2 className="text-xl font-semibold mb-4">Recent Scans</h2>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-[#9747FF]/20">
                  <th className="text-left py-2">File Name</th>
                  <th className="text-left py-2">Score</th>
                  <th className="text-left py-2">Date</th>
                  <th className="text-left py-2">Findings</th>
                </tr>
              </thead>
              <tbody>
                {scans.map(scan => (
                  <tr key={scan.id} className="border-b border-[#9747FF]/10">
                    <td className="py-2">{scan.fileName}</td>
                    <td className="py-2">
                      <span className={`px-2 py-1 rounded ${
                        scan.mirrorScore >= 80 ? 'bg-green-500/20 text-green-400' :
                        scan.mirrorScore >= 60 ? 'bg-yellow-500/20 text-yellow-400' :
                        'bg-red-500/20 text-red-400'
                      }`}>
                        {scan.mirrorScore}
                      </span>
                    </td>
                    <td className="py-2">{new Date(scan.uploadedAt).toLocaleDateString()}</td>
                    <td className="py-2">{scan.findings.length}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </main>
  );
} 