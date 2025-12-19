// In-memory storage for scans (for demo purposes)
// In production, this would use a database

interface Scan {
  id: string;
  fileName: string;
  fileType: string;
  uploadedAt: string;
  mirrorScore: number;
  findings: {
    id: number;
    category: string;
    severity: string;
    description: string;
    location: string;
  }[];
}

class ScanStorage {
  private scans: Scan[] = [];

  // Add a new scan
  addScan(scan: Omit<Scan, 'id' | 'uploadedAt'>): Scan {
    const newScan: Scan = {
      ...scan,
      id: Date.now().toString() + Math.random().toString(36).substr(2, 9),
      uploadedAt: new Date().toISOString(),
    };
    this.scans.unshift(newScan); // Add to beginning
    return newScan;
  }

  // Get all scans
  getAllScans(): Scan[] {
    return [...this.scans];
  }

  // Get a scan by ID
  getScanById(id: string): Scan | undefined {
    return this.scans.find(scan => scan.id === id);
  }

  // Delete a scan
  deleteScan(id: string): boolean {
    const index = this.scans.findIndex(scan => scan.id === id);
    if (index !== -1) {
      this.scans.splice(index, 1);
      return true;
    }
    return false;
  }

  // Get statistics
  getStatistics() {
    const totalScans = this.scans.length;
    const avgScore = totalScans > 0
      ? this.scans.reduce((sum, scan) => sum + scan.mirrorScore, 0) / totalScans
      : 0;
    
    const findingsByCategory = this.scans.reduce((acc, scan) => {
      scan.findings.forEach(finding => {
        const category = finding.category.toLowerCase();
        acc[category] = (acc[category] || 0) + 1;
      });
      return acc;
    }, {} as Record<string, number>);

    const severityBreakdown = this.scans.reduce((acc, scan) => {
      scan.findings.forEach(finding => {
        const severity = finding.severity.toLowerCase();
        acc[severity] = (acc[severity] || 0) + 1;
      });
      return acc;
    }, {} as Record<string, number>);

    return {
      totalScans,
      avgScore: Math.round(avgScore * 10) / 10,
      findingsByCategory,
      severityBreakdown,
    };
  }
}

// Export singleton instance
export const scanStorage = new ScanStorage();

