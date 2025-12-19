import { NextResponse } from 'next/server';
import { scanStorage } from '@/lib/scanStorage';
import { analyzeDocument } from '@/lib/documentAnalyzer';

export async function POST(request: Request) {
  try {
    // Get the form data
    const formData = await request.formData();
    const file = formData.get('file') as File;

    if (!file) {
      return NextResponse.json({ error: 'No file provided' }, { status: 400 });
    }

    // Validate file type
    const allowedTypes = [
      'application/pdf', 
      'application/msword', 
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 
      'text/plain'
    ];
    const allowedExtensions = ['.pdf', '.doc', '.docx', '.txt'];
    const fileName = file.name.toLowerCase();
    const hasValidExtension = allowedExtensions.some(ext => fileName.endsWith(ext));
    
    if (!allowedTypes.includes(file.type) && !hasValidExtension) {
      return NextResponse.json({ 
        error: 'Invalid file type. Please upload PDF, DOC, DOCX, or TXT files.' 
      }, { status: 400 });
    }

    // Validate file size (max 10MB)
    const maxSize = 10 * 1024 * 1024; // 10MB
    if (file.size > maxSize) {
      return NextResponse.json({ 
        error: 'File size exceeds 10MB limit. Please upload a smaller file.' 
      }, { status: 400 });
    }

    // Perform actual document analysis
    console.log(`Analyzing document: ${file.name} (${(file.size / 1024).toFixed(2)} KB)`);
    
    const analysisResult = await analyzeDocument(file);
    
    // Log analysis details for debugging
    console.log(`Analysis complete for ${file.name}:`);
    console.log(`- Text extracted: ${analysisResult.textContent.length} characters`);
    console.log(`- Findings: ${analysisResult.findings.length}`);
    console.log(`- High: ${analysisResult.findings.filter(f => f.severity === 'High').length}`);
    console.log(`- Medium: ${analysisResult.findings.filter(f => f.severity === 'Medium').length}`);
    console.log(`- Low: ${analysisResult.findings.filter(f => f.severity === 'Low').length}`);
    console.log(`- MirrorScore: ${analysisResult.mirrorScore}/10`);
    console.log(`- Metadata:`, analysisResult.metadata);

    // Save scan to storage
    const savedScan = scanStorage.addScan({
      fileName: file.name,
      fileType: file.type || 'application/pdf',
      mirrorScore: analysisResult.mirrorScore,
      findings: analysisResult.findings
    });

    return NextResponse.json({
      mirrorScore: analysisResult.mirrorScore,
      findings: analysisResult.findings,
      scanId: savedScan.id,
      metadata: analysisResult.metadata
    });
  } catch (error) {
    console.error('Upload error:', error);
    return NextResponse.json(
      { 
        error: error instanceof Error ? error.message : 'Failed to process file',
        details: process.env.NODE_ENV === 'development' ? String(error) : undefined
      },
      { status: 500 }
    );
  }
} 