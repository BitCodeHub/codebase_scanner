import React, { useState, useCallback } from 'react';
import { useDropzone } from 'react-dropzone';
import { Upload, File, AlertCircle, CheckCircle, Loader2, Brain, Shield, Code } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { scannerService } from '../services/scannerService';
import ReactMarkdown from 'react-markdown';

interface ScanResult {
  scan_id: string;
  status: string;
  filename: string;
  languages: string[];
  total_findings: number;
  severity_counts: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  ai_analysis?: {
    success: boolean;
    analysis: string;
  };
  findings: any[];
  secrets: {
    secrets_found: number;
    findings: any[];
  };
}

export const UniversalFileUpload: React.FC = () => {
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [enableAI, setEnableAI] = useState(true);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);

  const onDrop = useCallback((acceptedFiles: File[]) => {
    if (acceptedFiles.length > 0) {
      setSelectedFile(acceptedFiles[0]);
      setError(null);
      setScanResult(null);
    }
  }, []);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    maxFiles: 1,
    maxSize: 100 * 1024 * 1024, // 100MB
  });

  const startScan = async () => {
    if (!selectedFile) return;

    setIsScanning(true);
    setError(null);
    setScanProgress(0);

    try {
      // Create form data
      const formData = new FormData();
      formData.append('file', selectedFile);
      formData.append('enable_ai_analysis', enableAI.toString());
      formData.append('scan_type', 'comprehensive');

      // Start scan
      const response = await scannerService.uploadUniversalScan(formData);
      const scanId = response.scan_id;

      // Poll for results
      const pollInterval = setInterval(async () => {
        try {
          const status = await scannerService.getUniversalScanStatus(scanId);
          
          if (status.status === 'completed') {
            clearInterval(pollInterval);
            const results = await scannerService.getUniversalScanResults(scanId);
            setScanResult(results);
            setIsScanning(false);
            setScanProgress(100);
          } else if (status.status === 'failed') {
            clearInterval(pollInterval);
            setError('Scan failed. Please try again.');
            setIsScanning(false);
          } else {
            // Update progress
            setScanProgress(prev => Math.min(prev + 10, 90));
          }
        } catch (err) {
          console.error('Error polling scan status:', err);
        }
      }, 2000);

    } catch (err) {
      setError('Failed to start scan. Please try again.');
      setIsScanning(false);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return 'text-red-600 bg-red-100';
      case 'high': return 'text-orange-600 bg-orange-100';
      case 'medium': return 'text-yellow-600 bg-yellow-100';
      case 'low': return 'text-blue-600 bg-blue-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  return (
    <div className="max-w-6xl mx-auto p-6">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-gray-900 mb-2">Universal Security Scanner</h1>
        <p className="text-gray-600">Upload any code file or archive for comprehensive security analysis with AI-powered remediation recommendations</p>
      </div>

      {/* File Upload Area */}
      {!scanResult && (
        <div className="mb-8">
          <div
            {...getRootProps()}
            className={`border-2 border-dashed rounded-lg p-12 text-center cursor-pointer transition-colors ${
              isDragActive ? 'border-blue-500 bg-blue-50' : 'border-gray-300 hover:border-gray-400'
            }`}
          >
            <input {...getInputProps()} />
            <Upload className="mx-auto h-12 w-12 text-gray-400 mb-4" />
            {selectedFile ? (
              <div>
                <p className="text-lg font-medium text-gray-900">{selectedFile.name}</p>
                <p className="text-sm text-gray-500 mt-1">
                  {(selectedFile.size / 1024 / 1024).toFixed(2)} MB
                </p>
              </div>
            ) : (
              <div>
                <p className="text-lg font-medium text-gray-900">
                  Drop your code file here, or click to select
                </p>
                <p className="text-sm text-gray-500 mt-2">
                  Supports all programming languages • Single files or archives (zip, tar) • Max 100MB
                </p>
              </div>
            )}
          </div>

          {selectedFile && !isScanning && (
            <div className="mt-4 flex items-center justify-between">
              <label className="flex items-center">
                <input
                  type="checkbox"
                  checked={enableAI}
                  onChange={(e) => setEnableAI(e.target.checked)}
                  className="mr-2"
                />
                <span className="text-sm font-medium text-gray-700 flex items-center">
                  <Brain className="w-4 h-4 mr-1" />
                  Enable Claude AI Analysis & Remediation
                </span>
              </label>
              <button
                onClick={startScan}
                className="px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors flex items-center"
              >
                <Shield className="w-4 h-4 mr-2" />
                Start Security Scan
              </button>
            </div>
          )}
        </div>
      )}

      {/* Scanning Progress */}
      {isScanning && (
        <div className="mb-8 bg-white rounded-lg shadow p-6">
          <div className="flex items-center mb-4">
            <Loader2 className="animate-spin h-5 w-5 text-blue-600 mr-2" />
            <span className="font-medium">Scanning in progress...</span>
          </div>
          <div className="w-full bg-gray-200 rounded-full h-2">
            <div
              className="bg-blue-600 h-2 rounded-full transition-all duration-500"
              style={{ width: `${scanProgress}%` }}
            />
          </div>
          <p className="text-sm text-gray-600 mt-2">
            Analyzing code for vulnerabilities across multiple security tools...
          </p>
        </div>
      )}

      {/* Error Display */}
      {error && (
        <div className="mb-8 bg-red-50 border border-red-200 rounded-lg p-4 flex items-center">
          <AlertCircle className="h-5 w-5 text-red-600 mr-2" />
          <span className="text-red-800">{error}</span>
        </div>
      )}

      {/* Scan Results */}
      {scanResult && (
        <AnimatePresence>
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            className="space-y-6"
          >
            {/* Summary Card */}
            <div className="bg-white rounded-lg shadow p-6">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-xl font-bold text-gray-900 flex items-center">
                  <CheckCircle className="w-6 h-6 text-green-600 mr-2" />
                  Scan Complete
                </h2>
                <button
                  onClick={() => {
                    setScanResult(null);
                    setSelectedFile(null);
                    setScanProgress(0);
                  }}
                  className="text-sm text-blue-600 hover:text-blue-800"
                >
                  Scan Another File
                </button>
              </div>
              
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
                <div className="bg-gray-50 rounded p-4">
                  <p className="text-sm text-gray-600">File</p>
                  <p className="font-medium">{scanResult.filename}</p>
                </div>
                <div className="bg-gray-50 rounded p-4">
                  <p className="text-sm text-gray-600">Languages</p>
                  <p className="font-medium">{scanResult.languages.join(', ') || 'Unknown'}</p>
                </div>
                <div className="bg-gray-50 rounded p-4">
                  <p className="text-sm text-gray-600">Total Findings</p>
                  <p className="font-medium text-lg">{scanResult.total_findings}</p>
                </div>
              </div>

              {/* Severity Breakdown */}
              <div className="flex items-center space-x-4">
                {Object.entries(scanResult.severity_counts).map(([severity, count]) => (
                  <div key={severity} className={`px-3 py-1 rounded-full text-sm font-medium ${getSeverityColor(severity)}`}>
                    {severity}: {count}
                  </div>
                ))}
              </div>
            </div>

            {/* AI Analysis */}
            {scanResult.ai_analysis?.success && (
              <div className="bg-white rounded-lg shadow p-6">
                <h3 className="text-lg font-bold text-gray-900 mb-4 flex items-center">
                  <Brain className="w-5 h-5 text-purple-600 mr-2" />
                  Claude AI Security Analysis & Remediation Plan
                </h3>
                <div className="prose prose-sm max-w-none">
                  <ReactMarkdown>{scanResult.ai_analysis.analysis}</ReactMarkdown>
                </div>
              </div>
            )}

            {/* Detailed Findings */}
            <div className="bg-white rounded-lg shadow p-6">
              <h3 className="text-lg font-bold text-gray-900 mb-4 flex items-center">
                <Code className="w-5 h-5 text-gray-600 mr-2" />
                Detailed Security Findings
              </h3>
              
              {/* Secrets */}
              {scanResult.secrets.secrets_found > 0 && (
                <div className="mb-6">
                  <h4 className="font-medium text-red-600 mb-2">
                    🔐 {scanResult.secrets.secrets_found} Hardcoded Secrets Found
                  </h4>
                  <div className="space-y-2">
                    {scanResult.secrets.findings.slice(0, 5).map((secret, idx) => (
                      <div key={idx} className="bg-red-50 p-3 rounded text-sm">
                        <p className="font-medium">{secret.title}</p>
                        <p className="text-gray-600">File: {secret.file}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Other Findings */}
              <div className="space-y-3">
                {scanResult.findings.slice(0, 20).map((finding, idx) => (
                  <div key={idx} className="border-l-4 border-gray-200 pl-4 py-2">
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <p className="font-medium text-gray-900">{finding.title}</p>
                        <p className="text-sm text-gray-600 mt-1">
                          {finding.file}:{finding.line} • {finding.tool}
                        </p>
                        {finding.message && (
                          <p className="text-sm text-gray-700 mt-1">{finding.message}</p>
                        )}
                      </div>
                      <span className={`px-2 py-1 rounded text-xs font-medium ${getSeverityColor(finding.severity)}`}>
                        {finding.severity}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
              
              {scanResult.total_findings > 20 && (
                <p className="text-center text-gray-500 mt-4 text-sm">
                  Showing 20 of {scanResult.total_findings} findings
                </p>
              )}
            </div>
          </motion.div>
        </AnimatePresence>
      )}
    </div>
  );
};