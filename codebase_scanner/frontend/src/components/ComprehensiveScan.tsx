import React, { useState, useCallback } from 'react';
import { useDropzone } from 'react-dropzone';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Upload, 
  FileCode, 
  Shield, 
  AlertTriangle, 
  CheckCircle,
  Loader2,
  ChevronRight,
  Eye,
  Download,
  Code,
  Lock,
  Database,
  Cloud,
  Smartphone,
  Globe,
  Server,
  Bug
} from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import { getApiUrl } from '../utils/api-config';

interface ScanOptions {
  scanDepth: 'quick' | 'standard' | 'comprehensive' | 'paranoid';
  enableAiAnalysis: boolean;
  includeCodeQuality: boolean;
  includeDependencies: boolean;
  includeInfrastructure: boolean;
}

export const ComprehensiveScan: React.FC = () => {
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [scanId, setScanId] = useState<string | null>(null);
  const [scanResults, setScanResults] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const [showAiAnalysis, setShowAiAnalysis] = useState(false);
  
  const [scanOptions, setScanOptions] = useState<ScanOptions>({
    scanDepth: 'comprehensive',
    enableAiAnalysis: true,
    includeCodeQuality: true,
    includeDependencies: true,
    includeInfrastructure: true
  });

  const onDrop = useCallback(async (acceptedFiles: File[]) => {
    if (acceptedFiles.length === 0) return;
    
    const file = acceptedFiles[0];
    setError(null);
    setIsScanning(true);
    setScanProgress(0);
    setScanResults(null);
    
    const formData = new FormData();
    formData.append('file', file);
    formData.append('scan_depth', scanOptions.scanDepth);
    formData.append('enable_ai_analysis', String(scanOptions.enableAiAnalysis));
    formData.append('include_code_quality', String(scanOptions.includeCodeQuality));
    formData.append('include_dependencies', String(scanOptions.includeDependencies));
    formData.append('include_infrastructure', String(scanOptions.includeInfrastructure));
    
    try {
      // Initiate scan
      const response = await fetch(`${getApiUrl()}/api/comprehensive/scan`, {
        method: 'POST',
        body: formData,
      });
      
      if (!response.ok) {
        throw new Error('Failed to initiate scan');
      }
      
      const data = await response.json();
      setScanId(data.scan_id);
      
      // Poll for results
      const pollInterval = setInterval(async () => {
        const statusResponse = await fetch(
          `${getApiUrl()}/api/comprehensive/scan/${data.scan_id}/status`
        );
        
        if (statusResponse.ok) {
          const status = await statusResponse.json();
          setScanProgress(status.progress || 0);
          
          if (status.status === 'completed') {
            clearInterval(pollInterval);
            
            // Get full results
            const resultsResponse = await fetch(
              `${getApiUrl()}/api/comprehensive/scan/${data.scan_id}/results`
            );
            
            if (resultsResponse.ok) {
              const results = await resultsResponse.json();
              setScanResults(results);
              setIsScanning(false);
            }
          } else if (status.status === 'failed') {
            clearInterval(pollInterval);
            setError(status.error || 'Scan failed');
            setIsScanning(false);
          }
        }
      }, 2000);
      
      // Timeout after 10 minutes
      setTimeout(() => {
        clearInterval(pollInterval);
        if (isScanning) {
          setError('Scan timed out');
          setIsScanning(false);
        }
      }, 600000);
      
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Upload failed');
      setIsScanning(false);
    }
  }, [scanOptions, isScanning]);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    multiple: false,
    disabled: isScanning,
    maxSize: 500 * 1024 * 1024 // 500MB
  });

  const getSeverityColor = (severity: string) => {
    switch (severity?.toLowerCase()) {
      case 'critical': return 'text-red-600 bg-red-50';
      case 'high': return 'text-orange-600 bg-orange-50';
      case 'medium': return 'text-yellow-600 bg-yellow-50';
      case 'low': return 'text-blue-600 bg-blue-50';
      default: return 'text-gray-600 bg-gray-50';
    }
  };

  const getCategoryIcon = (category: string) => {
    switch (category) {
      case 'vulnerabilities': return <Bug className="w-5 h-5" />;
      case 'secrets': return <Lock className="w-5 h-5" />;
      case 'dependencies': return <Code className="w-5 h-5" />;
      case 'infrastructure': return <Cloud className="w-5 h-5" />;
      case 'mobile_security': return <Smartphone className="w-5 h-5" />;
      case 'code_quality': return <FileCode className="w-5 h-5" />;
      default: return <Shield className="w-5 h-5" />;
    }
  };

  const getProjectTypeIcon = (type: string) => {
    switch (type) {
      case 'web_application': return <Globe className="w-5 h-5" />;
      case 'api_service': return <Server className="w-5 h-5" />;
      case 'mobile_application': return <Smartphone className="w-5 h-5" />;
      case 'infrastructure': return <Cloud className="w-5 h-5" />;
      default: return <Code className="w-5 h-5" />;
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 py-8 px-4">
      <div className="max-w-7xl mx-auto">
        <div className="text-center mb-8">
          <h1 className="text-4xl font-bold text-gray-900 mb-4">
            Comprehensive Security Scanner
          </h1>
          <p className="text-lg text-gray-600 max-w-3xl mx-auto">
            Advanced security analysis for any codebase - web apps, mobile apps, APIs, 
            infrastructure code, and more. Get detailed vulnerability reports with AI-powered remediation.
          </p>
        </div>

        {/* Scan Options */}
        <div className="bg-white rounded-lg shadow-md p-6 mb-8">
          <h2 className="text-xl font-semibold mb-4">Scan Configuration</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Scan Depth
              </label>
              <select
                value={scanOptions.scanDepth}
                onChange={(e) => setScanOptions({...scanOptions, scanDepth: e.target.value as any})}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                disabled={isScanning}
              >
                <option value="quick">Quick (30-60 seconds)</option>
                <option value="standard">Standard (2-5 minutes)</option>
                <option value="comprehensive">Comprehensive (5-10 minutes)</option>
                <option value="paranoid">Paranoid (10+ minutes)</option>
              </select>
            </div>
            
            <div className="space-y-3">
              <label className="flex items-center">
                <input
                  type="checkbox"
                  checked={scanOptions.enableAiAnalysis}
                  onChange={(e) => setScanOptions({...scanOptions, enableAiAnalysis: e.target.checked})}
                  className="mr-2"
                  disabled={isScanning}
                />
                <span className="text-sm">Enable AI-Powered Analysis (Claude)</span>
              </label>
              
              <label className="flex items-center">
                <input
                  type="checkbox"
                  checked={scanOptions.includeCodeQuality}
                  onChange={(e) => setScanOptions({...scanOptions, includeCodeQuality: e.target.checked})}
                  className="mr-2"
                  disabled={isScanning}
                />
                <span className="text-sm">Include Code Quality Checks</span>
              </label>
              
              <label className="flex items-center">
                <input
                  type="checkbox"
                  checked={scanOptions.includeDependencies}
                  onChange={(e) => setScanOptions({...scanOptions, includeDependencies: e.target.checked})}
                  className="mr-2"
                  disabled={isScanning}
                />
                <span className="text-sm">Scan Dependencies</span>
              </label>
              
              <label className="flex items-center">
                <input
                  type="checkbox"
                  checked={scanOptions.includeInfrastructure}
                  onChange={(e) => setScanOptions({...scanOptions, includeInfrastructure: e.target.checked})}
                  className="mr-2"
                  disabled={isScanning}
                />
                <span className="text-sm">Scan Infrastructure Code</span>
              </label>
            </div>
          </div>
        </div>

        {/* Upload Area */}
        <div
          {...getRootProps()}
          className={`border-2 border-dashed rounded-lg p-12 text-center cursor-pointer transition-all
            ${isDragActive ? 'border-blue-500 bg-blue-50' : 'border-gray-300 hover:border-gray-400'}
            ${isScanning ? 'opacity-50 cursor-not-allowed' : ''}`}
        >
          <input {...getInputProps()} />
          
          {isScanning ? (
            <div className="space-y-4">
              <Loader2 className="w-16 h-16 mx-auto text-blue-600 animate-spin" />
              <p className="text-lg font-medium">Comprehensive security scan in progress...</p>
              <div className="max-w-md mx-auto">
                <div className="bg-gray-200 rounded-full h-3 overflow-hidden">
                  <motion.div
                    className="bg-blue-600 h-full"
                    initial={{ width: 0 }}
                    animate={{ width: `${scanProgress}%` }}
                    transition={{ duration: 0.5 }}
                  />
                </div>
                <p className="text-sm text-gray-600 mt-2">{scanProgress}% Complete</p>
              </div>
            </div>
          ) : (
            <>
              <Upload className="w-16 h-16 mx-auto text-gray-400 mb-4" />
              <p className="text-lg mb-2">
                {isDragActive ? 'Drop your code here...' : 'Drag & drop your code or click to browse'}
              </p>
              <p className="text-sm text-gray-500">
                Supports: ZIP, TAR, individual files, entire projects up to 500MB
              </p>
            </>
          )}
        </div>

        {/* Error Display */}
        {error && (
          <motion.div
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            className="mt-6 p-4 bg-red-50 border border-red-200 rounded-lg"
          >
            <p className="text-red-700 flex items-center">
              <AlertTriangle className="w-5 h-5 mr-2" />
              {error}
            </p>
          </motion.div>
        )}

        {/* Results Display */}
        {scanResults && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="mt-8 space-y-6"
          >
            {/* Summary Card */}
            <div className="bg-white rounded-lg shadow-lg p-6">
              <h2 className="text-2xl font-bold mb-4">Security Scan Results</h2>
              
              {/* Project Info */}
              <div className="mb-6 p-4 bg-gray-50 rounded-lg">
                <h3 className="font-semibold mb-2">Project Information</h3>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <div>
                    <p className="text-sm text-gray-600">Languages</p>
                    <p className="font-medium">{scanResults.results?.project_info?.languages?.join(', ') || 'N/A'}</p>
                  </div>
                  <div>
                    <p className="text-sm text-gray-600">Frameworks</p>
                    <p className="font-medium">{scanResults.results?.project_info?.frameworks?.join(', ') || 'N/A'}</p>
                  </div>
                  <div>
                    <p className="text-sm text-gray-600">Project Types</p>
                    <div className="flex items-center gap-1">
                      {scanResults.results?.project_info?.project_types?.map((type: string) => (
                        <span key={type} title={type}>
                          {getProjectTypeIcon(type)}
                        </span>
                      ))}
                    </div>
                  </div>
                  <div>
                    <p className="text-sm text-gray-600">Security Grade</p>
                    <p className="text-2xl font-bold text-blue-600">
                      {scanResults.results?.detailed_report?.overview?.security_grade || 'N/A'}
                    </p>
                  </div>
                </div>
              </div>
              
              {/* Severity Summary */}
              <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-6">
                {['critical', 'high', 'medium', 'low', 'info'].map((severity) => {
                  const count = scanResults.results?.summary?.severity_breakdown?.[severity] || 0;
                  return (
                    <div key={severity} className={`p-4 rounded-lg ${getSeverityColor(severity)}`}>
                      <p className="text-sm font-medium capitalize">{severity}</p>
                      <p className="text-2xl font-bold">{count}</p>
                    </div>
                  );
                })}
              </div>
              
              {/* Category Summary */}
              <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
                {Object.entries(scanResults.results?.summary?.categories || {}).map(([category, count]) => (
                  <div key={category} className="flex items-center p-3 bg-gray-50 rounded-lg">
                    {getCategoryIcon(category)}
                    <div className="ml-3">
                      <p className="text-sm text-gray-600 capitalize">
                        {category.replace('_', ' ')}
                      </p>
                      <p className="font-semibold">{count as number} issues</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Detailed Findings */}
            <div className="bg-white rounded-lg shadow-lg p-6">
              <h3 className="text-xl font-bold mb-4">Detailed Security Findings</h3>
              
              {Object.entries(scanResults.results?.findings || {}).map(([category, findings]: [string, any[]]) => (
                findings.length > 0 && (
                  <div key={category} className="mb-6">
                    <h4 className="font-semibold mb-3 flex items-center">
                      {getCategoryIcon(category)}
                      <span className="ml-2 capitalize">{category.replace('_', ' ')}</span>
                      <span className="ml-2 text-sm text-gray-500">({findings.length})</span>
                    </h4>
                    
                    <div className="space-y-3">
                      {findings.slice(0, 5).map((finding, idx) => (
                        <div key={idx} className="border rounded-lg p-4 hover:bg-gray-50">
                          <div className="flex items-start justify-between">
                            <div className="flex-1">
                              <p className="font-medium">{finding.title}</p>
                              <p className="text-sm text-gray-600 mt-1">
                                {finding.file}:{finding.line} • {finding.tool}
                              </p>
                              {finding.cve && (
                                <p className="text-sm text-red-600 mt-1">CVE: {finding.cve}</p>
                              )}
                            </div>
                            <span className={`px-2 py-1 text-xs font-medium rounded ${getSeverityColor(finding.severity)}`}>
                              {finding.severity}
                            </span>
                          </div>
                        </div>
                      ))}
                      
                      {findings.length > 5 && (
                        <p className="text-sm text-gray-500 text-center">
                          And {findings.length - 5} more...
                        </p>
                      )}
                    </div>
                  </div>
                )
              ))}
            </div>

            {/* AI Analysis */}
            {scanResults.results?.ai_analysis?.success && (
              <div className="bg-white rounded-lg shadow-lg p-6">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-xl font-bold flex items-center">
                    <Shield className="w-6 h-6 mr-2 text-blue-600" />
                    AI Security Analysis
                  </h3>
                  <button
                    onClick={() => setShowAiAnalysis(!showAiAnalysis)}
                    className="flex items-center text-blue-600 hover:text-blue-700"
                  >
                    {showAiAnalysis ? 'Hide' : 'Show'} Analysis
                    <ChevronRight className={`w-5 h-5 ml-1 transform transition-transform ${showAiAnalysis ? 'rotate-90' : ''}`} />
                  </button>
                </div>
                
                <AnimatePresence>
                  {showAiAnalysis && (
                    <motion.div
                      initial={{ opacity: 0, height: 0 }}
                      animate={{ opacity: 1, height: 'auto' }}
                      exit={{ opacity: 0, height: 0 }}
                      className="prose prose-sm max-w-none"
                    >
                      <ReactMarkdown>
                        {scanResults.results.ai_analysis.analysis}
                      </ReactMarkdown>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            )}

            {/* Action Buttons */}
            <div className="flex justify-center gap-4">
              <button
                onClick={() => {
                  const data = JSON.stringify(scanResults.results, null, 2);
                  const blob = new Blob([data], { type: 'application/json' });
                  const url = URL.createObjectURL(blob);
                  const a = document.createElement('a');
                  a.href = url;
                  a.download = `security-report-${scanId}.json`;
                  a.click();
                }}
                className="flex items-center px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
              >
                <Download className="w-5 h-5 mr-2" />
                Download Full Report
              </button>
              
              <button
                onClick={() => setScanResults(null)}
                className="px-6 py-3 bg-gray-200 text-gray-700 rounded-lg hover:bg-gray-300"
              >
                Scan Another File
              </button>
            </div>
          </motion.div>
        )}
      </div>
    </div>
  );
};