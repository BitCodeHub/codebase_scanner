import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Github,
  Shield, 
  AlertTriangle,
  CheckCircle,
  Loader2,
  Eye,
  Download,
  Code,
  Lock,
  Bug,
  AlertCircle,
  FileText,
  GitBranch,
  Clock,
  BarChart3,
  TrendingUp,
  Search
} from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import { getApiUrl } from '../utils/api-config';

interface ScanOptions {
  branch: string;
  scanDepth: 'quick' | 'standard' | 'comprehensive' | 'paranoid';
  enableAiAnalysis: boolean;
  includeCommitHistory: boolean;
  includePrAnalysis: boolean;
  maxHistoryDepth: number;
}

interface Finding {
  tool: string;
  severity: string;
  title: string;
  file: string;
  line: number;
  description: string;
  cwe?: string;
  owasp?: string;
  code_snippet?: string;
}

export const EnterpriseGitHubScan: React.FC = () => {
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [scanPhase, setScanPhase] = useState('');
  const [scanId, setScanId] = useState<string | null>(null);
  const [scanResults, setScanResults] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const [repositoryUrl, setRepositoryUrl] = useState('');
  const [showDetailedFindings, setShowDetailedFindings] = useState(false);
  
  const [scanOptions, setScanOptions] = useState<ScanOptions>({
    branch: 'main',
    scanDepth: 'comprehensive',
    enableAiAnalysis: true,
    includeCommitHistory: true,
    includePrAnalysis: false,
    maxHistoryDepth: 100
  });

  const initiateScan = async () => {
    if (!repositoryUrl) {
      setError('Please enter a GitHub repository URL');
      return;
    }

    setError(null);
    setIsScanning(true);
    setScanProgress(0);
    setScanPhase('Initializing scan...');
    setScanResults(null);

    try {
      const response = await fetch(`${getApiUrl()}/api/enterprise/github/scan`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          repository_url: repositoryUrl,
          branch: scanOptions.branch,
          scan_depth: scanOptions.scanDepth,
          enable_ai_analysis: scanOptions.enableAiAnalysis,
          include_commit_history: scanOptions.includeCommitHistory,
          include_pr_analysis: scanOptions.includePrAnalysis,
          max_history_depth: scanOptions.maxHistoryDepth
        }),
      });

      if (!response.ok) {
        throw new Error('Failed to initiate scan');
      }

      const data = await response.json();
      setScanId(data.scan_id);

      // Poll for results
      const pollInterval = setInterval(async () => {
        const statusResponse = await fetch(
          `${getApiUrl()}/api/enterprise/github/${data.scan_id}/status`
        );

        if (statusResponse.ok) {
          const status = await statusResponse.json();
          setScanProgress(status.progress || 0);
          setScanPhase(status.phase || 'Processing...');

          if (status.status === 'completed') {
            clearInterval(pollInterval);

            // Get full results
            const resultsResponse = await fetch(
              `${getApiUrl()}/api/enterprise/github/${data.scan_id}/results`
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
      }, 3000);

      // Timeout after 20 minutes
      setTimeout(() => {
        clearInterval(pollInterval);
        if (isScanning) {
          setError('Scan timed out');
          setIsScanning(false);
        }
      }, 1200000);

    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to start scan');
      setIsScanning(false);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity?.toLowerCase()) {
      case 'critical': return 'text-red-600 bg-red-50 border-red-200';
      case 'high': return 'text-orange-600 bg-orange-50 border-orange-200';
      case 'medium': return 'text-yellow-600 bg-yellow-50 border-yellow-200';
      case 'low': return 'text-blue-600 bg-blue-50 border-blue-200';
      default: return 'text-gray-600 bg-gray-50 border-gray-200';
    }
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity?.toLowerCase()) {
      case 'critical': return <AlertCircle className="w-5 h-5" />;
      case 'high': return <AlertTriangle className="w-5 h-5" />;
      case 'medium': return <Bug className="w-5 h-5" />;
      case 'low': return <AlertCircle className="w-5 h-5" />;
      default: return <FileText className="w-5 h-5" />;
    }
  };

  const downloadReport = () => {
    if (!scanResults?.detailed_report) return;
    
    const data = JSON.stringify(scanResults.detailed_report, null, 2);
    const blob = new Blob([data], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `enterprise-security-report-${scanId}.json`;
    a.click();
  };

  return (
    <div className="min-h-screen bg-gray-50 py-8 px-4">
      <div className="max-w-7xl mx-auto">
        <div className="text-center mb-8">
          <h1 className="text-4xl font-bold text-gray-900 mb-4 flex items-center justify-center gap-3">
            <Github className="w-10 h-10" />
            Enterprise GitHub Security Scanner
          </h1>
          <p className="text-lg text-gray-600 max-w-3xl mx-auto">
            Production-grade security analysis with 20+ tools, detailed line-by-line vulnerability detection,
            commit history scanning, and AI-powered remediation recommendations.
          </p>
        </div>

        {/* Scan Configuration */}
        <div className="bg-white rounded-lg shadow-md p-6 mb-8">
          <h2 className="text-xl font-semibold mb-4">Repository Configuration</h2>
          
          <div className="space-y-6">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                GitHub Repository URL
              </label>
              <input
                type="url"
                value={repositoryUrl}
                onChange={(e) => setRepositoryUrl(e.target.value)}
                placeholder="https://github.com/organization/repository"
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                disabled={isScanning}
              />
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Branch
                </label>
                <input
                  type="text"
                  value={scanOptions.branch}
                  onChange={(e) => setScanOptions({...scanOptions, branch: e.target.value})}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                  disabled={isScanning}
                />
              </div>

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
                  <option value="quick">Quick (1-2 minutes)</option>
                  <option value="standard">Standard (3-5 minutes)</option>
                  <option value="comprehensive">Comprehensive (5-10 minutes)</option>
                  <option value="paranoid">Paranoid (10-20 minutes)</option>
                </select>
              </div>
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
                  checked={scanOptions.includeCommitHistory}
                  onChange={(e) => setScanOptions({...scanOptions, includeCommitHistory: e.target.checked})}
                  className="mr-2"
                  disabled={isScanning}
                />
                <span className="text-sm">Scan Full Commit History for Secrets</span>
              </label>

              <label className="flex items-center">
                <input
                  type="checkbox"
                  checked={scanOptions.includePrAnalysis}
                  onChange={(e) => setScanOptions({...scanOptions, includePrAnalysis: e.target.checked})}
                  className="mr-2"
                  disabled={isScanning}
                />
                <span className="text-sm">Analyze Pull Requests (Coming Soon)</span>
              </label>
            </div>

            <button
              onClick={initiateScan}
              disabled={isScanning || !repositoryUrl}
              className={`w-full py-3 rounded-lg font-medium transition-all ${
                isScanning || !repositoryUrl
                  ? 'bg-gray-300 text-gray-500 cursor-not-allowed'
                  : 'bg-blue-600 text-white hover:bg-blue-700'
              }`}
            >
              {isScanning ? (
                <span className="flex items-center justify-center gap-2">
                  <Loader2 className="w-5 h-5 animate-spin" />
                  Scanning Repository...
                </span>
              ) : (
                'Start Enterprise Security Scan'
              )}
            </button>
          </div>
        </div>

        {/* Scan Progress */}
        {isScanning && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="bg-white rounded-lg shadow-md p-6 mb-8"
          >
            <h3 className="text-lg font-semibold mb-4">Scan Progress</h3>
            <div className="space-y-4">
              <div>
                <div className="flex justify-between text-sm text-gray-600 mb-1">
                  <span>{scanPhase}</span>
                  <span>{scanProgress}%</span>
                </div>
                <div className="bg-gray-200 rounded-full h-3 overflow-hidden">
                  <motion.div
                    className="bg-blue-600 h-full"
                    initial={{ width: 0 }}
                    animate={{ width: `${scanProgress}%` }}
                    transition={{ duration: 0.5 }}
                  />
                </div>
              </div>
              
              <div className="text-sm text-gray-500">
                <p>Running 20+ security tools including:</p>
                <p className="mt-1">Semgrep • Bandit • GitLeaks • TruffleHog • Grype • Trivy • Checkov • ESLint • and more...</p>
              </div>
            </div>
          </motion.div>
        )}

        {/* Error Display */}
        {error && (
          <motion.div
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            className="mb-6 p-4 bg-red-50 border border-red-200 rounded-lg"
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
            className="space-y-6"
          >
            {/* Executive Summary */}
            <div className="bg-white rounded-lg shadow-lg p-6">
              <h2 className="text-2xl font-bold mb-6">Executive Summary</h2>
              
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
                <div className="text-center p-4 bg-gray-50 rounded-lg">
                  <p className="text-sm text-gray-600">Security Score</p>
                  <p className="text-4xl font-bold text-blue-600 mt-1">
                    {scanResults.detailed_report?.executive_summary?.security_score || 'N/A'}
                  </p>
                </div>
                <div className="text-center p-4 bg-gray-50 rounded-lg">
                  <p className="text-sm text-gray-600">Risk Level</p>
                  <p className={`text-2xl font-bold mt-1 ${
                    scanResults.detailed_report?.executive_summary?.risk_level === 'CRITICAL' ? 'text-red-600' :
                    scanResults.detailed_report?.executive_summary?.risk_level === 'HIGH' ? 'text-orange-600' :
                    scanResults.detailed_report?.executive_summary?.risk_level === 'MEDIUM' ? 'text-yellow-600' :
                    'text-green-600'
                  }`}>
                    {scanResults.detailed_report?.executive_summary?.risk_level || 'N/A'}
                  </p>
                </div>
                <div className="text-center p-4 bg-gray-50 rounded-lg">
                  <p className="text-sm text-gray-600">Total Findings</p>
                  <p className="text-4xl font-bold text-gray-800 mt-1">
                    {scanResults.findings?.total || 0}
                  </p>
                </div>
              </div>

              {/* Repository Stats */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                <div>
                  <p className="text-sm text-gray-600">Files Scanned</p>
                  <p className="font-medium">{scanResults.repository_stats?.total_files || 0}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-600">Lines Analyzed</p>
                  <p className="font-medium">{scanResults.repository_stats?.total_lines?.toLocaleString() || 0}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-600">Languages</p>
                  <p className="font-medium">{scanResults.project_info?.languages?.length || 0}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-600">Scan Duration</p>
                  <p className="font-medium">
                    {scanResults.detailed_report?.executive_summary?.scan_duration || 'N/A'}
                  </p>
                </div>
              </div>

              {/* Severity Breakdown */}
              <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                {['critical', 'high', 'medium', 'low', 'info'].map((severity) => {
                  const count = scanResults.findings?.[severity] || 0;
                  return (
                    <div key={severity} className={`p-4 rounded-lg border ${getSeverityColor(severity)}`}>
                      <div className="flex items-center justify-between">
                        {getSeverityIcon(severity)}
                        <span className="text-2xl font-bold">{count}</span>
                      </div>
                      <p className="text-sm font-medium capitalize mt-1">{severity}</p>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Critical Issues */}
            {scanResults.detailed_report?.critical_issues?.length > 0 && (
              <div className="bg-white rounded-lg shadow-lg p-6">
                <h3 className="text-xl font-bold mb-4 flex items-center gap-2">
                  <AlertCircle className="w-6 h-6 text-red-600" />
                  Critical Security Issues
                </h3>
                
                <div className="space-y-4">
                  {scanResults.detailed_report.critical_issues.map((issue: Finding, idx: number) => (
                    <div key={idx} className="border border-red-200 rounded-lg p-4 bg-red-50">
                      <div className="flex items-start justify-between">
                        <div className="flex-1">
                          <h4 className="font-semibold text-red-800">{issue.title}</h4>
                          <p className="text-sm text-gray-700 mt-1">
                            {issue.file}:{issue.line} • {issue.tool}
                          </p>
                          <p className="text-sm text-gray-600 mt-2">{issue.description}</p>
                          {issue.cwe && (
                            <p className="text-xs text-gray-500 mt-1">CWE-{issue.cwe}</p>
                          )}
                        </div>
                        <span className="px-3 py-1 text-xs font-medium text-red-700 bg-red-100 rounded-full">
                          CRITICAL
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Detailed Findings Toggle */}
            <div className="bg-white rounded-lg shadow-lg p-6">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-xl font-bold">Detailed Security Findings</h3>
                <button
                  onClick={() => setShowDetailedFindings(!showDetailedFindings)}
                  className="flex items-center text-blue-600 hover:text-blue-700"
                >
                  {showDetailedFindings ? 'Hide Details' : 'Show All Findings'}
                  <Eye className="w-5 h-5 ml-1" />
                </button>
              </div>

              {showDetailedFindings && (
                <AnimatePresence>
                  <motion.div
                    initial={{ opacity: 0, height: 0 }}
                    animate={{ opacity: 1, height: 'auto' }}
                    exit={{ opacity: 0, height: 0 }}
                    className="space-y-6"
                  >
                    {Object.entries(scanResults.detailed_report?.findings_by_category || {}).map(
                      ([category, findings]: [string, any]) => (
                        findings.length > 0 && (
                          <div key={category}>
                            <h4 className="font-semibold mb-3 capitalize">
                              {category.replace('_', ' ')} ({findings.length})
                            </h4>
                            <div className="space-y-3">
                              {findings.slice(0, 10).map((finding: Finding, idx: number) => (
                                <div key={idx} className="border rounded-lg p-4 hover:bg-gray-50">
                                  <div className="flex items-start justify-between">
                                    <div className="flex-1">
                                      <p className="font-medium">{finding.title}</p>
                                      <p className="text-sm text-gray-600 mt-1">
                                        {finding.file}:{finding.line} • {finding.tool}
                                      </p>
                                      <p className="text-sm text-gray-700 mt-2">{finding.description}</p>
                                      {finding.code_snippet && (
                                        <pre className="mt-2 p-2 bg-gray-100 rounded text-xs overflow-x-auto">
                                          <code>{finding.code_snippet}</code>
                                        </pre>
                                      )}
                                    </div>
                                    <span className={`px-2 py-1 text-xs font-medium rounded ${getSeverityColor(finding.severity)}`}>
                                      {finding.severity.toUpperCase()}
                                    </span>
                                  </div>
                                </div>
                              ))}
                            </div>
                          </div>
                        )
                      )
                    )}
                  </motion.div>
                </AnimatePresence>
              )}
            </div>

            {/* AI Analysis */}
            {scanResults.ai_analysis && (
              <div className="bg-white rounded-lg shadow-lg p-6">
                <h3 className="text-xl font-bold mb-4 flex items-center gap-2">
                  <Shield className="w-6 h-6 text-blue-600" />
                  AI Security Analysis
                </h3>
                
                <div className="prose prose-sm max-w-none">
                  <ReactMarkdown>
                    {scanResults.ai_analysis.analysis || scanResults.ai_analysis}
                  </ReactMarkdown>
                </div>
              </div>
            )}

            {/* Compliance Status */}
            {scanResults.detailed_report?.executive_summary?.compliance_status && (
              <div className="bg-white rounded-lg shadow-lg p-6">
                <h3 className="text-xl font-bold mb-4">Compliance Status</h3>
                <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                  {Object.entries(scanResults.detailed_report.executive_summary.compliance_status).map(
                    ([standard, status]) => (
                      <div key={standard} className={`p-3 rounded-lg text-center ${
                        status === 'PASS' ? 'bg-green-50 text-green-700' :
                        status === 'FAIL' ? 'bg-red-50 text-red-700' :
                        'bg-yellow-50 text-yellow-700'
                      }`}>
                        <p className="font-medium text-sm">{standard.replace(/_/g, ' ')}</p>
                        <p className="text-xs mt-1">{status}</p>
                      </div>
                    )
                  )}
                </div>
              </div>
            )}

            {/* Action Buttons */}
            <div className="flex justify-center gap-4">
              <button
                onClick={downloadReport}
                className="flex items-center px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
              >
                <Download className="w-5 h-5 mr-2" />
                Download Full Report
              </button>
              
              <button
                onClick={() => {
                  setScanResults(null);
                  setRepositoryUrl('');
                }}
                className="px-6 py-3 bg-gray-200 text-gray-700 rounded-lg hover:bg-gray-300"
              >
                Scan Another Repository
              </button>
            </div>
          </motion.div>
        )}
      </div>
    </div>
  );
};