import { useState } from 'react'
import {
  Shield,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Info,
  Download,
  FileText,
  TrendingUp,
  Activity,
  BarChart3,
  Bug,
  Lock,
  Eye,
  ChevronRight,
  ChevronDown,
  Target,
  GitBranch,
  Clock,
  Users,
  Database,
  Cloud,
  Code2,
  FileCode,
  Zap,
  BookOpen,
  Award,
  AlertOctagon
} from 'lucide-react'

interface EnterpriseReportProps {
  scan: any
  results: any[]
}

export default function EnterpriseSecurityReport({ scan, results }: EnterpriseReportProps) {
  const [expandedSections, setExpandedSections] = useState<Set<string>>(new Set(['executive', 'risk', 'findings']))

  const toggleSection = (section: string) => {
    const newExpanded = new Set(expandedSections)
    if (newExpanded.has(section)) {
      newExpanded.delete(section)
    } else {
      newExpanded.add(section)
    }
    setExpandedSections(newExpanded)
  }

  const downloadReport = async () => {
    // Generate markdown report
    const reportContent = generateMarkdownReport()
    
    // Create blob and download
    const blob = new Blob([reportContent], { type: 'text/markdown' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `security-report-${scan.id}-${new Date().toISOString().split('T')[0]}.md`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  const generateMarkdownReport = () => {
    const scanConfig = scan.scan_config || {}
    const date = new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })
    
    return `# Enterprise Security Assessment Report
## ${scan.project?.name || 'Unknown Project'} - Comprehensive Security Analysis

**Document Classification:** CONFIDENTIAL  
**Report Version:** 1.0  
**Assessment Date:** ${date}  
**Report ID:** SEC-${scan.id}  
**Repository:** ${scanConfig.repository_url || 'Unknown'}  

### Quick Statistics
- **Total Security Tools Run:** ${scanConfig.tools_used?.length || 0}
- **Files Scanned:** ${scanConfig.files_scanned?.toLocaleString() || 0}
- **Lines of Code Analyzed:** ${scanConfig.lines_scanned?.toLocaleString() || 0}
- **Total Vulnerabilities:** ${scan.total_issues || 0}
- **Critical Issues:** ${scan.critical_issues || 0}
- **High Risk Issues:** ${scan.high_issues || 0}
- **Scan Duration:** ${scanConfig.scan_duration || 'Unknown'}

---

## Executive Summary

${scanConfig.executive_summary || 'No executive summary available.'}

---

## Risk Assessment

### Vulnerability Distribution
- Critical: ${scan.critical_issues || 0}
- High: ${scan.high_issues || 0}
- Medium: ${scan.medium_issues || 0}
- Low: ${scan.low_issues || 0}

**Overall Risk Level:** ${scanConfig.risk_level || 'UNKNOWN'}
**Risk Score:** ${scanConfig.risk_score || 0}/100

---

## Detailed Findings

${results.map(r => `
### ${r.title}
- **Severity:** ${r.severity}
- **File:** ${r.file_path}${r.line_number ? `:${r.line_number}` : ''}
- **Category:** ${r.category}
- **Description:** ${r.description}
- **Fix Recommendation:** ${r.fix_recommendation}
`).join('\n---\n')}

---

Generated on ${new Date().toISOString()}
`
  }

  const getRiskLevelColor = (level: string) => {
    switch (level?.toUpperCase()) {
      case 'CRITICAL': return 'text-red-500'
      case 'HIGH': return 'text-orange-500'
      case 'MEDIUM': return 'text-yellow-500'
      case 'LOW': return 'text-green-500'
      default: return 'text-gray-500'
    }
  }

  const scanConfig = scan.scan_config || {}
  const compliance = scanConfig.compliance_status || {}
  const recommendations = scanConfig.recommendations || {}

  return (
    <div className="space-y-6">
      {/* Header with Download Button */}
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-2xl font-bold text-white flex items-center space-x-2">
          <Shield className="w-8 h-8 text-blue-500" />
          <span>Enterprise Security Assessment Report</span>
        </h2>
        <button
          onClick={downloadReport}
          className="flex items-center space-x-2 px-4 py-2 bg-gradient-to-r from-blue-500 to-purple-600 text-white rounded-lg hover:from-blue-600 hover:to-purple-700 transition-all"
        >
          <Download className="w-4 h-4" />
          <span>Download Report</span>
        </button>
      </div>

      {/* Report Metadata */}
      <div className="bg-gradient-to-br from-gray-800/50 to-gray-900/50 rounded-xl p-6 border border-gray-700/30">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
          <div>
            <p className="text-gray-400">Report ID</p>
            <p className="text-white font-mono">SEC-{scan.id}</p>
          </div>
          <div>
            <p className="text-gray-400">Assessment Date</p>
            <p className="text-white">{new Date(scan.created_at).toLocaleDateString()}</p>
          </div>
          <div>
            <p className="text-gray-400">Repository</p>
            <p className="text-white truncate">{scanConfig.repository_url || scan.project?.repository_url || 'Unknown'}</p>
          </div>
          <div>
            <p className="text-gray-400">Scan Profile</p>
            <p className="text-white">{scanConfig.scan_profile || 'Comprehensive'}</p>
          </div>
        </div>
      </div>

      {/* Executive Summary Section */}
      <div className="bg-gradient-to-br from-gray-800/50 to-gray-900/50 rounded-xl border border-gray-700/30">
        <div
          className="p-6 cursor-pointer flex items-center justify-between"
          onClick={() => toggleSection('executive')}
        >
          <h3 className="text-xl font-semibold text-white flex items-center space-x-2">
            <FileText className="w-6 h-6 text-blue-400" />
            <span>Executive Summary</span>
          </h3>
          {expandedSections.has('executive') ? (
            <ChevronDown className="w-5 h-5 text-gray-400" />
          ) : (
            <ChevronRight className="w-5 h-5 text-gray-400" />
          )}
        </div>
        
        {expandedSections.has('executive') && (
          <div className="px-6 pb-6 space-y-6">
            {/* Risk Overview */}
            <div className="bg-gradient-to-r from-red-500/10 to-orange-500/10 rounded-lg p-4 border border-red-500/20">
              <h4 className="text-white font-semibold mb-3">Overall Security Assessment</h4>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div>
                  <p className="text-sm text-gray-400">Risk Level</p>
                  <p className={`text-2xl font-bold ${getRiskLevelColor(scanConfig.risk_level)}`}>
                    {scanConfig.risk_level || 'UNKNOWN'}
                  </p>
                </div>
                <div>
                  <p className="text-sm text-gray-400">Risk Score</p>
                  <p className="text-2xl font-bold text-white">{scanConfig.risk_score || 0}/100</p>
                </div>
                <div>
                  <p className="text-sm text-gray-400">Total Issues</p>
                  <p className="text-2xl font-bold text-white">{scan.total_issues || 0}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-400">Critical</p>
                  <p className="text-2xl font-bold text-red-400">{scan.critical_issues || 0}</p>
                </div>
              </div>
            </div>

            {/* Business Impact */}
            <div className="bg-gradient-to-r from-yellow-500/10 to-orange-500/10 rounded-lg p-4 border border-yellow-500/20">
              <h4 className="text-white font-semibold mb-3 flex items-center space-x-2">
                <TrendingUp className="w-4 h-4 text-yellow-400" />
                <span>Business Impact Summary</span>
              </h4>
              <div className="space-y-2 text-sm">
                <div className="flex items-center justify-between">
                  <span className="text-gray-300">Data Breach Risk</span>
                  <span className={`font-medium ${scan.critical_issues > 0 ? 'text-red-400' : 'text-green-400'}`}>
                    {scan.critical_issues > 0 ? 'HIGH' : 'LOW'}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-gray-300">Compliance Violations</span>
                  <span className={`font-medium ${scan.high_issues > 5 ? 'text-orange-400' : 'text-green-400'}`}>
                    {scan.high_issues > 5 ? 'MEDIUM' : 'LOW'}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-gray-300">Service Disruption</span>
                  <span className="font-medium text-yellow-400">MEDIUM</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-gray-300">Reputation Damage</span>
                  <span className={`font-medium ${scan.total_issues > 20 ? 'text-orange-400' : 'text-green-400'}`}>
                    {scan.total_issues > 20 ? 'MEDIUM' : 'LOW'}
                  </span>
                </div>
              </div>
            </div>

            {/* Key Metrics */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="bg-gray-800/30 rounded-lg p-4">
                <div className="flex items-center space-x-2 mb-2">
                  <FileCode className="w-4 h-4 text-blue-400" />
                  <span className="text-gray-400 text-sm">Files Analyzed</span>
                </div>
                <p className="text-2xl font-bold text-white">
                  {scanConfig.files_scanned?.toLocaleString() || '0'}
                </p>
              </div>
              <div className="bg-gray-800/30 rounded-lg p-4">
                <div className="flex items-center space-x-2 mb-2">
                  <Code2 className="w-4 h-4 text-green-400" />
                  <span className="text-gray-400 text-sm">Lines Scanned</span>
                </div>
                <p className="text-2xl font-bold text-white">
                  {scanConfig.lines_scanned?.toLocaleString() || '0'}
                </p>
              </div>
              <div className="bg-gray-800/30 rounded-lg p-4">
                <div className="flex items-center space-x-2 mb-2">
                  <Zap className="w-4 h-4 text-purple-400" />
                  <span className="text-gray-400 text-sm">Tools Used</span>
                </div>
                <p className="text-2xl font-bold text-white">
                  {scanConfig.tools_used?.length || 0}
                </p>
              </div>
              <div className="bg-gray-800/30 rounded-lg p-4">
                <div className="flex items-center space-x-2 mb-2">
                  <Clock className="w-4 h-4 text-yellow-400" />
                  <span className="text-gray-400 text-sm">Scan Duration</span>
                </div>
                <p className="text-2xl font-bold text-white">
                  {scanConfig.scan_duration || 'N/A'}
                </p>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Risk Assessment Section */}
      <div className="bg-gradient-to-br from-gray-800/50 to-gray-900/50 rounded-xl border border-gray-700/30">
        <div
          className="p-6 cursor-pointer flex items-center justify-between"
          onClick={() => toggleSection('risk')}
        >
          <h3 className="text-xl font-semibold text-white flex items-center space-x-2">
            <Target className="w-6 h-6 text-red-400" />
            <span>Risk Assessment & Threat Modeling</span>
          </h3>
          {expandedSections.has('risk') ? (
            <ChevronDown className="w-5 h-5 text-gray-400" />
          ) : (
            <ChevronRight className="w-5 h-5 text-gray-400" />
          )}
        </div>
        
        {expandedSections.has('risk') && (
          <div className="px-6 pb-6 space-y-6">
            {/* Risk Matrix */}
            <div className="bg-gray-900/50 rounded-lg p-6">
              <h4 className="text-white font-semibold mb-4">Risk Matrix</h4>
              <div className="grid grid-cols-5 gap-2 text-xs">
                <div className="text-gray-400 text-right pr-2">Critical</div>
                <div className="bg-yellow-500/20 p-2 text-center">Medium</div>
                <div className="bg-orange-500/20 p-2 text-center">High</div>
                <div className="bg-red-500/20 p-2 text-center">Critical</div>
                <div className="bg-red-600/20 p-2 text-center">Critical</div>
                
                <div className="text-gray-400 text-right pr-2">High</div>
                <div className="bg-green-500/20 p-2 text-center">Low</div>
                <div className="bg-yellow-500/20 p-2 text-center">Medium</div>
                <div className="bg-orange-500/20 p-2 text-center">High</div>
                <div className="bg-red-500/20 p-2 text-center">Critical</div>
                
                <div className="text-gray-400 text-right pr-2">Medium</div>
                <div className="bg-green-500/20 p-2 text-center">Low</div>
                <div className="bg-green-500/20 p-2 text-center">Low</div>
                <div className="bg-yellow-500/20 p-2 text-center">Medium</div>
                <div className="bg-orange-500/20 p-2 text-center">High</div>
                
                <div className="text-gray-400 text-right pr-2">Low</div>
                <div className="bg-green-500/20 p-2 text-center">Low</div>
                <div className="bg-green-500/20 p-2 text-center">Low</div>
                <div className="bg-green-500/20 p-2 text-center">Low</div>
                <div className="bg-yellow-500/20 p-2 text-center">Medium</div>
                
                <div></div>
                <div className="text-gray-400 text-center">Low</div>
                <div className="text-gray-400 text-center">Medium</div>
                <div className="text-gray-400 text-center">High</div>
                <div className="text-gray-400 text-center">Critical</div>
                
                <div className="col-span-5 text-center text-gray-400 mt-2">Likelihood →</div>
              </div>
            </div>

            {/* Vulnerability Categories */}
            <div className="bg-gray-900/50 rounded-lg p-6">
              <h4 className="text-white font-semibold mb-4">Vulnerability Distribution by Category</h4>
              <div className="space-y-3">
                {Object.entries(
                  results.reduce((acc: any, r) => {
                    const category = r.category || 'Other'
                    acc[category] = (acc[category] || 0) + 1
                    return acc
                  }, {})
                ).map(([category, count]: [string, any]) => (
                  <div key={category} className="flex items-center justify-between">
                    <span className="text-gray-300">{category}</span>
                    <div className="flex items-center space-x-2">
                      <div className="w-32 bg-gray-700 rounded-full h-2">
                        <div
                          className="bg-gradient-to-r from-blue-500 to-purple-600 h-2 rounded-full"
                          style={{ width: `${(count / results.length) * 100}%` }}
                        />
                      </div>
                      <span className="text-white font-medium w-12 text-right">{count}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* STRIDE Analysis */}
            <div className="bg-gray-900/50 rounded-lg p-6">
              <h4 className="text-white font-semibold mb-4">STRIDE Threat Model Analysis</h4>
              <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
                <div className="flex items-center justify-between p-3 bg-gray-800/50 rounded">
                  <span className="text-gray-300">Spoofing</span>
                  <span className="text-white font-bold">
                    {results.filter(r => r.category?.toLowerCase().includes('auth')).length}
                  </span>
                </div>
                <div className="flex items-center justify-between p-3 bg-gray-800/50 rounded">
                  <span className="text-gray-300">Tampering</span>
                  <span className="text-white font-bold">
                    {results.filter(r => r.category?.toLowerCase().includes('injection')).length}
                  </span>
                </div>
                <div className="flex items-center justify-between p-3 bg-gray-800/50 rounded">
                  <span className="text-gray-300">Repudiation</span>
                  <span className="text-white font-bold">0</span>
                </div>
                <div className="flex items-center justify-between p-3 bg-gray-800/50 rounded">
                  <span className="text-gray-300">Info Disclosure</span>
                  <span className="text-white font-bold">
                    {results.filter(r => r.category?.toLowerCase().includes('exposure') || r.title?.toLowerCase().includes('leak')).length}
                  </span>
                </div>
                <div className="flex items-center justify-between p-3 bg-gray-800/50 rounded">
                  <span className="text-gray-300">Denial of Service</span>
                  <span className="text-white font-bold">
                    {results.filter(r => r.category?.toLowerCase().includes('dos')).length}
                  </span>
                </div>
                <div className="flex items-center justify-between p-3 bg-gray-800/50 rounded">
                  <span className="text-gray-300">Elevation of Privilege</span>
                  <span className="text-white font-bold">
                    {results.filter(r => r.category?.toLowerCase().includes('privilege')).length}
                  </span>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Compliance Assessment Section */}
      <div className="bg-gradient-to-br from-gray-800/50 to-gray-900/50 rounded-xl border border-gray-700/30">
        <div
          className="p-6 cursor-pointer flex items-center justify-between"
          onClick={() => toggleSection('compliance')}
        >
          <h3 className="text-xl font-semibold text-white flex items-center space-x-2">
            <Award className="w-6 h-6 text-purple-400" />
            <span>Compliance & Standards Mapping</span>
          </h3>
          {expandedSections.has('compliance') ? (
            <ChevronDown className="w-5 h-5 text-gray-400" />
          ) : (
            <ChevronRight className="w-5 h-5 text-gray-400" />
          )}
        </div>
        
        {expandedSections.has('compliance') && (
          <div className="px-6 pb-6 space-y-6">
            {/* OWASP Top 10 Mapping */}
            <div className="bg-gray-900/50 rounded-lg p-6">
              <h4 className="text-white font-semibold mb-4">OWASP Top 10 (2021) Coverage</h4>
              <div className="space-y-2">
                {[
                  { id: 'A01', name: 'Broken Access Control', count: results.filter(r => r.owasp_category?.includes('A01')).length },
                  { id: 'A02', name: 'Cryptographic Failures', count: results.filter(r => r.owasp_category?.includes('A02')).length },
                  { id: 'A03', name: 'Injection', count: results.filter(r => r.owasp_category?.includes('A03')).length },
                  { id: 'A04', name: 'Insecure Design', count: results.filter(r => r.owasp_category?.includes('A04')).length },
                  { id: 'A05', name: 'Security Misconfiguration', count: results.filter(r => r.owasp_category?.includes('A05')).length },
                  { id: 'A06', name: 'Vulnerable Components', count: results.filter(r => r.owasp_category?.includes('A06')).length },
                  { id: 'A07', name: 'Auth Failures', count: results.filter(r => r.owasp_category?.includes('A07')).length },
                  { id: 'A08', name: 'Software & Data Integrity', count: results.filter(r => r.owasp_category?.includes('A08')).length },
                  { id: 'A09', name: 'Security Logging Failures', count: results.filter(r => r.owasp_category?.includes('A09')).length },
                  { id: 'A10', name: 'Server-Side Request Forgery', count: results.filter(r => r.owasp_category?.includes('A10')).length }
                ].map(item => (
                  <div key={item.id} className="flex items-center justify-between p-2 hover:bg-gray-800/30 rounded">
                    <div className="flex items-center space-x-3">
                      <span className="text-gray-400 font-mono text-sm">{item.id}</span>
                      <span className="text-gray-300">{item.name}</span>
                    </div>
                    <span className={`font-bold ${item.count > 0 ? 'text-red-400' : 'text-green-400'}`}>
                      {item.count}
                    </span>
                  </div>
                ))}
              </div>
            </div>

            {/* Compliance Status */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="bg-gray-900/50 rounded-lg p-4">
                <h5 className="text-gray-400 text-sm mb-2">PCI-DSS</h5>
                <div className="flex items-center space-x-2">
                  {scan.critical_issues > 0 ? (
                    <XCircle className="w-5 h-5 text-red-400" />
                  ) : (
                    <CheckCircle className="w-5 h-5 text-green-400" />
                  )}
                  <span className={scan.critical_issues > 0 ? 'text-red-400' : 'text-green-400'}>
                    {scan.critical_issues > 0 ? 'Non-Compliant' : 'Compliant'}
                  </span>
                </div>
              </div>
              <div className="bg-gray-900/50 rounded-lg p-4">
                <h5 className="text-gray-400 text-sm mb-2">GDPR</h5>
                <div className="flex items-center space-x-2">
                  <AlertTriangle className="w-5 h-5 text-yellow-400" />
                  <span className="text-yellow-400">Review Required</span>
                </div>
              </div>
              <div className="bg-gray-900/50 rounded-lg p-4">
                <h5 className="text-gray-400 text-sm mb-2">SOC 2</h5>
                <div className="flex items-center space-x-2">
                  {scan.high_issues > 5 ? (
                    <XCircle className="w-5 h-5 text-red-400" />
                  ) : (
                    <CheckCircle className="w-5 h-5 text-green-400" />
                  )}
                  <span className={scan.high_issues > 5 ? 'text-red-400' : 'text-green-400'}>
                    {scan.high_issues > 5 ? 'Gaps Found' : 'Compliant'}
                  </span>
                </div>
              </div>
              <div className="bg-gray-900/50 rounded-lg p-4">
                <h5 className="text-gray-400 text-sm mb-2">ISO 27001</h5>
                <div className="flex items-center space-x-2">
                  <AlertTriangle className="w-5 h-5 text-yellow-400" />
                  <span className="text-yellow-400">Partial</span>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Remediation Roadmap Section */}
      <div className="bg-gradient-to-br from-gray-800/50 to-gray-900/50 rounded-xl border border-gray-700/30">
        <div
          className="p-6 cursor-pointer flex items-center justify-between"
          onClick={() => toggleSection('remediation')}
        >
          <h3 className="text-xl font-semibold text-white flex items-center space-x-2">
            <BookOpen className="w-6 h-6 text-green-400" />
            <span>Remediation Roadmap</span>
          </h3>
          {expandedSections.has('remediation') ? (
            <ChevronDown className="w-5 h-5 text-gray-400" />
          ) : (
            <ChevronRight className="w-5 h-5 text-gray-400" />
          )}
        </div>
        
        {expandedSections.has('remediation') && (
          <div className="px-6 pb-6 space-y-6">
            {/* Immediate Actions */}
            {scan.critical_issues > 0 && (
              <div className="bg-gradient-to-r from-red-500/10 to-red-600/10 rounded-lg p-4 border border-red-500/20">
                <h4 className="text-white font-semibold mb-3 flex items-center space-x-2">
                  <AlertOctagon className="w-5 h-5 text-red-400" />
                  <span>Immediate Actions (0-48 hours)</span>
                </h4>
                <ul className="space-y-2 text-sm text-gray-300">
                  <li className="flex items-start space-x-2">
                    <span className="text-red-400">•</span>
                    <span>Address all {scan.critical_issues} CRITICAL vulnerabilities immediately</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <span className="text-red-400">•</span>
                    <span>Implement emergency patches for exposed secrets and credentials</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <span className="text-red-400">•</span>
                    <span>Enable security monitoring and alerting</span>
                  </li>
                </ul>
              </div>
            )}

            {/* Short-term Actions */}
            <div className="bg-gradient-to-r from-orange-500/10 to-orange-600/10 rounded-lg p-4 border border-orange-500/20">
              <h4 className="text-white font-semibold mb-3 flex items-center space-x-2">
                <Clock className="w-5 h-5 text-orange-400" />
                <span>Short-term Actions (1 week)</span>
              </h4>
              <ul className="space-y-2 text-sm text-gray-300">
                <li className="flex items-start space-x-2">
                  <span className="text-orange-400">•</span>
                  <span>Fix all {scan.high_issues} HIGH severity vulnerabilities</span>
                </li>
                <li className="flex items-start space-x-2">
                  <span className="text-orange-400">•</span>
                  <span>Implement security headers and CSP policies</span>
                </li>
                <li className="flex items-start space-x-2">
                  <span className="text-orange-400">•</span>
                  <span>Enable rate limiting and DDoS protection</span>
                </li>
                <li className="flex items-start space-x-2">
                  <span className="text-orange-400">•</span>
                  <span>Review and update authentication mechanisms</span>
                </li>
              </ul>
            </div>

            {/* Medium-term Actions */}
            <div className="bg-gradient-to-r from-yellow-500/10 to-yellow-600/10 rounded-lg p-4 border border-yellow-500/20">
              <h4 className="text-white font-semibold mb-3 flex items-center space-x-2">
                <Target className="w-5 h-5 text-yellow-400" />
                <span>Medium-term Actions (1 month)</span>
              </h4>
              <ul className="space-y-2 text-sm text-gray-300">
                <li className="flex items-start space-x-2">
                  <span className="text-yellow-400">•</span>
                  <span>Address all {scan.medium_issues} MEDIUM severity issues</span>
                </li>
                <li className="flex items-start space-x-2">
                  <span className="text-yellow-400">•</span>
                  <span>Implement comprehensive logging and monitoring</span>
                </li>
                <li className="flex items-start space-x-2">
                  <span className="text-yellow-400">•</span>
                  <span>Conduct security awareness training for development team</span>
                </li>
                <li className="flex items-start space-x-2">
                  <span className="text-yellow-400">•</span>
                  <span>Establish secure coding guidelines and review process</span>
                </li>
              </ul>
            </div>

            {/* Long-term Strategy */}
            <div className="bg-gradient-to-r from-green-500/10 to-green-600/10 rounded-lg p-4 border border-green-500/20">
              <h4 className="text-white font-semibold mb-3 flex items-center space-x-2">
                <TrendingUp className="w-5 h-5 text-green-400" />
                <span>Long-term Security Strategy</span>
              </h4>
              <ul className="space-y-2 text-sm text-gray-300">
                <li className="flex items-start space-x-2">
                  <span className="text-green-400">•</span>
                  <span>Implement DevSecOps practices and shift-left security</span>
                </li>
                <li className="flex items-start space-x-2">
                  <span className="text-green-400">•</span>
                  <span>Establish continuous security monitoring and scanning</span>
                </li>
                <li className="flex items-start space-x-2">
                  <span className="text-green-400">•</span>
                  <span>Regular security assessments and penetration testing</span>
                </li>
                <li className="flex items-start space-x-2">
                  <span className="text-green-400">•</span>
                  <span>Maintain security incident response plan</span>
                </li>
              </ul>
            </div>
          </div>
        )}
      </div>

      {/* Security Tools Used */}
      {scanConfig.tools_used && scanConfig.tools_used.length > 0 && (
        <div className="bg-gradient-to-br from-gray-800/50 to-gray-900/50 rounded-xl p-6 border border-gray-700/30">
          <h3 className="text-xl font-semibold text-white mb-4 flex items-center space-x-2">
            <Zap className="w-6 h-6 text-purple-400" />
            <span>Security Tools Used</span>
          </h3>
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-3">
            {scanConfig.tools_used.map((tool: string, index: number) => (
              <div key={index} className="bg-gray-800/30 px-3 py-2 rounded text-sm text-gray-300 flex items-center space-x-2">
                <CheckCircle className="w-4 h-4 text-green-400" />
                <span>{tool}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}