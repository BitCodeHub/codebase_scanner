import { useState, useEffect } from 'react'
import { useParams, Link } from 'react-router-dom'
import { db } from '../lib/supabase-proxy'
import {
  Shield,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Info,
  Code2,
  FileCode,
  GitBranch,
  Clock,
  ChevronRight,
  ChevronDown,
  Bug,
  Lock,
  Eye,
  Copy,
  Download,
  RefreshCw,
  ArrowLeft,
  Sparkles,
  TrendingUp,
  Activity,
  BarChart3,
  Loader2,
  ExternalLink,
  Terminal,
  Zap
} from 'lucide-react'
import LoadingSpinner from '../components/ui/LoadingSpinner'
import Prism from 'prismjs'
import 'prismjs/themes/prism-tomorrow.css'
import 'prismjs/components/prism-javascript'
import 'prismjs/components/prism-typescript'
import 'prismjs/components/prism-jsx'
import 'prismjs/components/prism-tsx'
import 'prismjs/components/prism-python'
import 'prismjs/components/prism-java'

interface ScanResult {
  id: string
  severity: string
  title: string
  description?: string
  file_path: string
  line_number?: number
  code_snippet?: string
  rule_id?: string
  owasp_category?: string
  fix_recommendation?: string
  cvss_score?: number
  confidence?: string
  vulnerability_type?: string
}

interface Scan {
  id: string
  status: string
  created_at: string
  completed_at?: string
  total_issues: number
  critical_issues: number
  high_issues: number
  medium_issues: number
  low_issues: number
  ai_insights?: any
  scan_config?: {
    scan_id?: string
    tools_used?: string[]
    repository_url?: string
    scan_profile?: string
    files_scanned?: number
    lines_scanned?: number
    risk_score?: number
    risk_level?: string
    scan_duration?: string
    executive_summary?: string
  }
  project?: {
    name: string
    repository_url?: string
  }
}

export default function ModernScanResults() {
  const { id } = useParams<{ id: string }>()
  const [scan, setScan] = useState<Scan | null>(null)
  const [results, setResults] = useState<ScanResult[]>([])
  const [loading, setLoading] = useState(true)
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all')
  const [expandedResults, setExpandedResults] = useState<Set<string>>(new Set())
  const [searchQuery, setSearchQuery] = useState('')
  const [refreshing, setRefreshing] = useState(false)
  const [retryCount, setRetryCount] = useState(0)
  const [retryTimer, setRetryTimer] = useState<NodeJS.Timeout | null>(null)
  const [autoRefreshInterval, setAutoRefreshInterval] = useState<NodeJS.Timeout | null>(null)

  useEffect(() => {
    if (id) {
      loadScanData(true) // Initial load
    }
    
    // Cleanup function to clear any pending timers
    return () => {
      if (retryTimer) {
        clearTimeout(retryTimer)
      }
      if (autoRefreshInterval) {
        clearInterval(autoRefreshInterval)
      }
    }
  }, [id])

  useEffect(() => {
    // Syntax highlighting for code snippets
    Prism.highlightAll()
  }, [results])

  const loadScanData = async (isInitialLoad = false) => {
    if (!id || refreshing) return // Prevent duplicate loads

    try {
      // Only show loading spinner on initial load, not on refresh
      if (isInitialLoad && !scan) {
        setLoading(true)
      }
      console.log(`Loading scan data for ID: ${id}`)
      
      // Load scan details
      const { data: scanData, error: scanError } = await db.scans.get(parseInt(id))
      console.log('Scan query result:', { scanData, scanError })
      
      if (scanError || !scanData) {
        console.error('Error loading scan:', scanError)
        
        // Check if this is a permanent error (scan doesn't exist)
        const isNotFound = scanError?.message?.includes('not found') || 
                          scanError?.code === 'PGRST116' // Supabase not found error
        
        if (isNotFound) {
          console.log('Scan definitively not found, stopping retries')
          setScan(null)
          setLoading(false)
          return
        }
        
        // Only retry for temporary errors (network issues, etc)
        if (retryCount < 3 && !isNotFound) {
          console.log(`Retrying scan load (attempt ${retryCount + 1}/3)...`)
          setRetryCount(prev => prev + 1)
          const timer = setTimeout(() => {
            loadScanData()
          }, (retryCount + 1) * 1000) // 1s, 2s, 3s delays
          setRetryTimer(timer)
          return
        }
        
        setScan(null)
        setLoading(false)
        return
      }

      // Load project details
      if (scanData.project_id) {
        const { data: projectData } = await db.projects.get(scanData.project_id)
        if (projectData) {
          scanData.project = projectData
        }
      }

      // Reset retry count and clear any pending timers on successful load
      setRetryCount(0)
      if (retryTimer) {
        clearTimeout(retryTimer)
        setRetryTimer(null)
      }
      
      setScan(scanData as Scan)
      console.log('Loaded scan data:', scanData)

      // Load scan results
      const { getSupabase } = await import('../lib/supabase-safe')
      const supabase = await getSupabase()
      console.log('Loading scan results for scan_id:', parseInt(id))
      
      const { data: resultsData, error: resultsError } = await supabase
        .from('scan_results')
        .select('*')
        .eq('scan_id', parseInt(id))

      if (resultsError) {
        console.error('Error loading scan results:', resultsError)
      } else {
        console.log('Loaded scan results:', resultsData)
        // Sort results by severity on client side
        const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 }
        const sortedResults = (resultsData || []).sort((a, b) => {
          const aSeverity = severityOrder[a.severity] ?? 4
          const bSeverity = severityOrder[b.severity] ?? 4
          return aSeverity - bSeverity
        })
        setResults(sortedResults)
      }

      // Auto-refresh for running scans only - prevent flickering
      if (scanData.status === 'running') {
        console.log('Scan is running, setting up auto-refresh...')
        // Clear any existing interval first
        if (autoRefreshInterval) {
          clearInterval(autoRefreshInterval)
        }
        
        const interval = setInterval(() => {
          console.log('Auto-refreshing running scan...')
          // Only refresh if not already refreshing to prevent overlap
          if (!refreshing) {
            handleRefresh()
          }
        }, 10000) // 10 seconds to reduce flickering
        setAutoRefreshInterval(interval)
      } else {
        // Clear interval for completed scans
        if (autoRefreshInterval) {
          clearInterval(autoRefreshInterval)
          setAutoRefreshInterval(null)
        }
      }
    } catch (error) {
      console.error('Error in loadScanData:', error)
    } finally {
      setLoading(false)
    }
  }

  const handleRefresh = async () => {
    if (refreshing) return // Prevent multiple refreshes
    setRefreshing(true)
    try {
      await loadScanData() // Refresh - not initial load
    } finally {
      setRefreshing(false)
    }
  }

  const toggleResult = (resultId: string) => {
    const newExpanded = new Set(expandedResults)
    if (newExpanded.has(resultId)) {
      newExpanded.delete(resultId)
    } else {
      newExpanded.add(resultId)
    }
    setExpandedResults(newExpanded)
  }

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
    showNotification('success', 'Copied to clipboard')
  }

  const showNotification = (type: 'success' | 'error', message: string) => {
    const notificationDiv = document.createElement('div')
    notificationDiv.className = `fixed bottom-4 right-4 ${
      type === 'success' ? 'bg-green-500' : 'bg-red-500'
    } text-white px-6 py-3 rounded-lg shadow-lg flex items-center space-x-2 animate-slide-up z-50`
    notificationDiv.innerHTML = `
      ${type === 'success' 
        ? '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path></svg>'
        : '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>'
      }
      <span>${message}</span>
    `
    document.body.appendChild(notificationDiv)
    setTimeout(() => notificationDiv.remove(), 3000)
  }

  const renderExecutiveSummary = (summary: string) => {
    // Parse the executive summary and organize it into professional sections
    const keyFindings = summary.match(/KEY FINDINGS:(.+?)(?=SECURITY POSTURE:|$)/s)?.[1]?.trim()
    const securityPosture = summary.match(/SECURITY POSTURE:(.+?)(?=BUSINESS IMPACT:|$)/s)?.[1]?.trim()
    const businessImpact = summary.match(/BUSINESS IMPACT:(.+?)(?=Tool Success Rate:|$)/s)?.[1]?.trim()
    
    // Extract metrics
    const riskLevel = summary.match(/Risk Level: (\w+)/)?.[1]
    const issuesCount = summary.match(/(\d+) total security vulnerabilities/)?.[1]
    const criticalIssues = summary.match(/(\d+) CRITICAL issues/)?.[1]
    const highIssues = summary.match(/(\d+) HIGH severity issues/)?.[1]
    const filesScanned = summary.match(/(\d+,?\d*) files/)?.[1]
    const linesScanned = summary.match(/(\d+,?\d*) lines of code/)?.[1]
    
    return (
      <div className="space-y-6">
        {/* Risk Assessment */}
        <div className="bg-gradient-to-r from-red-500/10 to-orange-500/10 rounded-lg p-4 border border-red-500/20">
          <h4 className="text-white font-semibold mb-3 flex items-center space-x-2">
            <AlertTriangle className="w-4 h-4 text-red-400" />
            <span>Risk Assessment</span>
          </h4>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
            {riskLevel && (
              <div>
                <p className="text-gray-400">Risk Level</p>
                <p className={`font-bold ${
                  riskLevel === 'CRITICAL' ? 'text-red-400' :
                  riskLevel === 'HIGH' ? 'text-orange-400' :
                  riskLevel === 'MEDIUM' ? 'text-yellow-400' :
                  'text-green-400'
                }`}>{riskLevel}</p>
              </div>
            )}
            {issuesCount && (
              <div>
                <p className="text-gray-400">Total Issues</p>
                <p className="text-white font-bold">{issuesCount}</p>
              </div>
            )}
            {criticalIssues && parseInt(criticalIssues) > 0 && (
              <div>
                <p className="text-gray-400">Critical</p>
                <p className="text-red-400 font-bold">{criticalIssues}</p>
              </div>
            )}
            {highIssues && parseInt(highIssues) > 0 && (
              <div>
                <p className="text-gray-400">High</p>
                <p className="text-orange-400 font-bold">{highIssues}</p>
              </div>
            )}
          </div>
        </div>

        {/* Key Findings */}
        {keyFindings && (
          <div className="bg-gradient-to-r from-purple-500/10 to-blue-500/10 rounded-lg p-4 border border-purple-500/20">
            <h4 className="text-white font-semibold mb-3 flex items-center space-x-2">
              <Bug className="w-4 h-4 text-purple-400" />
              <span>Key Security Findings</span>
            </h4>
            <div className="text-gray-300 text-sm leading-relaxed">
              {keyFindings.split('•').filter(item => item.trim()).map((finding, index) => (
                <div key={index} className="flex items-start space-x-2 mb-2">
                  <div className="w-2 h-2 bg-purple-400 rounded-full mt-2 flex-shrink-0"></div>
                  <span>{finding.trim()}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Security Posture */}
        {securityPosture && (
          <div className="bg-gradient-to-r from-blue-500/10 to-cyan-500/10 rounded-lg p-4 border border-blue-500/20">
            <h4 className="text-white font-semibold mb-3 flex items-center space-x-2">
              <Shield className="w-4 h-4 text-blue-400" />
              <span>Security Posture</span>
            </h4>
            <p className="text-gray-300 text-sm leading-relaxed">{securityPosture}</p>
          </div>
        )}

        {/* Business Impact */}
        {businessImpact && (
          <div className="bg-gradient-to-r from-amber-500/10 to-orange-500/10 rounded-lg p-4 border border-amber-500/20">
            <h4 className="text-white font-semibold mb-3 flex items-center space-x-2">
              <TrendingUp className="w-4 h-4 text-amber-400" />
              <span>Business Impact</span>
            </h4>
            <p className="text-gray-300 text-sm leading-relaxed">{businessImpact}</p>
          </div>
        )}

        {/* Scan Coverage */}
        {(filesScanned || linesScanned) && (
          <div className="bg-gradient-to-r from-green-500/10 to-teal-500/10 rounded-lg p-4 border border-green-500/20">
            <h4 className="text-white font-semibold mb-3 flex items-center space-x-2">
              <FileCode className="w-4 h-4 text-green-400" />
              <span>Scan Coverage</span>
            </h4>
            <div className="grid grid-cols-2 gap-4 text-sm">
              {filesScanned && (
                <div>
                  <p className="text-gray-400">Files Analyzed</p>
                  <p className="text-white font-bold">{filesScanned}</p>
                </div>
              )}
              {linesScanned && (
                <div>
                  <p className="text-gray-400">Lines Scanned</p>
                  <p className="text-white font-bold">{linesScanned}</p>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Fallback for unstructured summary */}
        {!keyFindings && !securityPosture && !businessImpact && (
          <div className="bg-gradient-to-r from-gray-500/10 to-gray-600/10 rounded-lg p-4 border border-gray-500/20">
            <h4 className="text-white font-semibold mb-3 flex items-center space-x-2">
              <FileCode className="w-4 h-4 text-gray-400" />
              <span>Executive Summary</span>
            </h4>
            <p className="text-gray-300 text-sm leading-relaxed">{summary}</p>
          </div>
        )}
      </div>
    )
  }

  const getSeverityConfig = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return { 
          color: 'bg-red-100 text-red-800 border-red-200', 
          bgGradient: 'from-red-500/20 to-red-600/20',
          icon: XCircle,
          label: 'Critical'
        }
      case 'high':
        return { 
          color: 'bg-orange-100 text-orange-800 border-orange-200', 
          bgGradient: 'from-orange-500/20 to-orange-600/20',
          icon: AlertTriangle,
          label: 'High'
        }
      case 'medium':
        return { 
          color: 'bg-yellow-100 text-yellow-800 border-yellow-200', 
          bgGradient: 'from-yellow-500/20 to-yellow-600/20',
          icon: AlertTriangle,
          label: 'Medium'
        }
      case 'low':
        return { 
          color: 'bg-blue-100 text-blue-800 border-blue-200', 
          bgGradient: 'from-blue-500/20 to-blue-600/20',
          icon: Info,
          label: 'Low'
        }
      default:
        return { 
          color: 'bg-gray-100 text-gray-800 border-gray-200', 
          bgGradient: 'from-gray-500/20 to-gray-600/20',
          icon: Info,
          label: 'Info'
        }
    }
  }

  const getStatusConfig = (status: string) => {
    switch (status) {
      case 'completed':
        return { color: 'text-green-400', icon: CheckCircle, label: 'Completed' }
      case 'running':
        return { color: 'text-blue-400', icon: Loader2, label: 'Running', animate: true }
      case 'failed':
        return { color: 'text-red-400', icon: XCircle, label: 'Failed' }
      default:
        return { color: 'text-gray-400', icon: Clock, label: 'Pending' }
    }
  }

  const filteredResults = results.filter(result => {
    const matchesSeverity = selectedSeverity === 'all' || result.severity === selectedSeverity
    const matchesSearch = !searchQuery || 
      result.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      result.file_path.toLowerCase().includes(searchQuery.toLowerCase()) ||
      result.description?.toLowerCase().includes(searchQuery.toLowerCase())
    
    return matchesSeverity && matchesSearch
  })

  if (loading && !scan) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900 flex items-center justify-center">
        <div className="text-center">
          <div className="relative">
            <div className="w-24 h-24 rounded-full bg-gradient-to-r from-blue-500 to-purple-600 animate-pulse"></div>
            <Shield className="w-12 h-12 text-white absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2" />
          </div>
          <p className="mt-6 text-gray-300 text-lg">Initializing security dashboard...</p>
        </div>
      </div>
    )
  }

  if (!scan) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900 flex items-center justify-center">
        <div className="text-center max-w-md">
          <XCircle className="w-16 h-16 text-red-400 mx-auto mb-4" />
          <h2 className="text-2xl font-semibold text-white mb-2">Scan not found</h2>
          <p className="text-gray-400 mb-2">The scan with ID #{id} could not be found.</p>
          <p className="text-gray-500 text-sm mb-6">This might happen if the scan is still being processed. Please try again in a few seconds.</p>
          <div className="flex flex-col sm:flex-row gap-3 justify-center">
            <button
              onClick={() => {
                // Clear any pending retry timers
                if (retryTimer) {
                  clearTimeout(retryTimer)
                  setRetryTimer(null)
                }
                setRetryCount(0)
                setScan(null)
                setResults([])
                setLoading(true)
                loadScanData(true) // Manual retry - treat as initial
              }}
              className="inline-flex items-center space-x-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"
            >
              <RefreshCw className="w-4 h-4" />
              <span>Try Again</span>
            </button>
            <Link
              to="/dashboard"
              className="inline-flex items-center space-x-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors"
            >
              <ArrowLeft className="w-4 h-4" />
              <span>Back to Dashboard</span>
            </Link>
          </div>
        </div>
      </div>
    )
  }

  const statusConfig = getStatusConfig(scan.status)
  const StatusIcon = statusConfig.icon

  // Special UI for running enterprise scans
  if (scan.status === 'running') {
    return (
      <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900 flex items-center justify-center">
        <div className="text-center max-w-2xl mx-auto px-8">
          <div className="relative mb-8">
            <div className="w-32 h-32 rounded-full bg-gradient-to-r from-blue-500 to-purple-600 animate-pulse mx-auto"></div>
            <Shield className="w-16 h-16 text-white absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2" />
          </div>
          
          <h2 className="text-3xl font-bold text-white mb-4">🔒 Enterprise Security Scan in Progress</h2>
          
          <div className="bg-gray-800/50 backdrop-blur-xl rounded-2xl p-6 mb-6">
            <p className="text-gray-300 mb-4">Running comprehensive analysis with all 15 professional security tools:</p>
            
            <div className="grid grid-cols-3 gap-3 text-sm text-gray-400 mb-6">
              <div>• Semgrep</div>
              <div>• Bandit</div>
              <div>• Gitleaks</div>
              <div>• TruffleHog</div>
              <div>• Safety</div>
              <div>• Retire.js</div>
              <div>• JADX</div>
              <div>• APKLeaks</div>
              <div>• QARK</div>
              <div>• ESLint Security</div>
              <div>• njsscan</div>
              <div>• Checkov</div>
              <div>• tfsec</div>
              <div>• OWASP Check</div>
              <div>• detect-secrets</div>
            </div>
            
            <div className="flex items-center justify-center space-x-2">
              <Loader2 className="w-6 h-6 text-blue-400 animate-spin" />
              <p className="text-gray-300">This comprehensive scan typically takes 3-5 minutes...</p>
            </div>
          </div>
          
          <div className="text-gray-400 text-sm">
            <p>Scan ID: #{scan.id}</p>
            <p>Started: {new Date(scan.created_at).toLocaleString()}</p>
            <p className="mt-2">
              {refreshing ? (
                <span className="flex items-center justify-center space-x-2">
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  <span>Checking for updates...</span>
                </span>
              ) : (
                "Page auto-refreshes every 10 seconds"
              )}
            </p>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900">
      {/* Animated background */}
      <div className="fixed inset-0 overflow-hidden pointer-events-none">
        <div className="absolute -top-40 -right-40 w-80 h-80 bg-purple-500 rounded-full mix-blend-multiply filter blur-3xl opacity-10 animate-blob"></div>
        <div className="absolute -bottom-40 -left-40 w-80 h-80 bg-blue-500 rounded-full mix-blend-multiply filter blur-3xl opacity-10 animate-blob animation-delay-2000"></div>
        <div className="absolute top-40 left-40 w-80 h-80 bg-indigo-500 rounded-full mix-blend-multiply filter blur-3xl opacity-10 animate-blob animation-delay-4000"></div>
      </div>

      {/* Header */}
      <header className="relative backdrop-blur-xl bg-gray-900/70 border-b border-gray-700/50 sticky top-0 z-40">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center space-x-4">
              <Link
                to="/dashboard"
                className="p-2 hover:bg-gray-800 rounded-lg transition-colors"
              >
                <ArrowLeft className="w-5 h-5 text-gray-300" />
              </Link>
              <div>
                <h1 className="text-xl font-bold text-white">Scan Results</h1>
                {scan.project && (
                  <p className="text-sm text-gray-400">{scan.project.name}</p>
                )}
              </div>
            </div>

            <div className="flex items-center space-x-3">
              <button
                onClick={handleRefresh}
                disabled={refreshing}
                className="p-2 hover:bg-gray-800 rounded-lg transition-colors disabled:opacity-50"
              >
                <RefreshCw className={`w-5 h-5 text-gray-300 ${refreshing ? 'animate-spin' : ''}`} />
              </button>
              
              <button className="p-2 hover:bg-gray-800 rounded-lg transition-colors">
                <Download className="w-5 h-5 text-gray-300" />
              </button>
            </div>
          </div>
        </div>
      </header>

      {/* Main content */}
      <main className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Scan summary */}
        <div className="bg-gradient-to-br from-gray-800/50 to-gray-900/50 backdrop-blur-xl rounded-2xl border border-gray-700/50 p-8 mb-8">
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center space-x-4">
              <div className="p-3 bg-gradient-to-r from-blue-500/20 to-purple-600/20 rounded-xl">
                <Shield className="w-8 h-8 text-blue-400" />
              </div>
              <div>
                <h2 className="text-2xl font-bold text-white">Security Scan #{scan.id}</h2>
                <div className="flex items-center space-x-4 mt-2">
                  <div className={`flex items-center space-x-2 ${statusConfig.color}`}>
                    <StatusIcon className={`w-5 h-5 ${statusConfig.animate ? 'animate-spin' : ''}`} />
                    <span className="font-medium">{statusConfig.label}</span>
                  </div>
                  <div className="flex items-center space-x-2 text-gray-400">
                    <Clock className="w-4 h-4" />
                    <span className="text-sm">
                      {new Date(scan.created_at).toLocaleString()}
                    </span>
                  </div>
                </div>
              </div>
            </div>

            {scan.project?.repository_url && (
              <a
                href={scan.project.repository_url}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center space-x-2 px-4 py-2 bg-gray-700/50 hover:bg-gray-700 text-gray-300 hover:text-white rounded-lg transition-all"
              >
                <GitBranch className="w-4 h-4" />
                <span>View Repository</span>
                <ExternalLink className="w-4 h-4" />
              </a>
            )}
          </div>

          {/* Stats grid */}
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
            <div className="bg-gray-900/50 rounded-xl p-4">
              <div className="flex items-center justify-between mb-2">
                <span className="text-gray-400 text-sm">Total</span>
                <Bug className="w-4 h-4 text-gray-500" />
              </div>
              <p className="text-2xl font-bold text-white">{scan.total_issues}</p>
            </div>

            <div className="bg-gradient-to-br from-red-500/20 to-red-600/20 rounded-xl p-4 border border-red-500/20">
              <div className="flex items-center justify-between mb-2">
                <span className="text-red-400 text-sm">Critical</span>
                <XCircle className="w-4 h-4 text-red-400" />
              </div>
              <p className="text-2xl font-bold text-red-400">{scan.critical_issues}</p>
            </div>

            <div className="bg-gradient-to-br from-orange-500/20 to-orange-600/20 rounded-xl p-4 border border-orange-500/20">
              <div className="flex items-center justify-between mb-2">
                <span className="text-orange-400 text-sm">High</span>
                <AlertTriangle className="w-4 h-4 text-orange-400" />
              </div>
              <p className="text-2xl font-bold text-orange-400">{scan.high_issues}</p>
            </div>

            <div className="bg-gradient-to-br from-yellow-500/20 to-yellow-600/20 rounded-xl p-4 border border-yellow-500/20">
              <div className="flex items-center justify-between mb-2">
                <span className="text-yellow-400 text-sm">Medium</span>
                <AlertTriangle className="w-4 h-4 text-yellow-400" />
              </div>
              <p className="text-2xl font-bold text-yellow-400">{scan.medium_issues}</p>
            </div>

            <div className="bg-gradient-to-br from-blue-500/20 to-blue-600/20 rounded-xl p-4 border border-blue-500/20">
              <div className="flex items-center justify-between mb-2">
                <span className="text-blue-400 text-sm">Low</span>
                <Info className="w-4 h-4 text-blue-400" />
              </div>
              <p className="text-2xl font-bold text-blue-400">{scan.low_issues}</p>
            </div>
          </div>

          {/* Enterprise Scan Info */}
          {scan.scan_config && (
            <div className="mt-6 p-4 bg-gradient-to-r from-blue-500/10 to-purple-500/10 rounded-xl border border-blue-500/20">
              <div className="flex items-center space-x-2 mb-3">
                <Shield className="w-5 h-5 text-blue-400" />
                <h3 className="text-lg font-semibold text-white">🔒 Enterprise Security Analysis</h3>
              </div>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                {scan.scan_config.risk_score !== undefined && (
                  <div>
                    <p className="text-gray-400">Risk Score</p>
                    <p className="text-xl font-bold text-white">{scan.scan_config.risk_score}/100</p>
                  </div>
                )}
                {scan.scan_config.risk_level && (
                  <div>
                    <p className="text-gray-400">Risk Level</p>
                    <p className={`text-xl font-bold ${
                      scan.scan_config.risk_level === 'CRITICAL' ? 'text-red-400' :
                      scan.scan_config.risk_level === 'HIGH' ? 'text-orange-400' :
                      scan.scan_config.risk_level === 'MEDIUM' ? 'text-yellow-400' :
                      'text-green-400'
                    }`}>{scan.scan_config.risk_level}</p>
                  </div>
                )}
                {scan.scan_config.files_scanned && (
                  <div>
                    <p className="text-gray-400">Files Analyzed</p>
                    <p className="text-xl font-bold text-white">{scan.scan_config.files_scanned.toLocaleString()}</p>
                  </div>
                )}
                {scan.scan_config.lines_scanned && (
                  <div>
                    <p className="text-gray-400">Lines Scanned</p>
                    <p className="text-xl font-bold text-white">{scan.scan_config.lines_scanned.toLocaleString()}</p>
                  </div>
                )}
              </div>
              {scan.scan_config.tools_used && scan.scan_config.tools_used.length > 0 && (
                <div className="mt-4">
                  <p className="text-gray-400 text-sm mb-2">Security Tools Used ({scan.scan_config.tools_used.length}):</p>
                  <div className="flex flex-wrap gap-2">
                    {scan.scan_config.tools_used.map((tool: string, index: number) => (
                      <span key={index} className="text-xs px-2 py-1 bg-gray-800/50 text-gray-300 rounded">
                        {tool}
                      </span>
                    ))}
                  </div>
                </div>
              )}
              {scan.scan_config.executive_summary && (
                <div className="mt-6">
                  <h3 className="text-lg font-semibold text-white mb-4 flex items-center space-x-2">
                    <BarChart3 className="w-5 h-5" />
                    <span>Executive Security Assessment</span>
                  </h3>
                  <div className="bg-gradient-to-br from-gray-800/30 to-gray-900/30 rounded-xl p-6 border border-gray-700/30">
                    {renderExecutiveSummary(scan.scan_config.executive_summary)}
                  </div>
                </div>              )}
            </div>
          )}

          {/* AI Insights */}
          {scan.ai_insights && (
            <div className="mt-6 p-4 bg-gradient-to-r from-purple-500/10 to-blue-500/10 rounded-xl border border-purple-500/20">
              <div className="flex items-center space-x-2 mb-3">
                <Sparkles className="w-5 h-5 text-purple-400" />
                <h3 className="text-lg font-semibold text-white">AI Security Insights</h3>
              </div>
              <p className="text-gray-300 leading-relaxed">
                {scan.ai_insights.summary || 'AI analysis pending...'}
              </p>
            </div>
          )}
        </div>

        {/* Filters */}
        <div className="flex flex-col sm:flex-row gap-4 mb-6">
          <div className="flex-1 relative">
            <input
              type="text"
              placeholder="Search vulnerabilities..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-10 pr-4 py-3 bg-gray-800/50 backdrop-blur-xl border border-gray-700/50 rounded-xl text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500/50 focus:border-transparent transition-all"
            />
            <FileCode className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
          </div>

          <div className="flex gap-2">
            {['all', 'critical', 'high', 'medium', 'low'].map((severity) => (
              <button
                key={severity}
                onClick={() => setSelectedSeverity(severity)}
                className={`px-4 py-2 rounded-lg font-medium transition-all ${
                  selectedSeverity === severity
                    ? 'bg-gradient-to-r from-blue-500 to-purple-600 text-white'
                    : 'bg-gray-800/50 text-gray-400 hover:text-white hover:bg-gray-700/50'
                }`}
              >
                {severity.charAt(0).toUpperCase() + severity.slice(1)}
              </button>
            ))}
          </div>
        </div>

        {/* Results */}
        {results.length > 0 ? (
          filteredResults.length > 0 ? (
          <div className="space-y-4">
            {filteredResults.map((result) => {
              const severityConfig = getSeverityConfig(result.severity)
              const SeverityIcon = severityConfig.icon
              const isExpanded = expandedResults.has(result.id)

              return (
                <div
                  key={result.id}
                  className={`bg-gradient-to-br ${severityConfig.bgGradient} backdrop-blur-xl rounded-xl border border-gray-700/50 hover:border-gray-600/50 transition-all`}
                >
                  <div
                    className="p-6 cursor-pointer"
                    onClick={() => toggleResult(result.id)}
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex-1 mr-4">
                        <div className="flex items-start space-x-3">
                          <div className={`p-2 rounded-lg ${severityConfig.color}`}>
                            <SeverityIcon className="w-5 h-5" />
                          </div>
                          <div className="flex-1">
                            <h3 className="text-lg font-semibold text-white mb-1">
                              {result.title}
                            </h3>
                            <div className="flex items-center space-x-4 text-sm text-gray-400">
                              <div className="flex items-center space-x-1">
                                <FileCode className="w-4 h-4" />
                                <span className="font-mono">{result.file_path}</span>
                                {result.line_number && (
                                  <span>:{result.line_number}</span>
                                )}
                              </div>
                              {result.rule_id && (
                                <div className="flex items-center space-x-1">
                                  <Terminal className="w-4 h-4" />
                                  <span className="font-mono text-xs">{result.rule_id}</span>
                                </div>
                              )}
                            </div>
                          </div>
                        </div>
                      </div>
                      
                      <button className="p-2 hover:bg-gray-700/50 rounded-lg transition-colors">
                        {isExpanded ? (
                          <ChevronDown className="w-5 h-5 text-gray-400" />
                        ) : (
                          <ChevronRight className="w-5 h-5 text-gray-400" />
                        )}
                      </button>
                    </div>

                    {/* Quick actions */}
                    {isExpanded && (
                      <div className="mt-6 space-y-4">
                        {result.description && (
                          <div>
                            <h4 className="text-sm font-medium text-gray-400 mb-2">Description</h4>
                            <p className="text-gray-300">{result.description}</p>
                          </div>
                        )}

                        {result.code_snippet && (
                          <div>
                            <div className="flex items-center justify-between mb-2">
                              <h4 className="text-sm font-medium text-gray-400">Code</h4>
                              <button
                                onClick={(e) => {
                                  e.stopPropagation()
                                  copyToClipboard(result.code_snippet!)
                                }}
                                className="p-1 hover:bg-gray-700/50 rounded transition-colors"
                              >
                                <Copy className="w-4 h-4 text-gray-400" />
                              </button>
                            </div>
                            <pre className="bg-gray-900/50 rounded-lg p-4 overflow-x-auto">
                              <code className="language-javascript text-sm">
                                {result.code_snippet}
                              </code>
                            </pre>
                          </div>
                        )}

                        {result.fix_recommendation && (
                          <div>
                            <h4 className="text-sm font-medium text-gray-400 mb-2 flex items-center space-x-2">
                              <Zap className="w-4 h-4" />
                              <span>Recommended Fix</span>
                            </h4>
                            <p className="text-gray-300 bg-gray-900/50 rounded-lg p-4">
                              {result.fix_recommendation}
                            </p>
                          </div>
                        )}

                        <div className="flex items-center space-x-4 pt-4 border-t border-gray-700/50">
                          {result.owasp_category && (
                            <span className="text-xs px-3 py-1 bg-gray-700/50 text-gray-300 rounded-full">
                              {result.owasp_category}
                            </span>
                          )}
                          {result.cvss_score && (
                            <span className="text-xs px-3 py-1 bg-gray-700/50 text-gray-300 rounded-full">
                              CVSS: {result.cvss_score}
                            </span>
                          )}
                          {result.confidence && (
                            <span className="text-xs px-3 py-1 bg-gray-700/50 text-gray-300 rounded-full">
                              {result.confidence} confidence
                            </span>
                          )}
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              )
            })}
          </div>
          ) : (
            <div className="text-center py-16">
              <div className="inline-flex items-center justify-center w-24 h-24 rounded-full bg-gray-800/50 mb-6">
                <AlertTriangle className="w-12 h-12 text-yellow-400" />
              </div>
              <h3 className="text-2xl font-semibold text-white mb-2">
                No results match your current filter
              </h3>
              <p className="text-gray-400 max-w-md mx-auto">
                Try adjusting your search or filters to see the {results.length} security findings.
              </p>
              <button
                onClick={() => {
                  setSelectedSeverity('all')
                  setSearchQuery('')
                }}
                className="mt-4 px-6 py-2 bg-gradient-to-r from-blue-500 to-purple-600 text-white rounded-lg hover:from-blue-600 hover:to-purple-700 transition-all"
              >
                Clear Filters
              </button>
            </div>
          )
        ) : (
          <div className="text-center py-16">
            <div className="inline-flex items-center justify-center w-24 h-24 rounded-full bg-gray-800/50 mb-6">
              <CheckCircle className="w-12 h-12 text-green-400" />
            </div>
            <h3 className="text-2xl font-semibold text-white mb-2">
              All clear!
            </h3>
            <p className="text-gray-400 max-w-md mx-auto">
              No security vulnerabilities were detected in this scan. Your code is looking secure!
            </p>
          </div>
        )}
      </main>

      <style>{`
        @keyframes blob {
          0% { transform: translate(0px, 0px) scale(1); }
          33% { transform: translate(30px, -50px) scale(1.1); }
          66% { transform: translate(-20px, 20px) scale(0.9); }
          100% { transform: translate(0px, 0px) scale(1); }
        }
        
        .animate-blob {
          animation: blob 7s infinite;
        }
        
        .animation-delay-2000 {
          animation-delay: 2s;
        }
        
        .animation-delay-4000 {
          animation-delay: 4s;
        }
        
        @keyframes slide-up {
          from {
            transform: translateY(100%);
            opacity: 0;
          }
          to {
            transform: translateY(0);
            opacity: 1;
          }
        }
        
        .animate-slide-up {
          animation: slide-up 0.3s ease-out;
        }
      `}</style>
    </div>
  )
}