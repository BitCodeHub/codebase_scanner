import { useState, useEffect } from 'react'
import { useParams, Link } from 'react-router-dom'
import { 
  ArrowLeft, 
  Shield, 
  AlertTriangle, 
  FileCode, 
  Brain,
  Download,
  RefreshCw,
  CheckCircle,
  XCircle
} from 'lucide-react'
import { supabase } from '../lib/supabase'
import AIAnalysisPanel from '../components/ai/AIAnalysisPanel'
import LoadingSpinner from '../components/ui/LoadingSpinner'

// No more mock data - we only show real scan results

export default function ScanResults() {
  const { id } = useParams()
  const [scan, setScan] = useState<any>(null)
  const [loading, setLoading] = useState(true)
  const [selectedVulnerability, setSelectedVulnerability] = useState<any>(null)
  const [analyzedVulnerabilities, setAnalyzedVulnerabilities] = useState<Set<string>>(new Set())

  useEffect(() => {
    loadScanData()
    
    // Set up auto-refresh for running scans
    const interval = setInterval(() => {
      if (scan?.status === 'running') {
        loadScanData()
      }
    }, 5000) // Refresh every 5 seconds
    
    return () => clearInterval(interval)
  }, [id, scan?.status])

  const loadScanData = async () => {
    try {
      setLoading(true)
      
      // Fetch scan details with project info
      const { data: scanData, error: scanError } = await supabase
        .from('scans')
        .select(`
          *,
          projects (
            name,
            description,
            github_repo_url
          )
        `)
        .eq('id', id)
        .single()

      if (scanError) throw scanError

      // Fetch scan results
      const { data: results, error: resultsError } = await supabase
        .from('scan_results')
        .select('*')
        .eq('scan_id', id)
        .order('severity', { ascending: false })

      if (resultsError) throw resultsError

      // Combine data
      const fullScanData = {
        ...scanData,
        project_name: scanData.projects?.name || 'Unknown Project',
        results: results || []
      }

      setScan(fullScanData)
    } catch (error) {
      console.error('Error loading scan data:', error)
      // Show error state instead of mock data
      setScan(null)
    } finally {
      setLoading(false)
    }
  }

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return 'text-red-600 bg-red-50 border-red-200'
      case 'high': return 'text-orange-600 bg-orange-50 border-orange-200'
      case 'medium': return 'text-yellow-600 bg-yellow-50 border-yellow-200'
      case 'low': return 'text-blue-600 bg-blue-50 border-blue-200'
      default: return 'text-gray-600 bg-gray-50 border-gray-200'
    }
  }

  const getSeverityIcon = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return <XCircle className="h-5 w-5" />
      case 'high': return <AlertTriangle className="h-5 w-5" />
      case 'medium': return <AlertTriangle className="h-5 w-5" />
      case 'low': return <Shield className="h-5 w-5" />
      default: return <Shield className="h-5 w-5" />
    }
  }

  const handleAnalysisComplete = (vulnerabilityId: string) => {
    setAnalyzedVulnerabilities(prev => new Set(prev).add(vulnerabilityId))
  }

  const analyzeAllVulnerabilities = async () => {
    try {
      const { analyzeAllVulnerabilities } = await import('../services/scanService')
      const result = await analyzeAllVulnerabilities(id!)
      alert(`${result.message}\nTask ID: ${result.taskId}`)
    } catch (error: any) {
      console.error('Analyze all error:', error)
      alert(`Error: ${error.message}`)
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <LoadingSpinner />
      </div>
    )
  }

  if (!scan) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="text-center">
          <p className="text-gray-500">No scan data found</p>
          <Link to="/projects" className="text-blue-600 hover:underline mt-2">
            Back to Projects
          </Link>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <div className="bg-white shadow-sm border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center">
              <Link
                to="/dashboard"
                className="mr-4 text-gray-500 hover:text-gray-700"
              >
                <ArrowLeft className="h-5 w-5" />
              </Link>
              <div>
                <h1 className="text-2xl font-bold text-gray-900">Scan Results</h1>
                <p className="text-sm text-gray-500 mt-1">
                  {scan.project_name} • {new Date(scan.created_at).toLocaleString()}
                </p>
                {scan.status === 'running' && (
                  <div className="flex items-center mt-2 text-blue-600">
                    <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                    <span className="text-sm">Scan in progress...</span>
                  </div>
                )}
                {scan.status === 'failed' && (
                  <div className="flex items-center mt-2 text-red-600">
                    <XCircle className="h-4 w-4 mr-2" />
                    <span className="text-sm">Scan failed: {scan.error_message || 'Unknown error'}</span>
                  </div>
                )}
              </div>
            </div>
            <div className="flex items-center space-x-3">
              <button
                onClick={analyzeAllVulnerabilities}
                className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 flex items-center"
              >
                <Brain className="h-4 w-4 mr-2" />
                Analyze All with AI
              </button>
              <button className="px-4 py-2 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50 flex items-center">
                <Download className="h-4 w-4 mr-2" />
                Export Report
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
        <div className="grid grid-cols-1 md:grid-cols-5 gap-4 mb-6">
          <div className="bg-white rounded-lg shadow-sm p-4 border border-gray-200">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-500">Total Issues</p>
                <p className="text-2xl font-bold text-gray-900">{scan.total_issues || scan.results?.length || 0}</p>
              </div>
              <Shield className="h-8 w-8 text-gray-400" />
            </div>
          </div>
          
          <div className="bg-white rounded-lg shadow-sm p-4 border border-red-200">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-red-600">Critical</p>
                <p className="text-2xl font-bold text-red-600">{scan.critical_issues || scan.results?.filter((r: any) => r.severity === 'critical').length || 0}</p>
              </div>
              <XCircle className="h-8 w-8 text-red-400" />
            </div>
          </div>

          <div className="bg-white rounded-lg shadow-sm p-4 border border-orange-200">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-orange-600">High</p>
                <p className="text-2xl font-bold text-orange-600">{scan.high_issues || scan.results?.filter((r: any) => r.severity === 'high').length || 0}</p>
              </div>
              <AlertTriangle className="h-8 w-8 text-orange-400" />
            </div>
          </div>

          <div className="bg-white rounded-lg shadow-sm p-4 border border-yellow-200">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-yellow-600">Medium</p>
                <p className="text-2xl font-bold text-yellow-600">{scan.medium_issues || scan.results?.filter((r: any) => r.severity === 'medium').length || 0}</p>
              </div>
              <AlertTriangle className="h-8 w-8 text-yellow-400" />
            </div>
          </div>

          <div className="bg-white rounded-lg shadow-sm p-4 border border-blue-200">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-blue-600">Low</p>
                <p className="text-2xl font-bold text-blue-600">{scan.low_issues || scan.results?.filter((r: any) => r.severity === 'low').length || 0}</p>
              </div>
              <Shield className="h-8 w-8 text-blue-400" />
            </div>
          </div>
        </div>

        {/* Results List */}
        <div className="bg-white rounded-lg shadow-sm border border-gray-200">
          <div className="px-6 py-4 border-b border-gray-200">
            <h2 className="text-lg font-semibold text-gray-900">Vulnerability Findings</h2>
          </div>
          
          <div className="divide-y divide-gray-200">
            {scan.results && scan.results.length > 0 ? (
              scan.results.map((result: any) => (
                <div key={result.id} className="p-6">
                  <div className="flex items-start justify-between mb-4">
                    <div className="flex items-start">
                      <div className={`p-2 rounded-lg ${getSeverityColor(result.severity)} mr-4`}>
                        {getSeverityIcon(result.severity)}
                      </div>
                      <div>
                        <h3 className="text-lg font-medium text-gray-900 flex items-center">
                          {result.title}
                          {analyzedVulnerabilities.has(result.id) && (
                            <CheckCircle className="h-4 w-4 text-green-500 ml-2" />
                          )}
                        </h3>
                        <p className="text-sm text-gray-500 mt-1">
                          {result.rule_id} • {result.owasp_category}
                        </p>
                        <p className="text-sm text-gray-600 mt-2">{result.description}</p>
                        
                        <div className="flex items-center mt-3 text-sm text-gray-500">
                          <FileCode className="h-4 w-4 mr-1" />
                          <span className="font-mono">{result.file_path}:{result.line_number}</span>
                        </div>
                        
                        {result.code_snippet && (
                          <pre className="mt-3 p-3 bg-gray-900 text-gray-100 rounded-lg text-sm overflow-x-auto">
                            <code>{result.code_snippet}</code>
                          </pre>
                        )}
                      </div>
                    </div>
                    
                    <span className={`px-3 py-1 rounded-full text-xs font-medium ${getSeverityColor(result.severity)}`}>
                      {result.severity.toUpperCase()}
                    </span>
                  </div>
                  
                  {/* AI Analysis Panel */}
                  <AIAnalysisPanel 
                    vulnerability={result}
                    scanId={scan.id}
                    onAnalysisComplete={() => handleAnalysisComplete(result.id)}
                  />
                </div>
              ))
            ) : (
              <div className="p-12 text-center">
                <CheckCircle className="h-16 w-16 text-green-400 mx-auto mb-4" />
                <h3 className="text-lg font-medium text-gray-900 mb-2">No vulnerabilities found!</h3>
                <p className="text-gray-500">
                  {scan.status === 'completed' 
                    ? 'Great! The security scan completed successfully with no issues detected.'
                    : scan.status === 'running' 
                    ? 'Scan is still running. Check back in a few minutes.'
                    : scan.status === 'failed'
                    ? 'Scan failed. Please try running a new scan.'
                    : 'Scan is pending. Real security analysis will begin shortly.'
                  }
                </p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}