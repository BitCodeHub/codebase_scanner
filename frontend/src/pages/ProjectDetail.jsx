import { useState, useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { apiService as api } from '../services/api'
import { 
  CodeBracketIcon, 
  ShieldCheckIcon, 
  ClockIcon, 
  ExclamationTriangleIcon,
  CheckCircleIcon,
  XCircleIcon,
  ArrowLeftIcon,
  BoltIcon,
  DocumentTextIcon,
  BeakerIcon
} from '@heroicons/react/24/outline'

export default function ProjectDetail() {
  const { projectId } = useParams()
  const navigate = useNavigate()
  const [project, setProject] = useState(null)
  const [scans, setScans] = useState([])
  const [loading, setLoading] = useState(true)
  const [scanning, setScanning] = useState(false)
  const [scanConfig, setScanConfig] = useState({
    scan_type: 'security',
    include_ai_analysis: false
  })

  useEffect(() => {
    fetchProjectDetails()
  }, [projectId])

  const fetchProjectDetails = async () => {
    try {
      const [projectData, scansData] = await Promise.all([
        api.getProject(projectId),
        api.getProjectScans(projectId)
      ])
      setProject(projectData)
      setScans(scansData)
    } catch (error) {
      console.error('Failed to fetch project details:', error)
    } finally {
      setLoading(false)
    }
  }

  const handleStartScan = async () => {
    setScanning(true)
    try {
      const scan = await api.startScan(projectId, scanConfig)
      setScans([scan, ...scans])
      // Poll for scan status
      pollScanStatus(scan.id)
    } catch (error) {
      console.error('Failed to start scan:', error)
    } finally {
      setScanning(false)
    }
  }

  const pollScanStatus = async (scanId) => {
    const interval = setInterval(async () => {
      try {
        const scan = await api.getScan(scanId)
        setScans(current => 
          current.map(s => s.id === scanId ? scan : s)
        )
        if (scan.status === 'completed' || scan.status === 'failed') {
          clearInterval(interval)
        }
      } catch (error) {
        console.error('Failed to poll scan status:', error)
        clearInterval(interval)
      }
    }, 2000)
  }

  const getScanStatusColor = (status) => {
    switch (status) {
      case 'completed': return 'text-green-600 bg-green-100'
      case 'failed': return 'text-red-600 bg-red-100'
      case 'running': return 'text-blue-600 bg-blue-100'
      default: return 'text-gray-600 bg-gray-100'
    }
  }

  if (loading) {
    return (
      <div className="flex justify-center items-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-600"></div>
      </div>
    )
  }

  if (!project) {
    return <div>Project not found</div>
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Header */}
        <div className="mb-8">
          <button
            onClick={() => navigate('/projects')}
            className="flex items-center text-gray-600 hover:text-gray-900 mb-4"
          >
            <ArrowLeftIcon className="h-5 w-5 mr-2" />
            Back to Projects
          </button>
          
          <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-6">
            <div className="flex items-start justify-between">
              <div className="flex items-start">
                <div className="bg-gradient-to-br from-indigo-500 to-purple-600 rounded-lg p-3 mr-4">
                  <CodeBracketIcon className="h-8 w-8 text-white" />
                </div>
                <div>
                  <h1 className="text-2xl font-bold text-gray-900">{project.name}</h1>
                  <p className="text-gray-600 mt-1">{project.description || 'No description'}</p>
                  <div className="mt-3 flex items-center gap-4 text-sm text-gray-500">
                    <span className="flex items-center">
                      <ClockIcon className="h-4 w-4 mr-1" />
                      Created {new Date(project.created_at).toLocaleDateString()}
                    </span>
                    {project.github_repo_url && (
                      <a 
                        href={project.github_repo_url} 
                        target="_blank" 
                        rel="noopener noreferrer" 
                        className="text-indigo-600 hover:text-indigo-700 flex items-center"
                      >
                        <CodeBracketIcon className="h-4 w-4 mr-1" />
                        View on GitHub
                      </a>
                    )}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Start New Scan */}
        <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-6 mb-8">
          <div className="flex items-center mb-4">
            <BeakerIcon className="h-6 w-6 text-indigo-600 mr-2" />
            <h2 className="text-lg font-semibold text-gray-900">Start New Security Scan</h2>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Scan Type
              </label>
              <select
                value={scanConfig.scan_type}
                onChange={(e) => setScanConfig({ ...scanConfig, scan_type: e.target.value })}
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
              >
                <option value="security">Security Scan</option>
                <option value="quality">Code Quality</option>
                <option value="performance">Performance Analysis</option>
                <option value="launch_ready">Launch Ready Check</option>
              </select>
            </div>
            <div className="flex items-end">
              <label className="flex items-center cursor-pointer bg-gray-50 rounded-lg px-4 py-2 hover:bg-gray-100 transition-colors">
                <input
                  type="checkbox"
                  checked={scanConfig.include_ai_analysis}
                  onChange={(e) => setScanConfig({ ...scanConfig, include_ai_analysis: e.target.checked })}
                  className="mr-3 h-4 w-4 text-indigo-600 focus:ring-indigo-500 border-gray-300 rounded"
                />
                <span className="text-sm text-gray-700">Include AI Analysis</span>
                <span className="ml-2 text-xs text-gray-500">(Slower but more thorough)</span>
              </label>
            </div>
          </div>
          
          <button
            onClick={handleStartScan}
            disabled={scanning}
            className="inline-flex items-center px-6 py-3 bg-gradient-to-r from-indigo-600 to-purple-600 text-white rounded-lg hover:from-indigo-700 hover:to-purple-700 disabled:opacity-50 disabled:cursor-not-allowed transition-all transform hover:scale-105"
          >
            {scanning ? (
              <>
                <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                Starting Scan...
              </>
            ) : (
              <>
                <BoltIcon className="h-5 w-5 mr-2" />
                Start Scan
              </>
            )}
          </button>
        </div>

        {/* Scan History */}
        <div className="bg-white rounded-xl shadow-sm border border-gray-100 overflow-hidden">
          <div className="px-6 py-4 border-b border-gray-100 flex items-center justify-between">
            <h2 className="text-lg font-semibold text-gray-900 flex items-center">
              <ClockIcon className="h-6 w-6 text-gray-400 mr-2" />
              Scan History
            </h2>
            {scans.length > 0 && (
              <span className="text-sm text-gray-500">
                {scans.length} scan{scans.length > 1 ? 's' : ''}
              </span>
            )}
          </div>
          
          <div className="p-6">
            {scans.length === 0 ? (
              <div className="text-center py-8">
                <ShieldCheckIcon className="mx-auto h-12 w-12 text-gray-400 mb-3" />
                <p className="text-gray-500">No scans yet</p>
                <p className="text-sm text-gray-400 mt-1">Start your first scan to check for vulnerabilities</p>
              </div>
            ) : (
              <div className="space-y-4">
                {scans.map((scan) => {
                  const statusIcon = {
                    completed: CheckCircleIcon,
                    failed: XCircleIcon,
                    running: ClockIcon,
                    pending: ClockIcon
                  }[scan.status] || ClockIcon
                  
                  const StatusIcon = statusIcon
                  
                  return (
                    <div
                      key={scan.id}
                      className="border border-gray-200 rounded-lg p-4 hover:shadow-md hover:border-indigo-300 cursor-pointer transition-all"
                      onClick={() => navigate(`/scans/${scan.id}`)}
                    >
                      <div className="flex justify-between items-start">
                        <div className="flex items-start">
                          <StatusIcon className={`h-5 w-5 mr-3 mt-1 ${
                            scan.status === 'completed' ? 'text-green-500' :
                            scan.status === 'failed' ? 'text-red-500' :
                            scan.status === 'running' ? 'text-blue-500 animate-pulse' :
                            'text-gray-400'
                          }`} />
                          <div>
                            <h3 className="font-medium text-gray-900">
                              {scan.scan_type.charAt(0).toUpperCase() + scan.scan_type.slice(1).replace('_', ' ')} Scan
                            </h3>
                            <p className="text-sm text-gray-600 mt-1">
                              {new Date(scan.created_at).toLocaleString()}
                            </p>
                          </div>
                        </div>
                        <span className={`px-3 py-1 text-xs font-medium rounded-full ${getScanStatusColor(scan.status)}`}>
                          {scan.status}
                        </span>
                      </div>
                      
                      {scan.status === 'completed' && (
                        <div className="mt-3 flex items-center gap-4 text-sm">
                          {scan.critical_issues > 0 && (
                            <span className="flex items-center text-red-600">
                              <ExclamationTriangleIcon className="h-4 w-4 mr-1" />
                              {scan.critical_issues} critical
                            </span>
                          )}
                          {scan.high_issues > 0 && (
                            <span className="flex items-center text-orange-600">
                              <ExclamationTriangleIcon className="h-4 w-4 mr-1" />
                              {scan.high_issues} high
                            </span>
                          )}
                          {scan.medium_issues > 0 && (
                            <span className="text-yellow-600">
                              {scan.medium_issues} medium
                            </span>
                          )}
                          {scan.low_issues > 0 && (
                            <span className="text-blue-600">
                              {scan.low_issues} low
                            </span>
                          )}
                          {scan.total_issues === 0 && (
                            <span className="text-green-600 flex items-center">
                              <CheckCircleIcon className="h-4 w-4 mr-1" />
                              No issues found
                            </span>
                          )}
                        </div>
                      )}
                      
                      {scan.status === 'running' && (
                        <div className="mt-3">
                          <div className="w-full bg-gray-200 rounded-full h-2">
                            <div className="bg-blue-600 h-2 rounded-full animate-pulse" style={{ width: '45%' }}></div>
                          </div>
                        </div>
                      )}
                      
                      {scan.status === 'failed' && scan.error_message && (
                        <p className="mt-2 text-sm text-red-600">
                          Error: {scan.error_message}
                        </p>
                      )}
                    </div>
                  )
                })}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}