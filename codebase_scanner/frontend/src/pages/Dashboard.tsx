import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { supabase } from '../lib/supabase'
import { 
  FolderIcon, 
  ShieldCheckIcon, 
  AlertTriangleIcon,
  TrendingUpIcon,
  PlusIcon,
  Activity,
  Clock,
  FileText,
  Bug,
  Shield,
  Zap,
  AlertCircle,
  CheckCircle,
  XCircle,
  Calendar,
  BarChart3,
  Eye,
  Brain
} from 'lucide-react'
import LoadingSpinner from '../components/ui/LoadingSpinner'
import ScanModal from '../components/ScanModal'

interface DashboardStats {
  totalProjects: number
  totalScans: number
  criticalIssues: number
  highIssues: number
  mediumIssues: number
  lowIssues: number
  recentScans: any[]
  securityScore: number
  lastScanDate: string | null
  activeScans: number
  resolvedIssues: number
  weeklyTrend: number
}

export default function Dashboard() {
  const [stats, setStats] = useState<DashboardStats>({
    totalProjects: 0,
    totalScans: 0,
    criticalIssues: 0,
    highIssues: 0,
    mediumIssues: 0,
    lowIssues: 0,
    recentScans: [],
    securityScore: 0,
    lastScanDate: null,
    activeScans: 0,
    resolvedIssues: 0,
    weeklyTrend: 0
  })
  const [loading, setLoading] = useState(true)
  const [showScanModal, setShowScanModal] = useState(false)

  useEffect(() => {
    loadDashboardData()
  }, [])

  const loadDashboardData = async () => {
    try {
      // Get projects count
      const { count: projectsCount } = await supabase
        .from('projects')
        .select('*', { count: 'exact', head: true })

      // Get scans count
      const { count: scansCount } = await supabase
        .from('scans')
        .select('*', { count: 'exact', head: true })

      // Get issues count by severity
      const { count: criticalCount } = await supabase
        .from('scan_results')
        .select('*', { count: 'exact', head: true })
        .eq('severity', 'critical')

      const { count: highCount } = await supabase
        .from('scan_results')
        .select('*', { count: 'exact', head: true })
        .eq('severity', 'high')

      const { count: mediumCount } = await supabase
        .from('scan_results')
        .select('*', { count: 'exact', head: true })
        .eq('severity', 'medium')

      const { count: lowCount } = await supabase
        .from('scan_results')
        .select('*', { count: 'exact', head: true })
        .eq('severity', 'low')

      // Get active scans
      const { count: activeCount } = await supabase
        .from('scans')
        .select('*', { count: 'exact', head: true })
        .eq('status', 'running')

      // Calculate security score
      const totalIssues = (criticalCount || 0) + (highCount || 0) + (mediumCount || 0) + (lowCount || 0)
      const securityScore = totalIssues === 0 ? 100 : Math.max(0, 100 - (criticalCount || 0) * 25 - (highCount || 0) * 10 - (mediumCount || 0) * 5 - (lowCount || 0) * 1)

      // Get recent scans
      const { data: recentScans } = await supabase
        .from('scans')
        .select(`
          *,
          projects (name)
        `)
        .order('created_at', { ascending: false })
        .limit(5)

      setStats({
        totalProjects: projectsCount || 0,
        totalScans: scansCount || 0,
        criticalIssues: criticalCount || 0,
        highIssues: highCount || 0,
        mediumIssues: mediumCount || 0,
        lowIssues: lowCount || 0,
        recentScans: recentScans || [],
        securityScore: Math.round(securityScore),
        lastScanDate: recentScans?.[0]?.created_at || null,
        activeScans: activeCount || 0,
        resolvedIssues: Math.floor(Math.random() * 50), // Mock data for now
        weeklyTrend: Math.floor(Math.random() * 20) - 10 // Mock data for now
      })
    } catch (error) {
      console.error('Error loading dashboard data:', error)
    } finally {
      setLoading(false)
    }
  }

  const handleStartScan = async (files: File[], options: any) => {
    try {
      // Create FormData for file upload
      const formData = new FormData()
      
      // For demo, use the first project or create a demo project
      const { data: projects } = await supabase
        .from('projects')
        .select('id')
        .limit(1)
      
      let projectId = projects?.[0]?.id
      
      if (!projectId) {
        // Create a demo project
        const { data: newProject } = await supabase
          .from('projects')
          .insert({
            name: 'Demo Project',
            description: 'Demo project for security scanning',
            repository_url: 'https://github.com/demo/project'
          })
          .select()
          .single()
        
        projectId = newProject?.id
      }
      
      if (!projectId) {
        alert('Failed to create project. Please try again.')
        return
      }
      
      // Add files and metadata to FormData
      formData.append('file', files[0]) // For now, just upload the first file
      formData.append('project_id', projectId)
      formData.append('scan_type', options.scanType === 'quick' ? 'quick' : 'full')
      
      // Get auth token
      const { data: { session } } = await supabase.auth.getSession()
      
      if (!session?.access_token) {
        alert('Please log in to start a scan')
        return
      }
      
      // Call the scan API
      const response = await fetch(`${import.meta.env.VITE_API_URL}/api/scans`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${session.access_token}`
        },
        body: formData
      })
      
      if (!response.ok) {
        const error = await response.json()
        throw new Error(error.detail || 'Failed to start scan')
      }
      
      const scan = await response.json()
      
      // Show success message
      alert(`Scan started successfully! Scan ID: ${scan.id}`)
      
      // Refresh dashboard data
      await loadDashboardData()
      
      // Optionally redirect to scan results
      // window.location.href = `/scans/${scan.id}/results`
      
    } catch (error) {
      console.error('Error starting scan:', error)
      alert(`Failed to start scan: ${error instanceof Error ? error.message : 'Unknown error'}`)
    }
  }

  if (loading) {
    return (
      <div className="p-6">
        <LoadingSpinner size="lg" className="h-64" />
      </div>
    )
  }

  return (
    <div className="p-6 bg-gray-50 min-h-screen">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-4xl font-bold text-red-600">🚀 UPDATED Security Dashboard</h1>
            <p className="text-blue-600 mt-2 text-lg font-medium">Monitor your application security posture - ENHANCED VERSION</p>
          </div>
          <div className="flex items-center space-x-4">
            <div className="text-right">
              <p className="text-sm text-gray-500">Last Updated</p>
              <p className="text-sm font-medium text-gray-900">
                {stats.lastScanDate ? new Date(stats.lastScanDate).toLocaleString() : 'Never'}
              </p>
            </div>
            <Link
              to="/projects"
              className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
            >
              <PlusIcon className="-ml-1 mr-2 h-4 w-4" />
              New Project
            </Link>
          </div>
        </div>
      </div>

      {/* Main Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6 hover:shadow-md transition-shadow">
          <div className="flex items-center">
            <div className="p-3 bg-blue-50 rounded-lg">
              <FolderIcon className="h-6 w-6 text-blue-600" />
            </div>
            <div className="ml-4 flex-1">
              <p className="text-sm font-medium text-gray-600">Active Projects</p>
              <p className="text-2xl font-bold text-gray-900">{stats.totalProjects}</p>
              <p className="text-xs text-green-600 flex items-center mt-1">
                <TrendingUpIcon className="h-3 w-3 mr-1" />
                +2 this month
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6 hover:shadow-md transition-shadow">
          <div className="flex items-center">
            <div className="p-3 bg-green-50 rounded-lg">
              <ShieldCheckIcon className="h-6 w-6 text-green-600" />
            </div>
            <div className="ml-4 flex-1">
              <p className="text-sm font-medium text-gray-600">Security Score</p>
              <div className="flex items-baseline">
                <p className="text-2xl font-bold text-gray-900">{stats.securityScore}</p>
                <span className="text-lg text-gray-500 ml-1">/100</span>
              </div>
              <div className="w-full bg-gray-200 rounded-full h-2 mt-2">
                <div 
                  className={`h-2 rounded-full ${
                    stats.securityScore >= 80 ? 'bg-green-500' :
                    stats.securityScore >= 60 ? 'bg-yellow-500' : 'bg-red-500'
                  }`} 
                  style={{ width: `${stats.securityScore}%` }}
                ></div>
              </div>
            </div>
          </div>
        </div>

        <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6 hover:shadow-md transition-shadow">
          <div className="flex items-center">
            <div className="p-3 bg-red-50 rounded-lg">
              <AlertTriangleIcon className="h-6 w-6 text-red-600" />
            </div>
            <div className="ml-4 flex-1">
              <p className="text-sm font-medium text-gray-600">Critical Issues</p>
              <p className="text-2xl font-bold text-gray-900">{stats.criticalIssues}</p>
              <p className="text-xs text-gray-600 mt-1">
                {stats.highIssues} high, {stats.mediumIssues} medium
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6 hover:shadow-md transition-shadow">
          <div className="flex items-center">
            <div className="p-3 bg-purple-50 rounded-lg">
              <Activity className="h-6 w-6 text-purple-600" />
            </div>
            <div className="ml-4 flex-1">
              <p className="text-sm font-medium text-gray-600">Total Scans</p>
              <p className="text-2xl font-bold text-gray-900">{stats.totalScans}</p>
              <p className="text-xs text-blue-600 flex items-center mt-1">
                <Clock className="h-3 w-3 mr-1" />
                {stats.activeScans} running
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Secondary Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
        <div className="bg-white rounded-lg border border-gray-200 p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-600">Resolved Issues</p>
              <p className="text-lg font-semibold text-green-600">{stats.resolvedIssues}</p>
            </div>
            <CheckCircle className="h-8 w-8 text-green-500" />
          </div>
        </div>
        <div className="bg-white rounded-lg border border-gray-200 p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-600">Active Scans</p>
              <p className="text-lg font-semibold text-blue-600">{stats.activeScans}</p>
            </div>
            <Activity className="h-8 w-8 text-blue-500" />
          </div>
        </div>
        <div className="bg-white rounded-lg border border-gray-200 p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-600">Weekly Trend</p>
              <p className={`text-lg font-semibold ${
                stats.weeklyTrend >= 0 ? 'text-green-600' : 'text-red-600'
              }`}>
                {stats.weeklyTrend >= 0 ? '+' : ''}{stats.weeklyTrend}%
              </p>
            </div>
            <BarChart3 className={`h-8 w-8 ${
              stats.weeklyTrend >= 0 ? 'text-green-500' : 'text-red-500'
            }`} />
          </div>
        </div>
        <div className="bg-white rounded-lg border border-gray-200 p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-600">Low Risk Issues</p>
              <p className="text-lg font-semibold text-yellow-600">{stats.lowIssues}</p>
            </div>
            <AlertCircle className="h-8 w-8 text-yellow-500" />
          </div>
        </div>
      </div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
        {/* Quick Actions */}
        <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-4 flex items-center">
            <Zap className="h-5 w-5 mr-2 text-blue-600" />
            Quick Actions
          </h2>
          <div className="space-y-3">
            <Link
              to="/projects"
              className="flex items-center p-4 bg-gradient-to-r from-blue-50 to-indigo-50 border border-blue-200 rounded-lg hover:from-blue-100 hover:to-indigo-100 transition-all duration-200 group"
            >
              <div className="p-2 bg-blue-100 rounded-lg group-hover:bg-blue-200 transition-colors">
                <PlusIcon className="h-5 w-5 text-blue-600" />
              </div>
              <div className="ml-3">
                <p className="text-sm font-medium text-gray-900">Create New Project</p>
                <p className="text-xs text-gray-600">Start securing your codebase</p>
              </div>
            </Link>
            <button 
              onClick={() => setShowScanModal(true)}
              className="w-full flex items-center p-4 bg-gradient-to-r from-green-50 to-emerald-50 border border-green-200 rounded-lg hover:from-green-100 hover:to-emerald-100 transition-all duration-200 group"
            >
              <div className="p-2 bg-green-100 rounded-lg group-hover:bg-green-200 transition-colors">
                <ShieldCheckIcon className="h-5 w-5 text-green-600" />
              </div>
              <div className="ml-3 text-left">
                <p className="text-sm font-medium text-gray-900">Run Quick Scan</p>
                <p className="text-xs text-gray-600">Upload files for instant analysis</p>
              </div>
            </button>
            <Link
              to="/security"
              className="flex items-center p-4 bg-gradient-to-r from-purple-50 to-violet-50 border border-purple-200 rounded-lg hover:from-purple-100 hover:to-violet-100 transition-all duration-200 group"
            >
              <div className="p-2 bg-purple-100 rounded-lg group-hover:bg-purple-200 transition-colors">
                <Eye className="h-5 w-5 text-purple-600" />
              </div>
              <div className="ml-3">
                <p className="text-sm font-medium text-gray-900">View Security Report</p>
                <p className="text-xs text-gray-600">Detailed vulnerability analysis</p>
              </div>
            </Link>
            <Link
              to="/scans/1/results"
              className="flex items-center p-4 bg-gradient-to-r from-cyan-50 to-blue-50 border border-cyan-200 rounded-lg hover:from-cyan-100 hover:to-blue-100 transition-all duration-200 group"
            >
              <div className="p-2 bg-cyan-100 rounded-lg group-hover:bg-cyan-200 transition-colors">
                <Brain className="h-5 w-5 text-cyan-600" />
              </div>
              <div className="ml-3">
                <p className="text-sm font-medium text-gray-900">AI Analysis Demo</p>
                <p className="text-xs text-gray-600">View Claude-powered insights</p>
              </div>
            </Link>
            <Link
              to="/vulnerability-dashboard"
              className="flex items-center p-4 bg-gradient-to-r from-red-50 to-pink-50 border border-red-200 rounded-lg hover:from-red-100 hover:to-pink-100 transition-all duration-200 group"
            >
              <div className="p-2 bg-red-100 rounded-lg group-hover:bg-red-200 transition-colors">
                <BarChart3 className="h-5 w-5 text-red-600" />
              </div>
              <div className="ml-3">
                <p className="text-sm font-medium text-gray-900">Vulnerability Dashboard</p>
                <p className="text-xs text-gray-600">Advanced security analytics</p>
              </div>
            </Link>
          </div>
        </div>

        {/* Recent Scans */}
        <div className="lg:col-span-2 bg-white rounded-xl shadow-sm border border-gray-200 p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-gray-900 flex items-center">
              <Clock className="h-5 w-5 mr-2 text-gray-600" />
              Recent Activity
            </h2>
            <Link to="/projects" className="text-sm text-blue-600 hover:text-blue-700 font-medium">
              View all →
            </Link>
          </div>
          <div className="space-y-3">
            {stats.recentScans.length > 0 ? (
              stats.recentScans.map((scan) => (
                <Link
                  key={scan.id}
                  to={`/scans/${scan.id}/results`}
                  className="flex items-center justify-between p-4 bg-gray-50 rounded-lg hover:bg-gray-100 transition-colors cursor-pointer block"
                >
                  <div className="flex items-center">
                    <div className={`p-2 rounded-lg mr-3 ${
                      scan.status === 'completed' ? 'bg-green-100' :
                      scan.status === 'running' ? 'bg-blue-100' :
                      scan.status === 'failed' ? 'bg-red-100' : 'bg-gray-100'
                    }`}>
                      {scan.status === 'completed' ? (
                        <CheckCircle className="h-4 w-4 text-green-600" />
                      ) : scan.status === 'running' ? (
                        <Activity className="h-4 w-4 text-blue-600" />
                      ) : scan.status === 'failed' ? (
                        <XCircle className="h-4 w-4 text-red-600" />
                      ) : (
                        <Clock className="h-4 w-4 text-gray-600" />
                      )}
                    </div>
                    <div>
                      <p className="text-sm font-medium text-gray-900">
                        {scan.projects?.name || 'Unknown Project'}
                      </p>
                      <p className="text-xs text-gray-500 flex items-center">
                        <Calendar className="h-3 w-3 mr-1" />
                        {new Date(scan.created_at).toLocaleDateString()}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center space-x-2">
                    <span className={`px-2 py-1 text-xs font-medium rounded-full ${
                      scan.status === 'completed' ? 'bg-green-100 text-green-800' :
                      scan.status === 'running' ? 'bg-blue-100 text-blue-800' :
                      scan.status === 'failed' ? 'bg-red-100 text-red-800' : 'bg-gray-100 text-gray-800'
                    }`}>
                      {scan.status}
                    </span>
                    <Eye className="h-4 w-4 text-gray-400" />
                  </div>
                </Link>
              ))
            ) : (
              <div className="text-center py-8">
                <FileText className="h-12 w-12 text-gray-300 mx-auto mb-3" />
                <p className="text-sm text-gray-500 mb-2">No scans yet</p>
                <p className="text-xs text-gray-400">Create a project to get started with security scanning</p>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Security Overview */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-lg font-semibold text-gray-900 flex items-center">
            <Shield className="h-5 w-5 mr-2 text-blue-600" />
            Security Risk Analysis
          </h2>
          <div className="flex items-center space-x-2">
            <span className="text-sm text-gray-500">Overall Risk:</span>
            <span className={`px-3 py-1 text-sm font-medium rounded-full ${
              stats.securityScore >= 80 ? 'bg-green-100 text-green-800' :
              stats.securityScore >= 60 ? 'bg-yellow-100 text-yellow-800' : 'bg-red-100 text-red-800'
            }`}>
              {stats.securityScore >= 80 ? 'Low' : stats.securityScore >= 60 ? 'Medium' : 'High'}
            </span>
          </div>
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
          <div className="text-center p-6 bg-gradient-to-br from-red-50 to-red-100 rounded-xl border border-red-200">
            <div className="mx-auto w-12 h-12 bg-red-100 rounded-full flex items-center justify-center mb-3">
              <AlertTriangleIcon className="h-6 w-6 text-red-600" />
            </div>
            <div className="text-3xl font-bold text-red-600 mb-1">{stats.criticalIssues}</div>
            <div className="text-sm font-medium text-red-700">Critical</div>
            <div className="text-xs text-red-600 mt-1">Immediate attention required</div>
          </div>
          
          <div className="text-center p-6 bg-gradient-to-br from-orange-50 to-orange-100 rounded-xl border border-orange-200">
            <div className="mx-auto w-12 h-12 bg-orange-100 rounded-full flex items-center justify-center mb-3">
              <AlertCircle className="h-6 w-6 text-orange-600" />
            </div>
            <div className="text-3xl font-bold text-orange-600 mb-1">{stats.highIssues}</div>
            <div className="text-sm font-medium text-orange-700">High Risk</div>
            <div className="text-xs text-orange-600 mt-1">Address soon</div>
          </div>
          
          <div className="text-center p-6 bg-gradient-to-br from-yellow-50 to-yellow-100 rounded-xl border border-yellow-200">
            <div className="mx-auto w-12 h-12 bg-yellow-100 rounded-full flex items-center justify-center mb-3">
              <Bug className="h-6 w-6 text-yellow-600" />
            </div>
            <div className="text-3xl font-bold text-yellow-600 mb-1">{stats.mediumIssues}</div>
            <div className="text-sm font-medium text-yellow-700">Medium Risk</div>
            <div className="text-xs text-yellow-600 mt-1">Monitor closely</div>
          </div>
          
          <div className="text-center p-6 bg-gradient-to-br from-green-50 to-green-100 rounded-xl border border-green-200">
            <div className="mx-auto w-12 h-12 bg-green-100 rounded-full flex items-center justify-center mb-3">
              <CheckCircle className="h-6 w-6 text-green-600" />
            </div>
            <div className="text-3xl font-bold text-green-600 mb-1">{stats.lowIssues}</div>
            <div className="text-sm font-medium text-green-700">Low Risk</div>
            <div className="text-xs text-green-600 mt-1">Best practices</div>
          </div>
        </div>
        
        {/* Risk Distribution Bar */}
        <div className="mt-6">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm font-medium text-gray-700">Risk Distribution</span>
            <span className="text-sm text-gray-500">
              {stats.criticalIssues + stats.highIssues + stats.mediumIssues + stats.lowIssues} total issues
            </span>
          </div>
          <div className="w-full bg-gray-200 rounded-full h-3 overflow-hidden">
            {(stats.criticalIssues + stats.highIssues + stats.mediumIssues + stats.lowIssues) > 0 ? (
              <div className="h-3 flex">
                <div 
                  className="bg-red-500" 
                  style={{ width: `${(stats.criticalIssues / (stats.criticalIssues + stats.highIssues + stats.mediumIssues + stats.lowIssues)) * 100}%` }}
                ></div>
                <div 
                  className="bg-orange-500" 
                  style={{ width: `${(stats.highIssues / (stats.criticalIssues + stats.highIssues + stats.mediumIssues + stats.lowIssues)) * 100}%` }}
                ></div>
                <div 
                  className="bg-yellow-500" 
                  style={{ width: `${(stats.mediumIssues / (stats.criticalIssues + stats.highIssues + stats.mediumIssues + stats.lowIssues)) * 100}%` }}
                ></div>
                <div 
                  className="bg-green-500" 
                  style={{ width: `${(stats.lowIssues / (stats.criticalIssues + stats.highIssues + stats.mediumIssues + stats.lowIssues)) * 100}%` }}
                ></div>
              </div>
            ) : (
              <div className="h-3 bg-green-500 rounded-full"></div>
            )}
          </div>
        </div>
      </div>

      {/* Scan Modal */}
      <ScanModal
        isOpen={showScanModal}
        onClose={() => setShowScanModal(false)}
        onStartScan={handleStartScan}
      />
    </div>
  )
}