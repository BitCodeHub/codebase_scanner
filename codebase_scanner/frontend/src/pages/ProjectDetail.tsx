import { useState, useEffect } from 'react'
import { useParams, useNavigate, Link } from 'react-router-dom'
import { supabase } from '../lib/supabase'
import { 
  ArrowLeftIcon,
  GitBranchIcon,
  CalendarIcon,
  ShieldCheckIcon,
  PlayIcon,
  AlertTriangleIcon,
  CheckCircleIcon,
  XCircleIcon,
  ClockIcon,
  EditIcon,
  TrashIcon,
  ExternalLinkIcon,
  PackageIcon,
  ActivityIcon
} from 'lucide-react'
import LoadingSpinner from '../components/ui/LoadingSpinner'
import { startRepositoryScan } from '../services/scanService'
import { getProject } from '../services/projectService'

interface Project {
  id: number
  name: string
  description: string | null
  github_repo_url: string | null
  github_default_branch: string | null
  uploaded_file_path: string | null
  owner_id: string
  created_at: string
  updated_at: string
  is_active: boolean
}

interface Scan {
  id: number
  scan_type: string
  status: string
  created_at: string
  completed_at: string | null
  total_issues: number
  critical_issues: number
  high_issues: number
  medium_issues: number
  low_issues: number
  triggered_by: string | null
}

interface ScanStats {
  totalScans: number
  completedScans: number
  averageDuration: number
  lastScanDate: string | null
  totalIssues: number
  criticalIssues: number
  highIssues: number
  mediumIssues: number
  lowIssues: number
}

export default function ProjectDetail() {
  const { id } = useParams()
  const navigate = useNavigate()
  const [project, setProject] = useState<Project | null>(null)
  const [scans, setScans] = useState<Scan[]>([])
  const [stats, setStats] = useState<ScanStats>({
    totalScans: 0,
    completedScans: 0,
    averageDuration: 0,
    lastScanDate: null,
    totalIssues: 0,
    criticalIssues: 0,
    highIssues: 0,
    mediumIssues: 0,
    lowIssues: 0
  })
  const [loading, setLoading] = useState(true)
  const [scanningProject, setScanningProject] = useState(false)
  const [deleting, setDeleting] = useState(false)

  useEffect(() => {
    if (id) {
      loadProjectData()
    }
  }, [id])

  const loadProjectData = async () => {
    try {
      // Load project details
      const { data: projectData, error: projectError } = await supabase
        .from('projects')
        .select('*')
        .eq('id', id)
        .single()

      if (projectError) throw projectError
      setProject(projectData)

      // Load project scans
      const { data: scansData, error: scansError } = await supabase
        .from('scans')
        .select('*')
        .eq('project_id', id)
        .order('created_at', { ascending: false })

      if (scansError) throw scansError
      setScans(scansData || [])

      // Calculate statistics
      calculateStats(scansData || [])
    } catch (error) {
      console.error('Error loading project data:', error)
    } finally {
      setLoading(false)
    }
  }

  const calculateStats = (scansData: Scan[]) => {
    const completedScans = scansData.filter(scan => scan.status === 'completed')
    
    // Calculate average duration
    const durations = completedScans
      .filter(scan => scan.completed_at)
      .map(scan => {
        const start = new Date(scan.created_at).getTime()
        const end = new Date(scan.completed_at!).getTime()
        return end - start
      })
    
    const avgDuration = durations.length > 0 
      ? durations.reduce((a, b) => a + b, 0) / durations.length 
      : 0

    // Sum up all issues
    const totalIssues = completedScans.reduce((sum, scan) => sum + scan.total_issues, 0)
    const criticalIssues = completedScans.reduce((sum, scan) => sum + scan.critical_issues, 0)
    const highIssues = completedScans.reduce((sum, scan) => sum + scan.high_issues, 0)
    const mediumIssues = completedScans.reduce((sum, scan) => sum + scan.medium_issues, 0)
    const lowIssues = completedScans.reduce((sum, scan) => sum + scan.low_issues, 0)

    setStats({
      totalScans: scansData.length,
      completedScans: completedScans.length,
      averageDuration: avgDuration,
      lastScanDate: scansData[0]?.created_at || null,
      totalIssues,
      criticalIssues,
      highIssues,
      mediumIssues,
      lowIssues
    })
  }

  const handleScan = async () => {
    try {
      setScanningProject(true)
      
      if (!project) throw new Error('Project not loaded')

      // Use real scanning for all projects
      const repositoryUrl = project.github_repo_url || 'https://github.com/OWASP/NodeGoat' // Default demo repo
      
      const result = await startRepositoryScan(id!, {
        repositoryUrl: repositoryUrl,
        branch: project.github_default_branch || 'main',
        scanType: 'comprehensive'
      })
      
      console.log('Real security scan initiated:', result)
      
      // Reload project data to update scan history
      setTimeout(() => {
        loadProjectData()
      }, 1000)
      
      // Navigate to the scan results page
      navigate(`/scans/${result.scanId}/results`)
    } catch (error) {
      console.error('Error creating scan:', error)
      alert(`Failed to start scan: ${error instanceof Error ? error.message : 'Unknown error'}`)
    } finally {
      setScanningProject(false)
    }
  }

  const handleDelete = async () => {
    if (!confirm('Are you sure you want to delete this project? This action cannot be undone.')) {
      return
    }

    try {
      setDeleting(true)
      
      // Delete all scan results first
      const { error: scanResultsError } = await supabase
        .from('scan_results')
        .delete()
        .in('scan_id', scans.map(scan => scan.id))

      if (scanResultsError) throw scanResultsError

      // Delete all scans
      const { error: scansError } = await supabase
        .from('scans')
        .delete()
        .eq('project_id', id)

      if (scansError) throw scansError

      // Delete the project
      const { error: projectError } = await supabase
        .from('projects')
        .delete()
        .eq('id', id)

      if (projectError) throw projectError

      navigate('/projects')
    } catch (error) {
      console.error('Error deleting project:', error)
      alert('Failed to delete project. Please try again.')
    } finally {
      setDeleting(false)
    }
  }

  const formatDuration = (ms: number) => {
    const seconds = Math.floor(ms / 1000)
    const minutes = Math.floor(seconds / 60)
    const hours = Math.floor(minutes / 60)
    
    if (hours > 0) return `${hours}h ${minutes % 60}m`
    if (minutes > 0) return `${minutes}m ${seconds % 60}s`
    return `${seconds}s`
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed':
        return <CheckCircleIcon className="h-5 w-5 text-green-500" />
      case 'failed':
        return <XCircleIcon className="h-5 w-5 text-red-500" />
      case 'running':
        return <ClockIcon className="h-5 w-5 text-blue-500 animate-spin" />
      default:
        return <ClockIcon className="h-5 w-5 text-gray-400" />
    }
  }

  if (loading) {
    return (
      <div className="p-6">
        <LoadingSpinner size="lg" className="h-64" />
      </div>
    )
  }

  if (!project) {
    return (
      <div className="p-6">
        <div className="text-center py-12">
          <h3 className="text-lg font-medium text-gray-900 mb-2">Project not found</h3>
          <Link to="/projects" className="text-blue-600 hover:text-blue-700">
            Back to projects
          </Link>
        </div>
      </div>
    )
  }

  return (
    <div className="p-6">
      {/* Header */}
      <div className="mb-8">
        <Link 
          to="/projects" 
          className="inline-flex items-center text-gray-600 hover:text-gray-900 mb-4"
        >
          <ArrowLeftIcon className="h-4 w-4 mr-2" />
          Back to projects
        </Link>
        
        <div className="flex justify-between items-start">
          <div>
            <h1 className="text-3xl font-bold text-gray-900">{project.name}</h1>
            {project.description && (
              <p className="text-gray-600 mt-2">{project.description}</p>
            )}
            
            <div className="flex items-center space-x-4 mt-4 text-sm text-gray-500">
              {project.github_repo_url && (
                <a 
                  href={project.github_repo_url} 
                  target="_blank" 
                  rel="noopener noreferrer"
                  className="flex items-center hover:text-gray-700"
                >
                  <GitBranchIcon className="h-4 w-4 mr-1" />
                  Repository
                  <ExternalLinkIcon className="h-3 w-3 ml-1" />
                </a>
              )}
              <span className="flex items-center">
                <CalendarIcon className="h-4 w-4 mr-1" />
                Created {new Date(project.created_at).toLocaleDateString()}
              </span>
              <span className="flex items-center">
                <ActivityIcon className="h-4 w-4 mr-1" />
                {project.is_active ? 'Active' : 'Inactive'}
              </span>
            </div>
          </div>
          
          <div className="flex space-x-2">
            <button 
              onClick={handleScan}
              disabled={scanningProject}
              className="btn-primary flex items-center"
            >
              {scanningProject ? (
                <LoadingSpinner size="sm" className="mr-2" />
              ) : (
                <PlayIcon className="h-4 w-4 mr-2" />
              )}
              New Scan
            </button>
            <button 
              onClick={() => alert('Edit functionality coming soon!')}
              className="btn-secondary flex items-center"
            >
              <EditIcon className="h-4 w-4 mr-2" />
              Edit
            </button>
            <button 
              onClick={handleDelete}
              disabled={deleting}
              className="btn-secondary text-red-600 hover:bg-red-50 flex items-center"
            >
              {deleting ? (
                <LoadingSpinner size="sm" className="mr-2" />
              ) : (
                <TrashIcon className="h-4 w-4 mr-2" />
              )}
              Delete
            </button>
          </div>
        </div>
      </div>

      {/* Statistics Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        <div className="card p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-medium text-gray-600">Total Scans</h3>
            <ShieldCheckIcon className="h-8 w-8 text-blue-500" />
          </div>
          <div className="text-2xl font-bold text-gray-900">{stats.totalScans}</div>
          <p className="text-sm text-gray-500 mt-1">
            {stats.completedScans} completed
          </p>
        </div>

        <div className="card p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-medium text-gray-600">Total Issues</h3>
            <AlertTriangleIcon className="h-8 w-8 text-yellow-500" />
          </div>
          <div className="text-2xl font-bold text-gray-900">{stats.totalIssues}</div>
          <div className="flex space-x-4 mt-2">
            {stats.criticalIssues > 0 && (
              <span className="text-xs text-red-600">{stats.criticalIssues} critical</span>
            )}
            {stats.highIssues > 0 && (
              <span className="text-xs text-orange-600">{stats.highIssues} high</span>
            )}
          </div>
        </div>

        <div className="card p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-medium text-gray-600">Avg Scan Time</h3>
            <ClockIcon className="h-8 w-8 text-green-500" />
          </div>
          <div className="text-2xl font-bold text-gray-900">
            {stats.averageDuration > 0 ? formatDuration(stats.averageDuration) : '-'}
          </div>
          <p className="text-sm text-gray-500 mt-1">Per scan</p>
        </div>

        <div className="card p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-medium text-gray-600">Last Scan</h3>
            <CalendarIcon className="h-8 w-8 text-purple-500" />
          </div>
          <div className="text-2xl font-bold text-gray-900">
            {stats.lastScanDate 
              ? new Date(stats.lastScanDate).toLocaleDateString() 
              : 'Never'
            }
          </div>
          <p className="text-sm text-gray-500 mt-1">
            {stats.lastScanDate && (
              new Date(stats.lastScanDate).toLocaleTimeString()
            )}
          </p>
        </div>
      </div>

      {/* Scan History */}
      <div className="card">
        <div className="p-6 border-b border-gray-200">
          <h2 className="text-xl font-semibold text-gray-900">Scan History</h2>
        </div>
        
        {scans.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Status
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Type
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Date
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Duration
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Issues Found
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Triggered By
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {scans.map((scan) => {
                  const duration = scan.completed_at 
                    ? new Date(scan.completed_at).getTime() - new Date(scan.created_at).getTime()
                    : null
                  
                  return (
                    <tr key={scan.id} className="hover:bg-gray-50">
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="flex items-center">
                          {getStatusIcon(scan.status)}
                          <span className={`ml-2 badge ${
                            scan.status === 'completed' ? 'badge-low' :
                            scan.status === 'running' ? 'badge-medium' :
                            scan.status === 'failed' ? 'badge-critical' : 'badge-info'
                          }`}>
                            {scan.status}
                          </span>
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                        {scan.scan_type}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                        {new Date(scan.created_at).toLocaleString()}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                        {duration ? formatDuration(duration) : '-'}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm">
                        {scan.status === 'completed' && (
                          <div className="flex space-x-2">
                            {scan.critical_issues > 0 && (
                              <span className="badge badge-critical">
                                {scan.critical_issues} critical
                              </span>
                            )}
                            {scan.high_issues > 0 && (
                              <span className="badge badge-high">
                                {scan.high_issues} high
                              </span>
                            )}
                            {scan.medium_issues > 0 && (
                              <span className="badge badge-medium">
                                {scan.medium_issues} medium
                              </span>
                            )}
                            {scan.low_issues > 0 && (
                              <span className="badge badge-low">
                                {scan.low_issues} low
                              </span>
                            )}
                            {scan.total_issues === 0 && (
                              <span className="text-green-600">No issues</span>
                            )}
                          </div>
                        )}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                        {scan.triggered_by || 'Manual'}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm">
                        {scan.status === 'completed' && (
                          <Link
                            to={`/scans/${scan.id}/results`}
                            className="text-blue-600 hover:text-blue-700 font-medium"
                          >
                            View Results
                          </Link>
                        )}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="p-8 text-center">
            <PackageIcon className="h-12 w-12 text-gray-400 mx-auto mb-4" />
            <p className="text-gray-500">No scans yet</p>
            <button 
              onClick={handleScan}
              className="btn-primary mt-4"
            >
              <PlayIcon className="h-4 w-4 mr-2" />
              Run First Scan
            </button>
          </div>
        )}
      </div>
    </div>
  )
}