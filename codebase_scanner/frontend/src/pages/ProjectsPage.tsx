import { useState, useEffect } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { supabase } from '../lib/supabase'
import { 
  Plus, 
  Folder, 
  GitBranch,
  Calendar,
  ShieldCheck,
  Play,
  RefreshCw,
  AlertCircle,
  CheckCircle2,
  Clock,
  XCircle,
  Search,
  Filter,
  Grid,
  List,
  TrendingUp,
  Activity,
  BarChart3
} from 'lucide-react'
import LoadingSpinner from '../components/ui/LoadingSpinner'
import CreateProjectModal from '../components/forms/CreateProjectModal'
import { listProjects, Project } from '../services/projectService'
import { getFullApiUrl } from '../utils/api-config'

interface ProjectWithStats extends Project {
  scan_count?: number
  last_scan?: any
}

export default function ProjectsPage() {
  const [projects, setProjects] = useState<ProjectWithStats[]>([])
  const [loading, setLoading] = useState(true)
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [scanningProject, setScanningProject] = useState<string | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [viewMode, setViewMode] = useState<'grid' | 'list'>('grid')
  const [filterStatus, setFilterStatus] = useState<'all' | 'active' | 'needs-scan'>('all')
  const navigate = useNavigate()

  useEffect(() => {
    loadProjects()
    // Set up auto-refresh every 30 seconds
    const interval = setInterval(loadProjects, 30000)
    return () => clearInterval(interval)
  }, [])

  const loadProjects = async () => {
    try {
      console.log('Loading projects...')
      const response = await listProjects(0, 50)
      console.log('Projects response:', response)
      
      const projectsWithStats = await Promise.all(
        response.projects.map(async (project) => {
          try {
            const { data: scans, error: scanError } = await supabase
              .from('scans')
              .select('id, status, created_at, total_issues')
              .eq('project_id', parseInt(project.id))
              .order('created_at', { ascending: false })
            
            if (scanError) {
              console.error(`Error loading scans for project ${project.id}:`, scanError)
            }
            
            return {
              ...project,
              scan_count: scans?.length || 0,
              last_scan: scans?.[0] || null
            } as ProjectWithStats
          } catch (error) {
            console.error(`Error loading scans for project ${project.id}:`, error)
            return {
              ...project,
              scan_count: 0,
              last_scan: null
            } as ProjectWithStats
          }
        })
      )

      console.log('Projects with stats:', projectsWithStats)
      setProjects(projectsWithStats)
    } catch (error) {
      console.error('Error loading projects:', error)
    } finally {
      setLoading(false)
    }
  }

  const handleProjectCreated = async () => {
    setShowCreateModal(false)
    setTimeout(() => {
      console.log('Refreshing projects after creation...')
      loadProjects()
    }, 500)
  }

  const handleScan = async (projectId: string) => {
    console.log('=== SCAN BUTTON CLICKED ===')
    console.log('Project ID:', projectId)
    
    try {
      setScanningProject(projectId)
      const project = projects.find(p => p.id === projectId)
      console.log('Found project:', project)
      
      if (!project) throw new Error('Project not found')

      const { data: { user } } = await supabase.auth.getUser()
      console.log('User:', user)
      
      if (!user) throw new Error('No user found')

      const repositoryUrl = project.repository_url || 'https://github.com/OWASP/NodeGoat'
      
      console.log('Starting scan for:', repositoryUrl)
      console.log('API URL:', getFullApiUrl('/api/scans/quick-production'))
      
      const response = await fetch(getFullApiUrl('/api/scans/quick-production'), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          project_id: projectId,
          repository_url: repositoryUrl,
          branch: 'main',
          scan_type: 'comprehensive',
          user_id: user.id
        })
      })

      const responseText = await response.text()
      console.log('Response status:', response.status)
      console.log('Response text:', responseText)

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${responseText}`)
      }

      let scanResult
      try {
        scanResult = JSON.parse(responseText)
      } catch (e) {
        throw new Error(`Invalid response: ${responseText}`)
      }
      
      if (scanResult.error) {
        throw new Error(scanResult.error)
      }

      console.log('Scan initiated:', scanResult)
      
      // Show success message
      const successDiv = document.createElement('div')
      successDiv.className = 'fixed bottom-4 right-4 bg-green-500 text-white px-6 py-3 rounded-lg shadow-lg flex items-center space-x-2 animate-slide-up'
      successDiv.innerHTML = `
        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path>
        </svg>
        <span>Security scan started successfully!</span>
      `
      document.body.appendChild(successDiv)
      setTimeout(() => successDiv.remove(), 3000)

      // Refresh projects after a delay
      setTimeout(() => {
        loadProjects()
      }, 2000)

      // Navigate to scan results if we have an ID
      if (scanResult.id) {
        setTimeout(() => {
          navigate(`/scans/${scanResult.id}/results`)
        }, 1500)
      }
    } catch (error) {
      console.error('Error starting scan:', error)
      
      // Show error message
      const errorDiv = document.createElement('div')
      errorDiv.className = 'fixed bottom-4 right-4 bg-red-500 text-white px-6 py-3 rounded-lg shadow-lg flex items-center space-x-2 animate-slide-up'
      errorDiv.innerHTML = `
        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
        </svg>
        <span>${error instanceof Error ? error.message : 'Failed to start scan'}</span>
      `
      document.body.appendChild(errorDiv)
      setTimeout(() => errorDiv.remove(), 5000)
    } finally {
      setScanningProject(null)
    }
  }

  const filteredProjects = projects.filter(project => {
    const matchesSearch = project.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
                         project.description?.toLowerCase().includes(searchQuery.toLowerCase()) ||
                         project.repository_url?.toLowerCase().includes(searchQuery.toLowerCase())
    
    const matchesFilter = filterStatus === 'all' ||
                         (filterStatus === 'active' && project.last_scan) ||
                         (filterStatus === 'needs-scan' && !project.last_scan)
    
    return matchesSearch && matchesFilter
  })

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed':
        return <CheckCircle2 className="h-5 w-5 text-green-500" />
      case 'running':
        return <Clock className="h-5 w-5 text-blue-500 animate-pulse" />
      case 'failed':
        return <XCircle className="h-5 w-5 text-red-500" />
      default:
        return <AlertCircle className="h-5 w-5 text-gray-400" />
    }
  }

  const getSecurityScore = (project: ProjectWithStats) => {
    if (!project.last_scan) return null
    const issues = project.last_scan.total_issues || 0
    if (issues === 0) return { score: 'A+', color: 'text-green-600', bg: 'bg-green-50' }
    if (issues <= 5) return { score: 'A', color: 'text-green-600', bg: 'bg-green-50' }
    if (issues <= 10) return { score: 'B', color: 'text-blue-600', bg: 'bg-blue-50' }
    if (issues <= 20) return { score: 'C', color: 'text-yellow-600', bg: 'bg-yellow-50' }
    if (issues <= 30) return { score: 'D', color: 'text-orange-600', bg: 'bg-orange-50' }
    return { score: 'F', color: 'text-red-600', bg: 'bg-red-50' }
  }

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-center">
          <LoadingSpinner size="lg" />
          <p className="mt-4 text-gray-600">Loading your security projects...</p>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Version indicator for debugging */}
      <div className="bg-green-600 text-white text-center py-1 text-xs">
        v2.0 - Modern UI Update - {new Date().toISOString()}
      </div>
      
      {/* Modern Header */}
      <div className="bg-white shadow-sm border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="py-6">
            <div className="flex items-center justify-between">
              <div>
                <h1 className="text-3xl font-bold text-gray-900">Security Dashboard</h1>
                <p className="mt-1 text-sm text-gray-500">
                  Monitor and scan your repositories for security vulnerabilities
                </p>
              </div>
              <button
                onClick={() => setShowCreateModal(true)}
                className="inline-flex items-center px-4 py-2 bg-blue-600 text-white text-sm font-medium rounded-lg hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 transition-colors"
              >
                <Plus className="h-5 w-5 mr-2" />
                New Project
              </button>
            </div>

            {/* Stats Overview */}
            <div className="mt-6 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              <div className="bg-gray-50 rounded-lg p-4">
                <div className="flex items-center">
                  <div className="p-2 bg-blue-100 rounded-lg">
                    <Folder className="h-6 w-6 text-blue-600" />
                  </div>
                  <div className="ml-4">
                    <p className="text-sm font-medium text-gray-500">Total Projects</p>
                    <p className="text-2xl font-bold text-gray-900">{projects.length}</p>
                  </div>
                </div>
              </div>
              
              <div className="bg-gray-50 rounded-lg p-4">
                <div className="flex items-center">
                  <div className="p-2 bg-green-100 rounded-lg">
                    <ShieldCheck className="h-6 w-6 text-green-600" />
                  </div>
                  <div className="ml-4">
                    <p className="text-sm font-medium text-gray-500">Total Scans</p>
                    <p className="text-2xl font-bold text-gray-900">
                      {projects.reduce((sum, p) => sum + (p.scan_count || 0), 0)}
                    </p>
                  </div>
                </div>
              </div>
              
              <div className="bg-gray-50 rounded-lg p-4">
                <div className="flex items-center">
                  <div className="p-2 bg-yellow-100 rounded-lg">
                    <Activity className="h-6 w-6 text-yellow-600" />
                  </div>
                  <div className="ml-4">
                    <p className="text-sm font-medium text-gray-500">Active Scans</p>
                    <p className="text-2xl font-bold text-gray-900">
                      {projects.filter(p => p.last_scan?.status === 'running').length}
                    </p>
                  </div>
                </div>
              </div>
              
              <div className="bg-gray-50 rounded-lg p-4">
                <div className="flex items-center">
                  <div className="p-2 bg-red-100 rounded-lg">
                    <AlertCircle className="h-6 w-6 text-red-600" />
                  </div>
                  <div className="ml-4">
                    <p className="text-sm font-medium text-gray-500">Needs Attention</p>
                    <p className="text-2xl font-bold text-gray-900">
                      {projects.filter(p => !p.last_scan || p.last_scan.status === 'failed').length}
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Search and Filters */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div className="flex-1 max-w-lg">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-5 w-5 text-gray-400" />
              <input
                type="text"
                placeholder="Search projects..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>
          </div>
          
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2">
              <Filter className="h-5 w-5 text-gray-400" />
              <select
                value={filterStatus}
                onChange={(e) => setFilterStatus(e.target.value as any)}
                className="border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              >
                <option value="all">All Projects</option>
                <option value="active">Active Projects</option>
                <option value="needs-scan">Needs Scan</option>
              </select>
            </div>
            
            <div className="flex items-center border border-gray-300 rounded-lg">
              <button
                onClick={() => setViewMode('grid')}
                className={`p-2 ${viewMode === 'grid' ? 'bg-gray-100 text-gray-900' : 'text-gray-500'}`}
              >
                <Grid className="h-5 w-5" />
              </button>
              <button
                onClick={() => setViewMode('list')}
                className={`p-2 ${viewMode === 'list' ? 'bg-gray-100 text-gray-900' : 'text-gray-500'}`}
              >
                <List className="h-5 w-5" />
              </button>
            </div>
            
            <button
              onClick={loadProjects}
              className="inline-flex items-center px-3 py-2 border border-gray-300 rounded-lg text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
            >
              <RefreshCw className="h-4 w-4 mr-2" />
              Refresh
            </button>
          </div>
        </div>

        {/* Projects Display */}
        {filteredProjects.length > 0 ? (
          viewMode === 'grid' ? (
            <div className="mt-6 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {filteredProjects.map((project) => {
                const score = getSecurityScore(project)
                const isScanning = scanningProject === project.id
                
                return (
                  <div key={project.id} className="bg-white rounded-lg shadow-sm hover:shadow-md transition-shadow border border-gray-200">
                    <div className="p-6">
                      <div className="flex items-start justify-between mb-4">
                        <div className="flex-1">
                          <h3 className="text-lg font-semibold text-gray-900 mb-1">{project.name}</h3>
                          {project.description && (
                            <p className="text-sm text-gray-600 line-clamp-2">{project.description}</p>
                          )}
                        </div>
                        {score && (
                          <div className={`ml-4 px-3 py-1 rounded-full ${score.bg}`}>
                            <span className={`text-lg font-bold ${score.color}`}>{score.score}</span>
                          </div>
                        )}
                      </div>

                      {project.repository_url && (
                        <div className="flex items-center text-sm text-gray-500 mb-3">
                          <GitBranch className="h-4 w-4 mr-2" />
                          <span className="truncate">{project.repository_url}</span>
                        </div>
                      )}

                      <div className="flex items-center justify-between text-sm text-gray-500 mb-4">
                        <div className="flex items-center">
                          <Calendar className="h-4 w-4 mr-1" />
                          <span>{new Date(project.created_at).toLocaleDateString()}</span>
                        </div>
                        <div className="flex items-center">
                          <BarChart3 className="h-4 w-4 mr-1" />
                          <span>{project.scan_count} scans</span>
                        </div>
                      </div>

                      {project.last_scan && (
                        <div className="mb-4 p-3 bg-gray-50 rounded-lg">
                          <div className="flex items-center justify-between">
                            <span className="text-sm font-medium text-gray-700">Last Scan</span>
                            {getStatusIcon(project.last_scan.status)}
                          </div>
                          <div className="mt-1 text-xs text-gray-500">
                            {new Date(project.last_scan.created_at).toLocaleString()}
                          </div>
                          {project.last_scan.total_issues > 0 && (
                            <div className="mt-2 flex items-center text-sm">
                              <AlertCircle className="h-4 w-4 text-orange-500 mr-1" />
                              <span className="text-orange-700 font-medium">
                                {project.last_scan.total_issues} issues found
                              </span>
                            </div>
                          )}
                        </div>
                      )}

                      <div className="flex gap-2">
                        <Link
                          to={`/projects/${project.id}`}
                          className="flex-1 inline-flex items-center justify-center px-4 py-2 border border-gray-300 rounded-lg text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
                        >
                          View Details
                        </Link>
                        <button 
                          className="inline-flex items-center justify-center px-4 py-2 bg-blue-600 text-white text-sm font-medium rounded-lg hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                          onClick={() => {
                            alert(`Scan button clicked for project: ${project.name}`)
                            handleScan(project.id)
                          }}
                          disabled={isScanning}
                        >
                          {isScanning ? (
                            <>
                              <LoadingSpinner size="sm" className="mr-2" />
                              Scanning...
                            </>
                          ) : (
                            <>
                              <Play className="h-4 w-4 mr-2" />
                              Scan Now
                            </>
                          )}
                        </button>
                      </div>
                    </div>
                  </div>
                )
              })}
            </div>
          ) : (
            <div className="mt-6 bg-white shadow-sm rounded-lg border border-gray-200">
              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-gray-200">
                  <thead className="bg-gray-50">
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Project
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Repository
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Status
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Score
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Scans
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Actions
                      </th>
                    </tr>
                  </thead>
                  <tbody className="bg-white divide-y divide-gray-200">
                    {filteredProjects.map((project) => {
                      const score = getSecurityScore(project)
                      const isScanning = scanningProject === project.id
                      
                      return (
                        <tr key={project.id} className="hover:bg-gray-50">
                          <td className="px-6 py-4 whitespace-nowrap">
                            <div>
                              <div className="text-sm font-medium text-gray-900">{project.name}</div>
                              {project.description && (
                                <div className="text-sm text-gray-500">{project.description}</div>
                              )}
                            </div>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            {project.repository_url ? (
                              <div className="flex items-center text-sm text-gray-500">
                                <GitBranch className="h-4 w-4 mr-2" />
                                <span className="truncate max-w-xs">{project.repository_url}</span>
                              </div>
                            ) : (
                              <span className="text-sm text-gray-400">No repository</span>
                            )}
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            {project.last_scan ? (
                              <div className="flex items-center">
                                {getStatusIcon(project.last_scan.status)}
                                <span className="ml-2 text-sm text-gray-600">
                                  {project.last_scan.status}
                                </span>
                              </div>
                            ) : (
                              <span className="text-sm text-gray-400">Never scanned</span>
                            )}
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            {score ? (
                              <div className={`inline-flex px-3 py-1 rounded-full ${score.bg}`}>
                                <span className={`text-sm font-bold ${score.color}`}>{score.score}</span>
                              </div>
                            ) : (
                              <span className="text-sm text-gray-400">-</span>
                            )}
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                            {project.scan_count}
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                            <div className="flex items-center gap-2">
                              <Link
                                to={`/projects/${project.id}`}
                                className="text-blue-600 hover:text-blue-900"
                              >
                                View
                              </Link>
                              <button 
                                className="inline-flex items-center text-blue-600 hover:text-blue-900 disabled:opacity-50 disabled:cursor-not-allowed"
                                onClick={() => handleScan(project.id)}
                                disabled={isScanning}
                              >
                                {isScanning ? (
                                  <>
                                    <LoadingSpinner size="sm" className="mr-1" />
                                    Scanning
                                  </>
                                ) : (
                                  <>
                                    <Play className="h-4 w-4 mr-1" />
                                    Scan
                                  </>
                                )}
                              </button>
                            </div>
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          )
        ) : (
          /* Empty State */
          <div className="mt-12 text-center">
            <div className="mx-auto h-24 w-24 bg-gray-100 rounded-full flex items-center justify-center">
              <Folder className="h-12 w-12 text-gray-400" />
            </div>
            <h3 className="mt-6 text-lg font-medium text-gray-900">No projects found</h3>
            <p className="mt-2 text-sm text-gray-500 max-w-md mx-auto">
              {searchQuery || filterStatus !== 'all' 
                ? 'Try adjusting your search or filter criteria'
                : 'Get started by creating your first security scanning project'
              }
            </p>
            {!searchQuery && filterStatus === 'all' && (
              <button
                onClick={() => setShowCreateModal(true)}
                className="mt-6 inline-flex items-center px-4 py-2 bg-blue-600 text-white text-sm font-medium rounded-lg hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
              >
                <Plus className="h-5 w-5 mr-2" />
                Create Your First Project
              </button>
            )}
          </div>
        )}
      </div>

      {/* Create Project Modal */}
      {showCreateModal && (
        <CreateProjectModal
          onClose={() => setShowCreateModal(false)}
          onSuccess={handleProjectCreated}
        />
      )}
      
      {/* Add animations */}
      <style>{`
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
        .line-clamp-2 {
          overflow: hidden;
          display: -webkit-box;
          -webkit-line-clamp: 2;
          -webkit-box-orient: vertical;
        }
      `}</style>
    </div>
  )
}