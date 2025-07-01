import { useState, useEffect } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { supabase } from '../lib/supabase'
import { 
  PlusIcon, 
  FolderIcon, 
  GitBranchIcon,
  CalendarIcon,
  ShieldCheckIcon,
  PlayIcon
} from 'lucide-react'
import LoadingSpinner from '../components/ui/LoadingSpinner'
import CreateProjectModal from '../components/forms/CreateProjectModal'
// Scan services imported dynamically to avoid dependency issues
import { listProjects, Project } from '../services/projectService'

interface ProjectWithStats extends Project {
  scan_count?: number
  last_scan?: any
}

export default function ProjectsPage() {
  const [projects, setProjects] = useState<ProjectWithStats[]>([])
  const [loading, setLoading] = useState(true)
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [scanningProject, setScanningProject] = useState<string | null>(null)
  const [debugInfo, setDebugInfo] = useState<any>(null)
  const [showDebug, setShowDebug] = useState(false)
  const navigate = useNavigate()

  useEffect(() => {
    loadProjects()
  }, [])

  const loadProjects = async () => {
    try {
      console.log('Loading projects...')
      const response = await listProjects(0, 50)
      console.log('Projects response:', response)
      
      // For now, we'll fetch scan counts separately
      // In a production app, this would be included in the API response
      const projectsWithStats = await Promise.all(
        response.projects.map(async (project) => {
          try {
            // Convert project.id to number for Supabase query since projects table uses BIGSERIAL
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
      setDebugInfo({ loadProjectsError: error })
      setShowDebug(true)
    } finally {
      setLoading(false)
    }
  }

  const handleProjectCreated = async () => {
    setShowCreateModal(false)
    // Add a small delay to ensure database write is complete
    setTimeout(() => {
      console.log('Refreshing projects after creation...')
      loadProjects()
    }, 500)
  }

  const handleScan = async (projectId: string) => {
    try {
      setScanningProject(projectId)
      console.log('Starting real security scan for project:', projectId)
      
      // Find the project to check if it has a repository URL
      const project = projects.find(p => p.id === projectId)
      if (!project) throw new Error('Project not found')

      const { data: { user } } = await supabase.auth.getUser()
      if (!user) throw new Error('No user found')

      console.log('Starting real scan for project ID:', projectId, 'User ID:', user.id)

      // Use simplified repository scanning endpoint
      const { getFullApiUrl } = await import('../utils/api-config')
      const repositoryUrl = project.repository_url || 'https://github.com/OWASP/NodeGoat'
      
      console.log('Starting repository scan for:', repositoryUrl)
      
      const response = await fetch(getFullApiUrl('/api/scans/repository-simple'), {
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

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`)
      }

      const scanResult = await response.json()
      
      if (scanResult.error) {
        throw new Error(scanResult.error)
      }

      console.log('Real scan initiated:', scanResult)

      // Real scanning is now handled by the backend automatically
      console.log('Backend will process the real security scan using Semgrep, Bandit, Safety, and Gitleaks')
      
      // Refresh project list to show scan in progress
      setTimeout(() => {
        loadProjects()
      }, 1000)

      // Navigate to the scan results page
      navigate(`/scans/${scanResult.id}/results`)
    } catch (error) {
      console.error('Error starting scan:', error)
      alert(`Failed to start scan: ${error instanceof Error ? error.message : 'Unknown error'}`)
    } finally {
      setScanningProject(null)
    }
  }

  if (loading) {
    return (
      <div className="p-6">
        <LoadingSpinner size="lg" className="h-64" />
      </div>
    )
  }

  const testScannerTools = async () => {
    try {
      const { getFullApiUrl } = await import('../utils/api-config')
      
      // Test scanner tools availability
      const toolsResponse = await fetch(getFullApiUrl('/api/test/scanner-tools'))
      const toolsResult = await toolsResponse.json()
      
      setDebugInfo({
        timestamp: new Date().toISOString(),
        scannerToolsStatus: toolsResult,
        message: toolsResult.status === 'healthy' 
          ? '✅ All scanning tools are ready!' 
          : '⚠️ Some scanning tools need installation'
      })
      setShowDebug(true)
    } catch (error) {
      setDebugInfo({ 
        error: error instanceof Error ? error.message : 'Unknown error',
        message: '❌ Failed to check scanner tools'
      })
      setShowDebug(true)
    }
  }

  const testDirectCreate = async () => {
    try {
      const session = await supabase.auth.getSession()
      const user = await supabase.auth.getUser()
      const token = session.data.session?.access_token
      const userId = user.data.user?.id

      const debugData: any = {
        timestamp: new Date().toISOString(),
        hasToken: !!token,
        hasUserId: !!userId,
        userId: userId,
        tokenPreview: token ? token.substring(0, 50) + '...' : 'No token',
      }

      // Test the direct endpoint
      if (userId) {
        const { getFullApiUrl } = await import('../utils/api-config')
        
        // Test project creation
        const createResponse = await fetch(getFullApiUrl('/api/test/create-project'), {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            user_id: userId,
            name: 'Debug Test ' + new Date().toISOString(),
            description: 'Testing direct creation'
          })
        })

        const createResult = await createResponse.json()
        debugData.directCreateResult = createResult
        debugData.directCreateStatus = createResponse.status
        
        // Test project listing
        const listResponse = await fetch(getFullApiUrl('/api/test/list-projects'))
        const listResult = await listResponse.json()
        debugData.directListResult = listResult
        debugData.directListStatus = listResponse.status
        
        // Test the actual projects API with authentication
        try {
          const projectsResponse = await fetch(getFullApiUrl('/api/projects/'), {
            method: 'GET',
            headers: {
              'Authorization': `Bearer ${token}`
            }
          })
          const projectsResult = await projectsResponse.json()
          debugData.projectsApiResult = projectsResult
          debugData.projectsApiStatus = projectsResponse.status
        } catch (err) {
          debugData.projectsApiError = err instanceof Error ? err.message : 'Unknown error'
        }
      }

      setDebugInfo(debugData)
      setShowDebug(true)
    } catch (error) {
      setDebugInfo({ error: error instanceof Error ? error.message : 'Unknown error' })
      setShowDebug(true)
    }
  }

  return (
    <div className="p-6">
      {/* Header */}
      <div className="flex justify-between items-center mb-8">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Projects</h1>
          <p className="text-gray-600 mt-2">Manage your security scanning projects</p>
        </div>
        <div className="flex space-x-2">
          <button
            onClick={testScannerTools}
            className="btn-secondary flex items-center"
          >
            🔧 Scanner Tools
          </button>
          <button
            onClick={testDirectCreate}
            className="btn-secondary flex items-center"
          >
            Debug
          </button>
          <button
            onClick={() => {
              console.log('Manual refresh triggered')
              loadProjects()
            }}
            className="btn-secondary flex items-center"
          >
            Refresh
          </button>
          <button
            onClick={() => setShowCreateModal(true)}
            className="btn-primary flex items-center"
          >
            <PlusIcon className="h-5 w-5 mr-2" />
            New Project
          </button>
        </div>
      </div>

      {/* Debug Info */}
      {showDebug && debugInfo && (
        <div className="mb-6 p-4 bg-gray-100 rounded-lg">
          <div className="flex justify-between items-center mb-2">
            <h3 className="font-semibold">Debug Information</h3>
            <button onClick={() => setShowDebug(false)} className="text-gray-500 hover:text-gray-700">×</button>
          </div>
          <pre className="text-xs overflow-auto max-h-96">
            {JSON.stringify(debugInfo, null, 2)}
          </pre>
        </div>
      )}

      {/* Projects Grid */}
      {projects.length > 0 ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {projects.map((project) => (
            <div key={project.id} className="card p-6 hover:shadow-md transition-shadow">
              <div className="flex items-start justify-between mb-4">
                <div className="flex items-center">
                  <div className="p-2 bg-blue-100 rounded-lg">
                    <FolderIcon className="h-6 w-6 text-blue-600" />
                  </div>
                  <div className="ml-3">
                    <h3 className="text-lg font-semibold text-gray-900">{project.name}</h3>
                    {project.description && (
                      <p className="text-sm text-gray-600 mt-1">{project.description}</p>
                    )}
                  </div>
                </div>
              </div>

              {/* Project Stats */}
              <div className="space-y-3 mb-4">
                {project.repository_url && (
                  <div className="flex items-center text-sm text-gray-600">
                    <GitBranchIcon className="h-4 w-4 mr-2" />
                    <span className="truncate">{project.repository_url}</span>
                  </div>
                )}
                
                <div className="flex items-center text-sm text-gray-600">
                  <CalendarIcon className="h-4 w-4 mr-2" />
                  <span>Created {new Date(project.created_at).toLocaleDateString()}</span>
                </div>

                <div className="flex items-center text-sm text-gray-600">
                  <ShieldCheckIcon className="h-4 w-4 mr-2" />
                  <span>{project.scan_count} scans</span>
                </div>
              </div>

              {/* Last Scan Info */}
              {project.last_scan && (
                <div className="mb-4 p-3 bg-gray-50 rounded-lg">
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-medium text-gray-700">Last Scan</span>
                    <span className={`badge ${
                      project.last_scan.status === 'completed' ? 'badge-low' :
                      project.last_scan.status === 'running' ? 'badge-medium' :
                      project.last_scan.status === 'failed' ? 'badge-critical' : 'badge-info'
                    }`}>
                      {project.last_scan.status}
                    </span>
                  </div>
                  <div className="text-xs text-gray-500 mt-1">
                    {new Date(project.last_scan.created_at).toLocaleDateString()}
                  </div>
                  {project.last_scan.total_issues > 0 && (
                    <div className="text-xs text-red-600 mt-1">
                      {project.last_scan.total_issues} issues found
                    </div>
                  )}
                </div>
              )}

              {/* Actions */}
              <div className="flex space-x-2">
                <Link
                  to={`/projects/${project.id}`}
                  className="btn-primary flex-1 text-center"
                >
                  View Details
                </Link>
                <button 
                  className="btn-secondary flex items-center justify-center"
                  onClick={() => handleScan(project.id)}
                  disabled={scanningProject === project.id}
                >
                  {scanningProject === project.id ? (
                    <LoadingSpinner size="sm" />
                  ) : (
                    <>
                      <PlayIcon className="h-4 w-4 mr-1" />
                      Scan Now
                    </>
                  )}
                </button>
              </div>
            </div>
          ))}
        </div>
      ) : (
        /* Empty State */
        <div className="text-center py-12">
          <div className="p-4 bg-gray-100 rounded-full w-16 h-16 mx-auto mb-4 flex items-center justify-center">
            <FolderIcon className="h-8 w-8 text-gray-400" />
          </div>
          <h3 className="text-lg font-medium text-gray-900 mb-2">No projects yet</h3>
          <p className="text-gray-600 mb-6">
            Get started by creating your first security scanning project
          </p>
          <button
            onClick={() => setShowCreateModal(true)}
            className="btn-primary"
          >
            <PlusIcon className="h-5 w-5 mr-2" />
            Create Your First Project
          </button>
        </div>
      )}

      {/* Create Project Modal */}
      {showCreateModal && (
        <CreateProjectModal
          onClose={() => setShowCreateModal(false)}
          onSuccess={handleProjectCreated}
        />
      )}
    </div>
  )
}