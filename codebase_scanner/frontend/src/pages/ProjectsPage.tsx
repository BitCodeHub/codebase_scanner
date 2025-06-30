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
import { simulateScan } from '../services/scanService'

interface Project {
  id: number
  name: string
  description: string
  github_repo_url: string
  created_at: string
  updated_at: string
  scan_count?: number
  last_scan?: any
}

export default function ProjectsPage() {
  const [projects, setProjects] = useState<Project[]>([])
  const [loading, setLoading] = useState(true)
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [scanningProject, setScanningProject] = useState<number | null>(null)
  const navigate = useNavigate()

  useEffect(() => {
    loadProjects()
  }, [])

  const loadProjects = async () => {
    try {
      const { data, error } = await supabase
        .from('projects')
        .select(`
          *,
          scans (
            id,
            status,
            created_at,
            total_issues
          )
        `)
        .order('updated_at', { ascending: false })

      if (error) throw error

      // Process projects to add scan statistics
      const processedProjects = data.map((project: any) => ({
        ...project,
        scan_count: project.scans?.length || 0,
        last_scan: project.scans?.[0] || null
      }))

      setProjects(processedProjects)
    } catch (error) {
      console.error('Error loading projects:', error)
    } finally {
      setLoading(false)
    }
  }

  const handleProjectCreated = () => {
    setShowCreateModal(false)
    loadProjects()
  }

  const handleScan = async (projectId: number) => {
    try {
      setScanningProject(projectId)
      
      // Get current user
      const { data: { user } } = await supabase.auth.getUser()
      if (!user) throw new Error('No user found')

      // Create a new scan record
      const { data: scan, error } = await supabase
        .from('scans')
        .insert({
          project_id: projectId,
          user_id: user.id,
          scan_type: 'security',
          status: 'pending',
          triggered_by: 'manual',
          scan_config: {
            scanType: 'comprehensive',
            includeTests: true,
            includeDependencies: true,
            severityThreshold: 'low'
          }
        })
        .select()
        .single()

      if (error) throw error

      // Start the scan simulation
      simulateScan(scan.id, projectId).then(() => {
        // Reload projects to update scan count
        loadProjects()
      })

      // Navigate to the scan results page
      navigate(`/scans/${scan.id}/results`)
    } catch (error) {
      console.error('Error creating scan:', error)
      alert('Failed to start scan. Please try again.')
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

  return (
    <div className="p-6">
      {/* Header */}
      <div className="flex justify-between items-center mb-8">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Projects</h1>
          <p className="text-gray-600 mt-2">Manage your security scanning projects</p>
        </div>
        <button
          onClick={() => setShowCreateModal(true)}
          className="btn-primary flex items-center"
        >
          <PlusIcon className="h-5 w-5 mr-2" />
          New Project
        </button>
      </div>

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
                {project.github_repo_url && (
                  <div className="flex items-center text-sm text-gray-600">
                    <GitBranchIcon className="h-4 w-4 mr-2" />
                    <span className="truncate">{project.github_repo_url}</span>
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