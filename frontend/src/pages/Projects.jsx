import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { apiService as api } from '../services/api'
import { FolderPlusIcon, DocumentArrowUpIcon, LinkIcon, ShieldCheckIcon, ClockIcon, ChartBarIcon } from '@heroicons/react/24/outline'
import { CodeBracketIcon } from '@heroicons/react/24/solid'

export default function Projects() {
  const [projects, setProjects] = useState([])
  const [loading, setLoading] = useState(true)
  const [showNewProject, setShowNewProject] = useState(false)
  const [newProject, setNewProject] = useState({ 
    name: '', 
    description: '', 
    github_repo_url: '',
    upload_type: 'file' // 'file' or 'github'
  })
  const [selectedFile, setSelectedFile] = useState(null)

  useEffect(() => {
    fetchProjects()
  }, [])

  const fetchProjects = async () => {
    try {
      const data = await api.getProjects()
      setProjects(data)
    } catch (error) {
      console.error('Failed to fetch projects:', error)
    } finally {
      setLoading(false)
    }
  }

  const handleCreateProject = async (e) => {
    e.preventDefault()
    try {
      const projectData = {
        name: newProject.name,
        description: newProject.description,
        ...(newProject.upload_type === 'github' && { github_repo_url: newProject.github_repo_url })
      }
      const project = await api.createProject(projectData)
      
      // If file is selected, upload it
      if (selectedFile && newProject.upload_type === 'file') {
        try {
          await api.uploadCodeToProject(project.id, selectedFile)
        } catch (uploadError) {
          console.error('Failed to upload file:', uploadError)
        }
      }
      
      setProjects([...projects, project])
      setShowNewProject(false)
      setNewProject({ name: '', description: '', github_repo_url: '', upload_type: 'file' })
      setSelectedFile(null)
    } catch (error) {
      console.error('Failed to create project:', error)
    }
  }

  if (loading) {
    return (
      <div className="flex justify-center items-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-600"></div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Header */}
        <div className="mb-8">
          <div className="flex justify-between items-center">
            <div>
              <h1 className="text-3xl font-bold text-gray-900">Projects</h1>
              <p className="mt-2 text-sm text-gray-600">
                Manage your code repositories and track security scans
              </p>
            </div>
            <button
              onClick={() => setShowNewProject(true)}
              className="inline-flex items-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 transition-colors"
            >
              <FolderPlusIcon className="h-5 w-5 mr-2" />
              New Project
            </button>
          </div>
        </div>

        {/* Create Project Modal */}
        {showNewProject && (
          <div className="mb-8 bg-white rounded-xl shadow-lg overflow-hidden">
            <div className="bg-gradient-to-r from-indigo-600 to-purple-600 px-6 py-4">
              <h2 className="text-xl font-semibold text-white">Create New Project</h2>
            </div>
            <form onSubmit={handleCreateProject} className="p-6">
              <div className="space-y-6">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Project Name
                  </label>
                  <input
                    type="text"
                    value={newProject.name}
                    onChange={(e) => setNewProject({ ...newProject, name: e.target.value })}
                    className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition-all"
                    placeholder="Enter project name"
                    required
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Description
                  </label>
                  <textarea
                    value={newProject.description}
                    onChange={(e) => setNewProject({ ...newProject, description: e.target.value })}
                    className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition-all"
                    rows="3"
                    placeholder="Describe your project"
                  />
                </div>

                {/* Upload Type Selection */}
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Code Source
                  </label>
                  <div className="grid grid-cols-2 gap-4">
                    <button
                      type="button"
                      onClick={() => setNewProject({ ...newProject, upload_type: 'file' })}
                      className={`p-4 border-2 rounded-lg flex flex-col items-center justify-center transition-all ${
                        newProject.upload_type === 'file'
                          ? 'border-indigo-600 bg-indigo-50'
                          : 'border-gray-300 hover:border-gray-400'
                      }`}
                    >
                      <DocumentArrowUpIcon className={`h-8 w-8 mb-2 ${
                        newProject.upload_type === 'file' ? 'text-indigo-600' : 'text-gray-400'
                      }`} />
                      <span className={`text-sm font-medium ${
                        newProject.upload_type === 'file' ? 'text-indigo-600' : 'text-gray-700'
                      }`}>Upload Files</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => setNewProject({ ...newProject, upload_type: 'github' })}
                      className={`p-4 border-2 rounded-lg flex flex-col items-center justify-center transition-all ${
                        newProject.upload_type === 'github'
                          ? 'border-indigo-600 bg-indigo-50'
                          : 'border-gray-300 hover:border-gray-400'
                      }`}
                    >
                      <LinkIcon className={`h-8 w-8 mb-2 ${
                        newProject.upload_type === 'github' ? 'text-indigo-600' : 'text-gray-400'
                      }`} />
                      <span className={`text-sm font-medium ${
                        newProject.upload_type === 'github' ? 'text-indigo-600' : 'text-gray-700'
                      }`}>GitHub URL</span>
                    </button>
                  </div>
                </div>

                {/* Conditional Input Based on Upload Type */}
                {newProject.upload_type === 'file' ? (
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">
                      Upload Code Files
                    </label>
                    <div className="mt-1 flex justify-center px-6 pt-5 pb-6 border-2 border-gray-300 border-dashed rounded-lg hover:border-gray-400 transition-colors">
                      <div className="space-y-1 text-center">
                        <DocumentArrowUpIcon className="mx-auto h-12 w-12 text-gray-400" />
                        <div className="flex text-sm text-gray-600">
                          <label htmlFor="file-upload" className="relative cursor-pointer bg-white rounded-md font-medium text-indigo-600 hover:text-indigo-500 focus-within:outline-none focus-within:ring-2 focus-within:ring-offset-2 focus-within:ring-indigo-500">
                            <span>Upload files</span>
                            <input
                              id="file-upload"
                              name="file-upload"
                              type="file"
                              className="sr-only"
                              multiple
                              onChange={(e) => setSelectedFile(e.target.files[0])}
                            />
                          </label>
                          <p className="pl-1">or drag and drop</p>
                        </div>
                        <p className="text-xs text-gray-500">
                          ZIP, TAR, or individual source files
                        </p>
                        {selectedFile && (
                          <p className="text-sm text-indigo-600 mt-2">
                            Selected: {selectedFile.name}
                          </p>
                        )}
                      </div>
                    </div>
                  </div>
                ) : (
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">
                      GitHub Repository URL
                    </label>
                    <input
                      type="url"
                      value={newProject.github_repo_url}
                      onChange={(e) => setNewProject({ ...newProject, github_repo_url: e.target.value })}
                      className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition-all"
                      placeholder="https://github.com/username/repository"
                    />
                  </div>
                )}
              </div>

              <div className="mt-6 flex justify-end gap-3">
                <button
                  type="button"
                  onClick={() => {
                    setShowNewProject(false)
                    setNewProject({ name: '', description: '', github_repo_url: '', upload_type: 'file' })
                    setSelectedFile(null)
                  }}
                  className="px-4 py-2 border border-gray-300 rounded-lg text-gray-700 hover:bg-gray-50 transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-6 py-2 bg-gradient-to-r from-indigo-600 to-purple-600 text-white rounded-lg hover:from-indigo-700 hover:to-purple-700 transition-all transform hover:scale-105"
                >
                  Create Project
                </button>
              </div>
            </form>
          </div>
        )}

        {/* Projects Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {projects.map((project) => (
            <Link
              key={project.id}
              to={`/projects/${project.id}`}
              className="group bg-white rounded-xl shadow-md hover:shadow-xl transition-all duration-300 overflow-hidden"
            >
              <div className="bg-gradient-to-r from-indigo-500 to-purple-600 h-2"></div>
              <div className="p-6">
                <div className="flex items-start justify-between mb-4">
                  <div className="flex items-center">
                    <div className="bg-indigo-100 rounded-lg p-3 mr-4">
                      <CodeBracketIcon className="h-6 w-6 text-indigo-600" />
                    </div>
                    <div>
                      <h3 className="text-lg font-semibold text-gray-900 group-hover:text-indigo-600 transition-colors">
                        {project.name}
                      </h3>
                      <p className="text-sm text-gray-500 mt-1">
                        {project.description || 'No description'}
                      </p>
                    </div>
                  </div>
                </div>

                <div className="space-y-3">
                  <div className="flex items-center text-sm text-gray-600">
                    <ShieldCheckIcon className="h-4 w-4 mr-2 text-gray-400" />
                    <span>{project.scan_count || 0} security scans</span>
                  </div>
                  <div className="flex items-center text-sm text-gray-600">
                    <ClockIcon className="h-4 w-4 mr-2 text-gray-400" />
                    <span>Created {new Date(project.created_at).toLocaleDateString()}</span>
                  </div>
                  {project.last_scan_at && (
                    <div className="flex items-center text-sm text-gray-600">
                      <ChartBarIcon className="h-4 w-4 mr-2 text-gray-400" />
                      <span>Last scan: {new Date(project.last_scan_at).toLocaleDateString()}</span>
                    </div>
                  )}
                </div>

                <div className="mt-4 pt-4 border-t border-gray-100">
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-medium text-indigo-600 group-hover:text-indigo-700">
                      View Details →
                    </span>
                    {project.github_repo_url && (
                      <span className="text-xs bg-gray-100 text-gray-600 px-2 py-1 rounded">
                        GitHub
                      </span>
                    )}
                  </div>
                </div>
              </div>
            </Link>
          ))}
        </div>

        {/* Empty State */}
        {projects.length === 0 && !showNewProject && (
          <div className="text-center py-16 bg-white rounded-xl shadow-sm">
            <FolderPlusIcon className="mx-auto h-16 w-16 text-gray-400 mb-4" />
            <h3 className="text-lg font-medium text-gray-900 mb-2">No projects yet</h3>
            <p className="text-gray-500 mb-6">Get started by creating your first project</p>
            <button
              onClick={() => setShowNewProject(true)}
              className="inline-flex items-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 transition-colors"
            >
              <FolderPlusIcon className="h-5 w-5 mr-2" />
              Create First Project
            </button>
          </div>
        )}
      </div>
    </div>
  )
}