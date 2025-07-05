import { useState } from 'react'
import { X, GitBranch, Shield, FolderOpen, AlertCircle, CheckCircle, Code2, Globe } from 'lucide-react'
import { supabase } from '../../lib/supabase'
import { createProject } from '../../services/projectService'
import LoadingSpinner from '../ui/LoadingSpinner'

interface CreateProjectModalProps {
  onClose: () => void
  onSuccess: () => void
}

export default function CreateProjectModal({ onClose, onSuccess }: CreateProjectModalProps) {
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [repositoryUrl, setRepositoryUrl] = useState('')
  const [scanOnCreate, setScanOnCreate] = useState(true)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [repoType, setRepoType] = useState<'github' | 'gitlab' | 'bitbucket' | 'other'>('github')

  const isValidGitUrl = (url: string) => {
    if (!url) return true // Empty is valid
    const gitUrlPattern = /^https?:\/\/(github\.com|gitlab\.com|bitbucket\.org)\/.+\/.+/
    return gitUrlPattern.test(url)
  }

  const getRepoType = (url: string) => {
    if (url.includes('github.com')) return 'github'
    if (url.includes('gitlab.com')) return 'gitlab'
    if (url.includes('bitbucket.org')) return 'bitbucket'
    return 'other'
  }

  const handleRepoUrlChange = (url: string) => {
    setRepositoryUrl(url)
    if (url) {
      setRepoType(getRepoType(url))
    }
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    
    if (!name.trim()) {
      setError('Project name is required')
      return
    }

    if (repositoryUrl && !isValidGitUrl(repositoryUrl)) {
      setError('Please enter a valid repository URL')
      return
    }

    setLoading(true)
    setError(null)

    try {
      const { data: { user } } = await supabase.auth.getUser()
      if (!user) throw new Error('No user found')

      console.log('Creating project:', { name, description, repositoryUrl })
      
      const result = await createProject({
        name: name.trim(),
        description: description.trim() || undefined,
        repository_url: repositoryUrl.trim() || undefined
      })

      console.log('Project created:', result)
      
      // Show success message
      const successDiv = document.createElement('div')
      successDiv.className = 'fixed bottom-4 right-4 bg-green-500 text-white px-6 py-3 rounded-lg shadow-lg flex items-center space-x-2 animate-slide-up z-50'
      successDiv.innerHTML = `
        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path>
        </svg>
        <span>Project created successfully!</span>
      `
      document.body.appendChild(successDiv)
      setTimeout(() => successDiv.remove(), 3000)

      onSuccess()

      // If scan on create is enabled and we have a repository URL, start a scan
      if (scanOnCreate && repositoryUrl && result?.id) {
        setTimeout(async () => {
          try {
            const { getFullApiUrl } = await import('../../utils/api-config')
            const response = await fetch(getFullApiUrl('/api/scans/quick-production'), {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                project_id: result.id,
                repository_url: repositoryUrl,
                branch: 'main',
                scan_type: 'comprehensive',
                user_id: user.id
              })
            })

            if (response.ok) {
              const scanResult = await response.json()
              console.log('Initial scan started:', scanResult)
              
              const scanDiv = document.createElement('div')
              scanDiv.className = 'fixed bottom-4 right-4 bg-blue-500 text-white px-6 py-3 rounded-lg shadow-lg flex items-center space-x-2 animate-slide-up z-50'
              scanDiv.innerHTML = `
                <svg class="w-5 h-5 animate-spin" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path>
                </svg>
                <span>Security scan started automatically!</span>
              `
              document.body.appendChild(scanDiv)
              setTimeout(() => scanDiv.remove(), 4000)
            }
          } catch (err) {
            console.error('Failed to start initial scan:', err)
          }
        }, 1000)
      }
    } catch (error) {
      console.error('Error creating project:', error)
      setError(error instanceof Error ? error.message : 'Failed to create project')
    } finally {
      setLoading(false)
    }
  }

  const getRepoIcon = () => {
    switch (repoType) {
      case 'github':
        return <svg className="w-5 h-5" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/></svg>
      case 'gitlab':
        return <svg className="w-5 h-5" viewBox="0 0 24 24" fill="currentColor"><path d="M4.845.904c-.435 0-.82.28-.955.692C2.639 5.449 1.246 9.728.07 13.335a1.437 1.437 0 00.522 1.607l11.071 8.045c.2.145.472.144.67-.004l11.073-8.04a1.436 1.436 0 00.522-1.61c-1.285-3.942-2.683-8.256-3.817-11.746a1.004 1.004 0 00-.957-.684.987.987 0 00-.949.69l-2.405 7.408H8.203l-2.41-7.408a.987.987 0 00-.942-.69h-.006zm-.006 1.42l2.173 6.678H2.675zm14.326 0l2.168 6.678h-4.341zm-10.593 7.81h6.862c-1.142 3.52-2.288 7.04-3.434 10.559L8.572 10.135zm-5.514.005h4.321l3.086 9.5zm13.567 0h4.325c-2.467 3.17-4.95 6.328-7.411 9.502 1.028-3.167 2.059-6.334 3.086-9.502zM2.1 10.762l6.977 8.947-7.817-5.682a.305.305 0 01-.112-.341zm19.798 0l.952 2.922a.305.305 0 01-.11.341v.002l-7.82 5.68.026-.035z"/></svg>
      case 'bitbucket':
        return <svg className="w-5 h-5" viewBox="0 0 24 24" fill="currentColor"><path d="M.778 1.211c-.424-.006-.772.334-.778.758 0 .045.002.09.01.134l3.263 19.811c.084.499.515.867 1.022.872H19.95c.382.004.708-.271.78-.644l3.27-20.03c.068-.418-.216-.813-.635-.881a.778.778 0 00-.133-.01L.778 1.211zM14.52 15.528H9.522L8.17 8.464h7.561l-1.211 7.064z"/></svg>
      default:
        return <Globe className="w-5 h-5" />
    }
  }

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-xl shadow-2xl w-full max-w-2xl max-h-[90vh] overflow-hidden">
        {/* Header */}
        <div className="bg-gradient-to-r from-blue-600 to-blue-700 px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className="p-2 bg-white/20 rounded-lg">
                <FolderOpen className="h-6 w-6 text-white" />
              </div>
              <div>
                <h2 className="text-xl font-bold text-white">Create New Project</h2>
                <p className="text-sm text-blue-100">Start monitoring your codebase security</p>
              </div>
            </div>
            <button
              onClick={onClose}
              className="text-white/80 hover:text-white transition-colors"
            >
              <X className="h-6 w-6" />
            </button>
          </div>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="p-6 space-y-6">
          {error && (
            <div className="p-4 bg-red-50 border border-red-200 rounded-lg flex items-start space-x-3">
              <AlertCircle className="h-5 w-5 text-red-500 mt-0.5" />
              <div className="flex-1">
                <p className="text-sm font-medium text-red-800">Error</p>
                <p className="text-sm text-red-700 mt-1">{error}</p>
              </div>
            </div>
          )}

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Project Name <span className="text-red-500">*</span>
            </label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-colors"
              placeholder="My Awesome Project"
              disabled={loading}
              autoFocus
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Description
            </label>
            <textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-colors resize-none"
              placeholder="Brief description of your project"
              rows={3}
              disabled={loading}
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Repository URL
            </label>
            <div className="relative">
              <div className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400">
                {getRepoIcon()}
              </div>
              <input
                type="url"
                value={repositoryUrl}
                onChange={(e) => handleRepoUrlChange(e.target.value)}
                className="w-full pl-12 pr-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-colors"
                placeholder="https://github.com/username/repository"
                disabled={loading}
              />
            </div>
            {repositoryUrl && !isValidGitUrl(repositoryUrl) && (
              <p className="mt-2 text-sm text-red-600 flex items-center">
                <AlertCircle className="h-4 w-4 mr-1" />
                Please enter a valid GitHub, GitLab, or Bitbucket URL
              </p>
            )}
            {repositoryUrl && isValidGitUrl(repositoryUrl) && (
              <p className="mt-2 text-sm text-green-600 flex items-center">
                <CheckCircle className="h-4 w-4 mr-1" />
                Valid repository URL
              </p>
            )}
          </div>

          <div className="bg-gray-50 rounded-lg p-4">
            <label className="flex items-start space-x-3 cursor-pointer">
              <input
                type="checkbox"
                checked={scanOnCreate}
                onChange={(e) => setScanOnCreate(e.target.checked)}
                className="mt-1 h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
                disabled={loading || !repositoryUrl}
              />
              <div className="flex-1">
                <div className="flex items-center space-x-2">
                  <Shield className="h-5 w-5 text-blue-600" />
                  <span className="text-sm font-medium text-gray-900">
                    Start security scan immediately
                  </span>
                </div>
                <p className="text-sm text-gray-600 mt-1">
                  {repositoryUrl 
                    ? 'Automatically scan for vulnerabilities after creating the project'
                    : 'Add a repository URL to enable automatic scanning'
                  }
                </p>
              </div>
            </label>
          </div>

          <div className="bg-blue-50 rounded-lg p-4">
            <div className="flex items-start space-x-3">
              <Code2 className="h-5 w-5 text-blue-600 mt-0.5" />
              <div className="text-sm text-blue-900">
                <p className="font-medium mb-1">What happens next?</p>
                <ul className="space-y-1 text-blue-800">
                  <li>• Your project will be created instantly</li>
                  {scanOnCreate && repositoryUrl && (
                    <li>• Security scan will start automatically (15 tools)</li>
                  )}
                  <li>• You'll see real-time scan progress</li>
                  <li>• Get detailed vulnerability reports</li>
                </ul>
              </div>
            </div>
          </div>

          <div className="flex items-center justify-end space-x-3 pt-4 border-t border-gray-200">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 border border-gray-300 rounded-lg text-gray-700 hover:bg-gray-50 font-medium transition-colors"
              disabled={loading}
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading || !name.trim() || !!(repositoryUrl && !isValidGitUrl(repositoryUrl))}
              className="inline-flex items-center px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed font-medium transition-colors"
            >
              {loading ? (
                <>
                  <LoadingSpinner size="sm" className="mr-2" />
                  Creating...
                </>
              ) : (
                <>
                  <FolderOpen className="h-5 w-5 mr-2" />
                  Create Project
                </>
              )}
            </button>
          </div>
        </form>
      </div>
      
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
      `}</style>
    </div>
  )
}