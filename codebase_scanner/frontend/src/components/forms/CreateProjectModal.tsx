import { useState } from 'react'
import { supabase } from '../../lib/supabase'
import { XIcon, UploadIcon, GitBranchIcon } from 'lucide-react'
import LoadingSpinner from '../ui/LoadingSpinner'
import { getApiUrl, getFullApiUrl } from '../../utils/api-config'

interface CreateProjectModalProps {
  onClose: () => void
  onSuccess: () => void
}

export default function CreateProjectModal({ onClose, onSuccess }: CreateProjectModalProps) {
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    github_repo_url: '',
    source_type: 'github' // 'github' or 'upload'
  })
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [debugInfo, setDebugInfo] = useState<any>(null)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError('')

    try {
      const session = await supabase.auth.getSession()
      const user = await supabase.auth.getUser()
      const token = session.data.session?.access_token
      
      // Debug information
      const debug: any = {
        hasToken: !!token,
        tokenPreview: token ? token.substring(0, 50) + '...' : 'No token',
        userId: user.data.user?.id,
        apiUrl: getApiUrl(),
        requestBody: {
          name: formData.name,
          description: formData.description,
          repository_url: formData.source_type === 'github' ? formData.github_repo_url : null
        }
      }
      
      if (!token) {
        setDebugInfo({ ...debug, error: 'No authentication token' })
        throw new Error('User not authenticated')
      }

      // Use the backend API to create the project
      const apiUrl = getFullApiUrl('/api/projects/')
      debug.apiUrl = apiUrl
      debug.detectedApiBase = getApiUrl()
      debug.isProduction = window.location.hostname.includes('onrender.com')
      
      let response;
      try {
        response = await fetch(apiUrl, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            name: formData.name,
            description: formData.description,
            repository_url: formData.source_type === 'github' ? formData.github_repo_url : null
          })
        });
      } catch (fetchError) {
        // Network or connection error
        debug.networkError = true;
        debug.fetchError = fetchError;
        setDebugInfo(debug);
        throw new Error('Network error: Unable to connect to the server. Please check your connection and try again.');
      }

      const responseText = await response.text()
      let responseData
      try {
        responseData = JSON.parse(responseText)
      } catch {
        responseData = { rawResponse: responseText }
      }

      debug.responseStatus = response.status
      debug.responseHeaders = Object.fromEntries(response.headers.entries())
      debug.responseData = responseData

      setDebugInfo(debug)

      if (!response.ok) {
        // Construct a meaningful error message from the response
        let errorMessage = `Failed to create project: ${response.status}`;
        
        if (responseData) {
          if (typeof responseData === 'string') {
            errorMessage = responseData;
          } else if (responseData.detail) {
            errorMessage = responseData.detail;
          } else if (responseData.error) {
            errorMessage = typeof responseData.error === 'string' 
              ? responseData.error 
              : JSON.stringify(responseData.error);
          } else if (responseData.message) {
            errorMessage = responseData.message;
          }
        }
        
        throw new Error(errorMessage);
      }

      onSuccess()
    } catch (error: any) {
      // Handle different error types properly
      let errorMessage = 'An unexpected error occurred';
      
      if (error instanceof Error) {
        errorMessage = error.message;
      } else if (typeof error === 'string') {
        errorMessage = error;
      } else if (error && typeof error === 'object') {
        // Try to extract meaningful error message from object
        errorMessage = error.detail || error.error || error.message || JSON.stringify(error);
      }
      
      setError(errorMessage);
      
      if (!debugInfo) {
        setDebugInfo({ 
          error: errorMessage, 
          errorType: error?.constructor?.name || typeof error,
          fullError: error,
          stack: error?.stack 
        });
      }
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
      <div className="bg-white rounded-lg max-w-md w-full max-h-[90vh] overflow-y-auto">
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b border-gray-200">
          <h2 className="text-lg font-semibold text-gray-900">Create New Project</h2>
          <button
            onClick={onClose}
            className="p-1 text-gray-400 hover:text-gray-600"
          >
            <XIcon className="h-5 w-5" />
          </button>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="p-6 space-y-6">
          {/* Project Name */}
          <div>
            <label htmlFor="name" className="block text-sm font-medium text-gray-700">
              Project Name *
            </label>
            <input
              type="text"
              id="name"
              value={formData.name}
              onChange={(e) => setFormData({ ...formData, name: e.target.value })}
              required
              className="input mt-1"
              placeholder="My Security Project"
            />
          </div>

          {/* Description */}
          <div>
            <label htmlFor="description" className="block text-sm font-medium text-gray-700">
              Description
            </label>
            <textarea
              id="description"
              value={formData.description}
              onChange={(e) => setFormData({ ...formData, description: e.target.value })}
              rows={3}
              className="input mt-1 resize-none"
              placeholder="Brief description of your project..."
            />
          </div>

          {/* Source Type */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-3">
              Source Type
            </label>
            <div className="space-y-3">
              <div
                className={`flex items-center p-3 border rounded-lg cursor-pointer transition-colors ${
                  formData.source_type === 'github'
                    ? 'border-blue-500 bg-blue-50'
                    : 'border-gray-200 hover:bg-gray-50'
                }`}
                onClick={() => setFormData({ ...formData, source_type: 'github' })}
              >
                <input
                  type="radio"
                  value="github"
                  checked={formData.source_type === 'github'}
                  onChange={() => setFormData({ ...formData, source_type: 'github' })}
                  className="mr-3"
                />
                <GitBranchIcon className="h-5 w-5 text-gray-500 mr-3" />
                <div>
                  <div className="font-medium text-gray-900">GitHub Repository</div>
                  <div className="text-sm text-gray-600">Connect to a GitHub repository</div>
                </div>
              </div>

              <div
                className={`flex items-center p-3 border rounded-lg cursor-pointer transition-colors ${
                  formData.source_type === 'upload'
                    ? 'border-blue-500 bg-blue-50'
                    : 'border-gray-200 hover:bg-gray-50'
                }`}
                onClick={() => setFormData({ ...formData, source_type: 'upload' })}
              >
                <input
                  type="radio"
                  value="upload"
                  checked={formData.source_type === 'upload'}
                  onChange={() => setFormData({ ...formData, source_type: 'upload' })}
                  className="mr-3"
                />
                <UploadIcon className="h-5 w-5 text-gray-500 mr-3" />
                <div>
                  <div className="font-medium text-gray-900">File Upload</div>
                  <div className="text-sm text-gray-600">Upload source code files</div>
                </div>
              </div>
            </div>
          </div>

          {/* GitHub URL (conditional) */}
          {formData.source_type === 'github' && (
            <div>
              <label htmlFor="github_repo_url" className="block text-sm font-medium text-gray-700">
                GitHub Repository URL *
              </label>
              <input
                type="url"
                id="github_repo_url"
                value={formData.github_repo_url}
                onChange={(e) => setFormData({ ...formData, github_repo_url: e.target.value })}
                required={formData.source_type === 'github'}
                className="input mt-1"
                placeholder="https://github.com/username/repository"
              />
              <p className="text-sm text-gray-500 mt-1">
                Make sure the repository is public or you have access
              </p>
            </div>
          )}

          {/* Error Message */}
          {error && (
            <div className="p-3 bg-red-50 border border-red-200 rounded-md">
              <p className="text-sm text-red-600">{error}</p>
              {debugInfo && (
                <details className="mt-2">
                  <summary className="text-xs text-gray-600 cursor-pointer">Debug Information</summary>
                  <pre className="mt-2 text-xs bg-gray-100 p-2 rounded overflow-auto max-h-40">
                    {JSON.stringify(debugInfo, null, 2)}
                  </pre>
                </details>
              )}
            </div>
          )}

          {/* Actions */}
          <div className="flex space-x-3 pt-4">
            <button
              type="button"
              onClick={onClose}
              className="btn-secondary flex-1"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading}
              className="btn-primary flex-1 flex items-center justify-center"
            >
              {loading ? (
                <LoadingSpinner size="sm" />
              ) : (
                'Create Project'
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}