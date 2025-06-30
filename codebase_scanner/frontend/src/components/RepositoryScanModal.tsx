import { useState } from 'react'
import { X, Shield, Play, GitBranch, Github } from 'lucide-react'

interface RepositoryScanModalProps {
  isOpen: boolean
  onClose: () => void
  onStartScan: (repoUrl: string, branch: string, scanType: string) => void
}

export default function RepositoryScanModal({ isOpen, onClose, onStartScan }: RepositoryScanModalProps) {
  const [repoUrl, setRepoUrl] = useState('')
  const [branch, setBranch] = useState('main')
  const [scanType, setScanType] = useState('comprehensive')
  const [currentStep, setCurrentStep] = useState<'input' | 'configure' | 'summary'>('input')

  if (!isOpen) return null

  const handleStartScan = () => {
    onStartScan(repoUrl, branch, scanType)
    onClose()
  }

  const canProceed = () => {
    switch (currentStep) {
      case 'input':
        return repoUrl.trim() !== '' && isValidGitUrl(repoUrl)
      case 'configure':
        return true
      case 'summary':
        return true
      default:
        return false
    }
  }

  const isValidGitUrl = (url: string) => {
    const gitUrlPattern = /^https:\/\/(github\.com|gitlab\.com|bitbucket\.org)\/.+\/.+/
    return gitUrlPattern.test(url)
  }

  const nextStep = () => {
    if (currentStep === 'input') setCurrentStep('configure')
    else if (currentStep === 'configure') setCurrentStep('summary')
  }

  const prevStep = () => {
    if (currentStep === 'configure') setCurrentStep('input')
    else if (currentStep === 'summary') setCurrentStep('configure')
  }

  const getRepoName = () => {
    try {
      const url = new URL(repoUrl)
      return url.pathname.replace('/', '').replace('.git', '')
    } catch {
      return 'Repository'
    }
  }

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-xl shadow-2xl w-full max-w-3xl max-h-[90vh] overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b border-gray-200 bg-gradient-to-r from-green-600 to-green-700">
          <div className="flex items-center space-x-3">
            <Github className="h-6 w-6 text-white" />
            <h2 className="text-xl font-bold text-white">Repository Security Scan</h2>
          </div>
          <button
            onClick={onClose}
            className="text-white hover:text-gray-200 transition-colors"
          >
            <X className="h-6 w-6" />
          </button>
        </div>

        {/* Progress Steps */}
        <div className="px-6 py-4 bg-gray-50 border-b border-gray-200">
          <div className="flex items-center space-x-4">
            {[
              { key: 'input', label: 'Repository URL', icon: '🔗' },
              { key: 'configure', label: 'Scan Options', icon: '⚙️' },
              { key: 'summary', label: 'Review & Start', icon: '🚀' }
            ].map((step, index) => (
              <div key={step.key} className="flex items-center">
                <div className={`flex items-center space-x-2 px-3 py-2 rounded-lg transition-colors ${
                  currentStep === step.key 
                    ? 'bg-green-100 text-green-700' 
                    : index < ['input', 'configure', 'summary'].indexOf(currentStep)
                      ? 'bg-green-100 text-green-700'
                      : 'bg-gray-100 text-gray-500'
                }`}>
                  <span>{step.icon}</span>
                  <span className="text-sm font-medium">{step.label}</span>
                </div>
                {index < 2 && (
                  <div className="w-8 h-px bg-gray-300 mx-2"></div>
                )}
              </div>
            ))}
          </div>
        </div>

        {/* Content */}
        <div className="p-6 max-h-[calc(90vh-200px)] overflow-y-auto">
          {currentStep === 'input' && (
            <div className="space-y-6">
              <div>
                <h3 className="text-lg font-semibold text-gray-900 mb-2">Repository Information</h3>
                <p className="text-gray-600">
                  Enter the URL of the GitHub, GitLab, or Bitbucket repository you want to scan.
                </p>
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Repository URL
                </label>
                <div className="relative">
                  <input
                    type="url"
                    value={repoUrl}
                    onChange={(e) => setRepoUrl(e.target.value)}
                    placeholder="https://github.com/username/repository"
                    className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-green-500 focus:border-transparent"
                  />
                  <Github className="absolute right-3 top-3 h-6 w-6 text-gray-400" />
                </div>
                {repoUrl && !isValidGitUrl(repoUrl) && (
                  <p className="mt-2 text-sm text-red-600">
                    Please enter a valid GitHub, GitLab, or Bitbucket URL
                  </p>
                )}
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Branch
                </label>
                <div className="relative">
                  <input
                    type="text"
                    value={branch}
                    onChange={(e) => setBranch(e.target.value)}
                    placeholder="main"
                    className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-green-500 focus:border-transparent"
                  />
                  <GitBranch className="absolute right-3 top-3 h-6 w-6 text-gray-400" />
                </div>
              </div>
            </div>
          )}

          {currentStep === 'configure' && (
            <div className="space-y-6">
              <div>
                <h3 className="text-lg font-semibold text-gray-900 mb-2">Scan Configuration</h3>
                <p className="text-gray-600">
                  Choose the type of security scan to perform on the repository.
                </p>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-3">Scan Type</label>
                <div className="space-y-3">
                  {[
                    { value: 'quick', label: 'Quick Scan', desc: 'Fast scan for common vulnerabilities (~5 min)', icon: '⚡' },
                    { value: 'comprehensive', label: 'Comprehensive', desc: 'Thorough analysis including dependencies (~15 min)', icon: '🔍' },
                    { value: 'custom', label: 'Custom Scan', desc: 'Configure specific rules and patterns', icon: '⚙️' }
                  ].map((type) => (
                    <label key={type.value} className="flex items-start space-x-3 p-4 border rounded-lg hover:bg-gray-50 cursor-pointer">
                      <input
                        type="radio"
                        name="scanType"
                        value={type.value}
                        checked={scanType === type.value}
                        onChange={(e) => setScanType(e.target.value)}
                        className="mt-1"
                      />
                      <div className="flex-1">
                        <div className="flex items-center space-x-2">
                          <span>{type.icon}</span>
                          <span className="font-medium text-gray-900">{type.label}</span>
                        </div>
                        <p className="text-sm text-gray-600 mt-1">{type.desc}</p>
                      </div>
                    </label>
                  ))}
                </div>
              </div>
            </div>
          )}

          {currentStep === 'summary' && (
            <div className="space-y-6">
              <div>
                <h3 className="text-lg font-semibold text-gray-900 mb-2">Scan Summary</h3>
                <p className="text-gray-600">
                  Review your repository scan configuration before starting.
                </p>
              </div>

              <div className="bg-gray-50 rounded-lg p-6 space-y-4">
                <div>
                  <h4 className="font-medium text-gray-900 mb-2">Repository</h4>
                  <p className="text-sm text-gray-600">{getRepoName()}</p>
                  <p className="text-xs text-gray-500 mt-1">{repoUrl}</p>
                  <p className="text-xs text-gray-500">Branch: {branch}</p>
                </div>

                <div>
                  <h4 className="font-medium text-gray-900 mb-2">Scan Configuration</h4>
                  <div className="space-y-1 text-sm text-gray-600">
                    <p>Type: <span className="font-medium">{scanType}</span></p>
                    <p>Scanners: <span className="font-medium">Semgrep, Bandit, Safety, GitLeaks</span></p>
                  </div>
                </div>

                <div className="border-t border-gray-200 pt-4">
                  <div className="flex items-center space-x-2 text-sm text-gray-600">
                    <Shield className="h-4 w-4" />
                    <span>
                      Estimated scan time: {
                        scanType === 'quick' ? '5-10 minutes' :
                        scanType === 'comprehensive' ? '10-20 minutes' :
                        '15-30 minutes'
                      }
                    </span>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between p-6 border-t border-gray-200 bg-gray-50">
          <div>
            {currentStep !== 'input' && (
              <button
                onClick={prevStep}
                className="px-4 py-2 text-gray-600 hover:text-gray-800 font-medium"
              >
                Back
              </button>
            )}
          </div>
          
          <div className="flex items-center space-x-3">
            <button
              onClick={onClose}
              className="px-4 py-2 border border-gray-300 rounded-lg text-gray-700 hover:bg-gray-50 font-medium"
            >
              Cancel
            </button>
            
            {currentStep === 'summary' ? (
              <button
                onClick={handleStartScan}
                disabled={!canProceed()}
                className="flex items-center space-x-2 px-6 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 disabled:opacity-50 disabled:cursor-not-allowed font-medium"
              >
                <Play className="h-4 w-4" />
                <span>Start Repository Scan</span>
              </button>
            ) : (
              <button
                onClick={nextStep}
                disabled={!canProceed()}
                className="px-6 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 disabled:opacity-50 disabled:cursor-not-allowed font-medium"
              >
                Next
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}