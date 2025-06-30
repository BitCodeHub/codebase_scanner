import { useState } from 'react'
import { X, Shield, Play, Clock } from 'lucide-react'
import FileUpload from './FileUpload'

interface ScanModalProps {
  isOpen: boolean
  onClose: () => void
  onStartScan: (files: File[], options: ScanOptions) => void
}

interface ScanOptions {
  scanType: 'quick' | 'comprehensive' | 'custom'
  includeTests: boolean
  includeDependencies: boolean
  severityThreshold: 'all' | 'low' | 'medium' | 'high' | 'critical'
  frameworks: string[]
}

export default function ScanModal({ isOpen, onClose, onStartScan }: ScanModalProps) {
  const [files, setFiles] = useState<File[]>([])
  const [scanOptions, setScanOptions] = useState<ScanOptions>({
    scanType: 'comprehensive',
    includeTests: true,
    includeDependencies: true,
    severityThreshold: 'low',
    frameworks: []
  })
  const [currentStep, setCurrentStep] = useState<'upload' | 'configure' | 'summary'>('upload')

  if (!isOpen) return null

  const handleFilesSelected = (selectedFiles: File[]) => {
    setFiles(selectedFiles)
  }

  const handleStartScan = () => {
    onStartScan(files, scanOptions)
    onClose()
  }

  const canProceed = () => {
    switch (currentStep) {
      case 'upload':
        return files.length > 0
      case 'configure':
        return true
      case 'summary':
        return true
      default:
        return false
    }
  }

  const nextStep = () => {
    if (currentStep === 'upload') setCurrentStep('configure')
    else if (currentStep === 'configure') setCurrentStep('summary')
  }

  const prevStep = () => {
    if (currentStep === 'configure') setCurrentStep('upload')
    else if (currentStep === 'summary') setCurrentStep('configure')
  }

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-xl shadow-2xl w-full max-w-4xl max-h-[90vh] overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b border-gray-200 bg-gradient-to-r from-blue-600 to-blue-700">
          <div className="flex items-center space-x-3">
            <Shield className="h-6 w-6 text-white" />
            <h2 className="text-xl font-bold text-white">Security Scan</h2>
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
              { key: 'upload', label: 'Upload Files', icon: '📁' },
              { key: 'configure', label: 'Configure Scan', icon: '⚙️' },
              { key: 'summary', label: 'Review & Start', icon: '🚀' }
            ].map((step, index) => (
              <div key={step.key} className="flex items-center">
                <div className={`flex items-center space-x-2 px-3 py-2 rounded-lg transition-colors ${
                  currentStep === step.key 
                    ? 'bg-blue-100 text-blue-700' 
                    : index < ['upload', 'configure', 'summary'].indexOf(currentStep)
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
          {currentStep === 'upload' && (
            <div className="space-y-6">
              <div>
                <h3 className="text-lg font-semibold text-gray-900 mb-2">Upload Source Code Files</h3>
                <p className="text-gray-600">
                  Select the source code files you want to scan for security vulnerabilities.
                </p>
              </div>
              
              <FileUpload
                onFilesSelected={handleFilesSelected}
                maxFiles={20}
                maxSize={10}
                acceptedTypes={['.js', '.ts', '.jsx', '.tsx', '.py', '.java', '.php', '.rb', '.go', '.cpp', '.c', '.cs']}
              />
            </div>
          )}

          {currentStep === 'configure' && (
            <div className="space-y-6">
              <div>
                <h3 className="text-lg font-semibold text-gray-900 mb-2">Scan Configuration</h3>
                <p className="text-gray-600">
                  Configure the scan parameters to match your project requirements.
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {/* Scan Type */}
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-3">Scan Type</label>
                  <div className="space-y-2">
                    {[
                      { value: 'quick', label: 'Quick Scan', desc: 'Fast scan for common vulnerabilities (~2 min)', icon: '⚡' },
                      { value: 'comprehensive', label: 'Comprehensive', desc: 'Thorough analysis including dependencies (~10 min)', icon: '🔍' },
                      { value: 'custom', label: 'Custom Scan', desc: 'Configure specific rules and patterns', icon: '⚙️' }
                    ].map((type) => (
                      <label key={type.value} className="flex items-start space-x-3 p-3 border rounded-lg hover:bg-gray-50 cursor-pointer">
                        <input
                          type="radio"
                          name="scanType"
                          value={type.value}
                          checked={scanOptions.scanType === type.value}
                          onChange={(e) => setScanOptions(prev => ({ ...prev, scanType: e.target.value as any }))}
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

                {/* Additional Options */}
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-3">Additional Options</label>
                  <div className="space-y-3">
                    <label className="flex items-center space-x-3">
                      <input
                        type="checkbox"
                        checked={scanOptions.includeTests}
                        onChange={(e) => setScanOptions(prev => ({ ...prev, includeTests: e.target.checked }))}
                        className="rounded border-gray-300"
                      />
                      <span className="text-sm text-gray-700">Include test files</span>
                    </label>
                    
                    <label className="flex items-center space-x-3">
                      <input
                        type="checkbox"
                        checked={scanOptions.includeDependencies}
                        onChange={(e) => setScanOptions(prev => ({ ...prev, includeDependencies: e.target.checked }))}
                        className="rounded border-gray-300"
                      />
                      <span className="text-sm text-gray-700">Scan dependencies for known vulnerabilities</span>
                    </label>
                  </div>

                  <div className="mt-6">
                    <label className="block text-sm font-medium text-gray-700 mb-2">Minimum Severity Level</label>
                    <select
                      value={scanOptions.severityThreshold}
                      onChange={(e) => setScanOptions(prev => ({ ...prev, severityThreshold: e.target.value as any }))}
                      className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    >
                      <option value="all">All Issues</option>
                      <option value="low">Low and above</option>
                      <option value="medium">Medium and above</option>
                      <option value="high">High and above</option>
                      <option value="critical">Critical only</option>
                    </select>
                  </div>
                </div>
              </div>
            </div>
          )}

          {currentStep === 'summary' && (
            <div className="space-y-6">
              <div>
                <h3 className="text-lg font-semibold text-gray-900 mb-2">Scan Summary</h3>
                <p className="text-gray-600">
                  Review your scan configuration before starting the security analysis.
                </p>
              </div>

              <div className="bg-gray-50 rounded-lg p-6 space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div>
                    <h4 className="font-medium text-gray-900 mb-2">Files to Scan</h4>
                    <p className="text-sm text-gray-600">{files.length} files selected</p>
                    <div className="mt-2 space-y-1">
                      {files.slice(0, 5).map((file, index) => (
                        <p key={index} className="text-xs text-gray-500 truncate">{file.name}</p>
                      ))}
                      {files.length > 5 && (
                        <p className="text-xs text-gray-500">+ {files.length - 5} more files</p>
                      )}
                    </div>
                  </div>

                  <div>
                    <h4 className="font-medium text-gray-900 mb-2">Scan Configuration</h4>
                    <div className="space-y-1 text-sm text-gray-600">
                      <p>Type: <span className="font-medium">{scanOptions.scanType}</span></p>
                      <p>Include tests: <span className="font-medium">{scanOptions.includeTests ? 'Yes' : 'No'}</span></p>
                      <p>Include dependencies: <span className="font-medium">{scanOptions.includeDependencies ? 'Yes' : 'No'}</span></p>
                      <p>Severity threshold: <span className="font-medium">{scanOptions.severityThreshold}</span></p>
                    </div>
                  </div>
                </div>

                <div className="border-t border-gray-200 pt-4">
                  <div className="flex items-center space-x-2 text-sm text-gray-600">
                    <Clock className="h-4 w-4" />
                    <span>
                      Estimated scan time: {
                        scanOptions.scanType === 'quick' ? '2-5 minutes' :
                        scanOptions.scanType === 'comprehensive' ? '5-15 minutes' :
                        '10-30 minutes'
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
            {currentStep !== 'upload' && (
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
                className="flex items-center space-x-2 px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed font-medium"
              >
                <Play className="h-4 w-4" />
                <span>Start Scan</span>
              </button>
            ) : (
              <button
                onClick={nextStep}
                disabled={!canProceed()}
                className="px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed font-medium"
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