import { useState, useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { apiService as api } from '../services/api'
import {
  ArrowLeftIcon,
  ExclamationTriangleIcon,
  ShieldCheckIcon,
  DocumentTextIcon,
  CodeBracketIcon,
  ClockIcon,
  CheckCircleIcon,
  XCircleIcon,
  InformationCircleIcon,
  LightBulbIcon
} from '@heroicons/react/24/outline'

const SEVERITY_CONFIG = {
  critical: {
    color: 'red',
    icon: ExclamationTriangleIcon,
    bgColor: 'bg-red-50',
    borderColor: 'border-red-200',
    textColor: 'text-red-800',
    iconColor: 'text-red-600'
  },
  high: {
    color: 'orange',
    icon: ExclamationTriangleIcon,
    bgColor: 'bg-orange-50',
    borderColor: 'border-orange-200',
    textColor: 'text-orange-800',
    iconColor: 'text-orange-600'
  },
  medium: {
    color: 'yellow',
    icon: ExclamationTriangleIcon,
    bgColor: 'bg-yellow-50',
    borderColor: 'border-yellow-200',
    textColor: 'text-yellow-800',
    iconColor: 'text-yellow-600'
  },
  low: {
    color: 'blue',
    icon: InformationCircleIcon,
    bgColor: 'bg-blue-50',
    borderColor: 'border-blue-200',
    textColor: 'text-blue-800',
    iconColor: 'text-blue-600'
  },
  info: {
    color: 'gray',
    icon: InformationCircleIcon,
    bgColor: 'bg-gray-50',
    borderColor: 'border-gray-200',
    textColor: 'text-gray-800',
    iconColor: 'text-gray-600'
  }
}

export default function ScanDetail() {
  const { scanId } = useParams()
  const navigate = useNavigate()
  const [scan, setScan] = useState(null)
  const [results, setResults] = useState([])
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState('all')
  const [sortBy, setSortBy] = useState('severity')

  useEffect(() => {
    fetchScanDetails()
  }, [scanId])

  const fetchScanDetails = async () => {
    try {
      const [scanData, resultsData] = await Promise.all([
        api.getScan(scanId),
        api.getScanResults(scanId)
      ])
      setScan(scanData)
      setResults(resultsData)
    } catch (error) {
      console.error('Failed to fetch scan details:', error)
    } finally {
      setLoading(false)
    }
  }

  const filteredResults = results.filter(result => 
    filter === 'all' || result.severity === filter
  )

  const sortedResults = [...filteredResults].sort((a, b) => {
    if (sortBy === 'severity') {
      const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
      return severityOrder[a.severity] - severityOrder[b.severity]
    }
    return 0
  })

  const severityCounts = results.reduce((acc, result) => {
    acc[result.severity] = (acc[result.severity] || 0) + 1
    return acc
  }, {})

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-600"></div>
      </div>
    )
  }

  if (!scan) {
    return <div>Scan not found</div>
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Header */}
        <div className="mb-8">
          <button
            onClick={() => navigate(-1)}
            className="flex items-center text-gray-600 hover:text-gray-900 mb-4"
          >
            <ArrowLeftIcon className="h-5 w-5 mr-2" />
            Back
          </button>
          
          <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-6">
            <div className="flex items-start justify-between">
              <div>
                <h1 className="text-2xl font-bold text-gray-900 flex items-center">
                  <ShieldCheckIcon className="h-8 w-8 mr-3 text-indigo-600" />
                  Security Scan Results
                </h1>
                <div className="mt-2 flex items-center gap-4 text-sm text-gray-600">
                  <span className="flex items-center">
                    <ClockIcon className="h-4 w-4 mr-1" />
                    {new Date(scan.created_at).toLocaleString()}
                  </span>
                  <span className={`px-3 py-1 rounded-full text-xs font-medium ${
                    scan.status === 'completed' ? 'bg-green-100 text-green-800' :
                    scan.status === 'failed' ? 'bg-red-100 text-red-800' :
                    'bg-blue-100 text-blue-800'
                  }`}>
                    {scan.status}
                  </span>
                </div>
              </div>
            </div>

            {/* Summary Stats */}
            <div className="mt-6 grid grid-cols-1 md:grid-cols-5 gap-4">
              {Object.entries(SEVERITY_CONFIG).map(([severity, config]) => {
                const count = severityCounts[severity] || 0
                const Icon = config.icon
                return (
                  <button
                    key={severity}
                    onClick={() => setFilter(filter === severity ? 'all' : severity)}
                    className={`p-4 rounded-lg border-2 transition-all ${
                      filter === severity 
                        ? `${config.bgColor} ${config.borderColor}` 
                        : 'bg-white border-gray-200 hover:border-gray-300'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-2xl font-bold text-gray-900">{count}</p>
                        <p className={`text-sm font-medium capitalize ${config.textColor}`}>
                          {severity}
                        </p>
                      </div>
                      <Icon className={`h-8 w-8 ${config.iconColor}`} />
                    </div>
                  </button>
                )
              })}
            </div>
          </div>
        </div>

        {/* Filters */}
        <div className="mb-6 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value)}
              className="px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500"
            >
              <option value="severity">Sort by Severity</option>
              <option value="file">Sort by File</option>
            </select>
            <span className="text-sm text-gray-600">
              Showing {sortedResults.length} of {results.length} issues
            </span>
          </div>
        </div>

        {/* Results */}
        <div className="space-y-4">
          {sortedResults.length === 0 ? (
            <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-12 text-center">
              <CheckCircleIcon className="mx-auto h-16 w-16 text-green-500 mb-4" />
              <h3 className="text-lg font-semibold text-gray-900 mb-2">No Issues Found</h3>
              <p className="text-gray-600">Great! Your code appears to be secure.</p>
            </div>
          ) : (
            sortedResults.map((result) => {
              const config = SEVERITY_CONFIG[result.severity]
              const Icon = config.icon
              
              return (
                <div
                  key={result.id}
                  className={`bg-white rounded-xl shadow-sm border-2 ${config.borderColor} overflow-hidden`}
                >
                  <div className={`${config.bgColor} px-6 py-4 border-b ${config.borderColor}`}>
                    <div className="flex items-start justify-between">
                      <div className="flex items-start">
                        <Icon className={`h-6 w-6 ${config.iconColor} mr-3 mt-0.5`} />
                        <div>
                          <h3 className="font-semibold text-gray-900">
                            {result.title || `${result.vulnerability_type} Vulnerability`}
                          </h3>
                          <p className="text-sm text-gray-600 mt-1">
                            {result.rule_id || 'Unknown Rule'} • {result.vulnerability_type || 'Security Issue'}
                          </p>
                        </div>
                      </div>
                      <span className={`px-3 py-1 rounded-full text-xs font-medium ${config.bgColor} ${config.textColor} capitalize`}>
                        {result.severity}
                      </span>
                    </div>
                  </div>
                  
                  <div className="p-6">
                    {result.description && (
                      <div className="mb-4">
                        <h4 className="text-sm font-semibold text-gray-700 mb-2">Description</h4>
                        <p className="text-sm text-gray-600">{result.description}</p>
                      </div>
                    )}
                    
                    <div className="mb-4">
                      <h4 className="text-sm font-semibold text-gray-700 mb-2">Location</h4>
                      <p className="text-sm text-gray-600">
                        <CodeBracketIcon className="inline-block h-4 w-4 mr-1" />
                        <span className="font-mono">{result.file_path}</span>
                        {result.line_number && (
                          <span className="text-gray-500">:{result.line_number}</span>
                        )}
                      </p>
                    </div>
                    
                    {result.code_snippet && (
                      <div className="mb-4">
                        <h4 className="text-sm font-semibold text-gray-700 mb-2">Code</h4>
                        <pre className="bg-gray-900 text-gray-100 p-4 rounded-lg overflow-x-auto">
                          <code className="text-sm">{result.code_snippet}</code>
                        </pre>
                      </div>
                    )}
                    
                    {result.fix_recommendation && (
                      <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
                        <h4 className="text-sm font-semibold text-blue-900 mb-2 flex items-center">
                          <LightBulbIcon className="h-4 w-4 mr-2" />
                          Recommendation
                        </h4>
                        <p className="text-sm text-blue-800">{result.fix_recommendation}</p>
                      </div>
                    )}
                  </div>
                </div>
              )
            })
          )}
        </div>

        {/* Generate Report Button */}
        {results.length > 0 && (
          <div className="mt-8 flex justify-center">
            <button className="px-6 py-3 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 flex items-center">
              <DocumentTextIcon className="h-5 w-5 mr-2" />
              Generate Full Report
            </button>
          </div>
        )}
      </div>
    </div>
  )
}