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
  LightBulbIcon,
  BookOpenIcon,
  ChartBarIcon,
  ScaleIcon,
  BeakerIcon,
  BuildingOfficeIcon,
  LinkIcon,
  TagIcon,
  AcademicCapIcon,
  ClipboardDocumentIcon
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

export default function ScanDetailEnhanced() {
  const { scanId } = useParams()
  const navigate = useNavigate()
  const [scan, setScan] = useState(null)
  const [results, setResults] = useState([])
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState('all')
  const [sortBy, setSortBy] = useState('priority')
  const [expandedResults, setExpandedResults] = useState(new Set())

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

  const toggleExpanded = (resultId) => {
    const newExpanded = new Set(expandedResults)
    if (newExpanded.has(resultId)) {
      newExpanded.delete(resultId)
    } else {
      newExpanded.add(resultId)
    }
    setExpandedResults(newExpanded)
  }

  const filteredResults = results.filter(result => 
    filter === 'all' || result.severity === filter
  )

  const sortedResults = [...filteredResults].sort((a, b) => {
    if (sortBy === 'priority') {
      return (a.fix_priority || 5) - (b.fix_priority || 5)
    } else if (sortBy === 'severity') {
      const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
      return severityOrder[a.severity] - severityOrder[b.severity]
    } else if (sortBy === 'cvss') {
      return (b.cvss_score || 0) - (a.cvss_score || 0)
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
              <option value="priority">Sort by Priority</option>
              <option value="severity">Sort by Severity</option>
              <option value="cvss">Sort by CVSS Score</option>
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
              const isExpanded = expandedResults.has(result.id)
              
              return (
                <div
                  key={result.id}
                  className={`bg-white rounded-xl shadow-sm border-2 ${config.borderColor} overflow-hidden`}
                >
                  <div className={`${config.bgColor} px-6 py-4 border-b ${config.borderColor}`}>
                    <div className="flex items-start justify-between">
                      <div className="flex items-start flex-1">
                        <Icon className={`h-6 w-6 ${config.iconColor} mr-3 mt-0.5`} />
                        <div className="flex-1">
                          <h3 className="font-semibold text-gray-900">
                            {result.title || `${result.vulnerability_type} Vulnerability`}
                          </h3>
                          <div className="flex items-center gap-3 mt-1">
                            <span className="text-sm text-gray-600">
                              {result.rule_id || 'Unknown Rule'} • {result.vulnerability_type || 'Security Issue'}
                            </span>
                            {result.owasp_category && (
                              <span className="text-sm text-purple-600 font-medium">
                                {result.owasp_category}
                              </span>
                            )}
                            {result.cvss_score && (
                              <span className="text-sm font-medium text-gray-700">
                                CVSS: {result.cvss_score}
                              </span>
                            )}
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        {result.fix_priority && (
                          <span className="px-2 py-1 bg-gray-100 text-gray-700 rounded text-xs font-medium">
                            P{result.fix_priority}
                          </span>
                        )}
                        <span className={`px-3 py-1 rounded-full text-xs font-medium ${config.bgColor} ${config.textColor} capitalize`}>
                          {result.severity}
                        </span>
                      </div>
                    </div>
                  </div>
                  
                  <div className="p-6">
                    {/* Basic Information */}
                    {result.description && (
                      <div className="mb-4">
                        <h4 className="text-sm font-semibold text-gray-700 mb-2 flex items-center">
                          <InformationCircleIcon className="h-4 w-4 mr-1" />
                          Description
                        </h4>
                        <p className="text-sm text-gray-600">{result.description}</p>
                      </div>
                    )}
                    
                    {/* Location */}
                    <div className="mb-4">
                      <h4 className="text-sm font-semibold text-gray-700 mb-2 flex items-center">
                        <CodeBracketIcon className="h-4 w-4 mr-1" />
                        Location
                      </h4>
                      <p className="text-sm text-gray-600">
                        <span className="font-mono">{result.file_path}</span>
                        {result.line_number && (
                          <span className="text-gray-500">:{result.line_number}</span>
                        )}
                      </p>
                    </div>
                    
                    {/* Code with Context */}
                    {result.code_snippet && (
                      <div className="mb-4">
                        <h4 className="text-sm font-semibold text-gray-700 mb-2">Code</h4>
                        <div className="bg-gray-900 text-gray-100 rounded-lg overflow-hidden">
                          {result.code_context && result.code_context.before && (
                            <div className="px-4 py-1 text-gray-500 text-xs font-mono">
                              {result.code_context.before.map((line) => (
                                <div key={line.line_number}>
                                  <span className="inline-block w-8 text-right mr-2">{line.line_number}</span>
                                  {line.content}
                                </div>
                              ))}
                            </div>
                          )}
                          <div className="px-4 py-2 bg-red-900 bg-opacity-20 border-l-4 border-red-500">
                            <code className="text-sm font-mono">
                              <span className="inline-block w-8 text-right mr-2 text-red-400">
                                {result.line_number}
                              </span>
                              {result.code_snippet}
                            </code>
                          </div>
                          {result.code_context && result.code_context.after && (
                            <div className="px-4 py-1 text-gray-500 text-xs font-mono">
                              {result.code_context.after.map((line) => (
                                <div key={line.line_number}>
                                  <span className="inline-block w-8 text-right mr-2">{line.line_number}</span>
                                  {line.content}
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      </div>
                    )}
                    
                    {/* Risk Assessment */}
                    {(result.cvss_score || result.exploitability || result.impact) && (
                      <div className="mb-4 p-4 bg-gray-50 rounded-lg">
                        <h4 className="text-sm font-semibold text-gray-700 mb-3 flex items-center">
                          <ChartBarIcon className="h-4 w-4 mr-1" />
                          Risk Assessment
                        </h4>
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
                          {result.cvss_vector && (
                            <div>
                              <span className="text-gray-500">CVSS Vector:</span>
                              <p className="font-mono text-xs mt-1">{result.cvss_vector}</p>
                            </div>
                          )}
                          {result.exploitability && (
                            <div>
                              <span className="text-gray-500">Exploitability:</span>
                              <p className="mt-1">{result.exploitability}</p>
                            </div>
                          )}
                          {result.impact && (
                            <div>
                              <span className="text-gray-500">Impact:</span>
                              <p className="mt-1">{result.impact}</p>
                            </div>
                          )}
                        </div>
                      </div>
                    )}
                    
                    {/* Compliance Mappings */}
                    {result.compliance_mappings && Object.keys(result.compliance_mappings).length > 0 && (
                      <div className="mb-4">
                        <h4 className="text-sm font-semibold text-gray-700 mb-2 flex items-center">
                          <BuildingOfficeIcon className="h-4 w-4 mr-1" />
                          Compliance Standards
                        </h4>
                        <div className="flex flex-wrap gap-2">
                          {Object.entries(result.compliance_mappings).map(([standard, code]) => (
                            <span key={standard} className="px-2 py-1 bg-purple-100 text-purple-700 rounded text-xs">
                              {standard}: {code}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                    
                    {/* Quick Actions */}
                    <div className="flex items-center gap-4 mb-4">
                      <button
                        onClick={() => toggleExpanded(result.id)}
                        className="text-sm text-indigo-600 hover:text-indigo-800 font-medium"
                      >
                        {isExpanded ? 'Show Less' : 'Show More Details'}
                      </button>
                      {result.fix_effort && (
                        <span className="text-sm text-gray-500">
                          Fix Effort: <span className="font-medium">{result.fix_effort}</span>
                        </span>
                      )}
                    </div>
                    
                    {/* Expanded Details */}
                    {isExpanded && (
                      <div className="space-y-4 pt-4 border-t border-gray-200">
                        {/* Recommendation */}
                        {result.fix_recommendation && (
                          <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
                            <h4 className="text-sm font-semibold text-blue-900 mb-2 flex items-center">
                              <LightBulbIcon className="h-4 w-4 mr-2" />
                              Recommendation
                            </h4>
                            <p className="text-sm text-blue-800">{result.fix_recommendation}</p>
                          </div>
                        )}
                        
                        {/* Code Example */}
                        {result.remediation_example && (
                          <div>
                            <h4 className="text-sm font-semibold text-gray-700 mb-2 flex items-center">
                              <AcademicCapIcon className="h-4 w-4 mr-1" />
                              Remediation Example
                            </h4>
                            <pre className="bg-green-900 bg-opacity-10 border border-green-200 text-green-900 p-4 rounded-lg overflow-x-auto">
                              <code className="text-sm">{result.remediation_example}</code>
                            </pre>
                          </div>
                        )}
                        
                        {/* References */}
                        {result.references && result.references.length > 0 && (
                          <div>
                            <h4 className="text-sm font-semibold text-gray-700 mb-2 flex items-center">
                              <LinkIcon className="h-4 w-4 mr-1" />
                              References
                            </h4>
                            <ul className="space-y-1">
                              {result.references.map((ref, index) => (
                                <li key={index}>
                                  <a 
                                    href={ref} 
                                    target="_blank" 
                                    rel="noopener noreferrer"
                                    className="text-sm text-indigo-600 hover:text-indigo-800 hover:underline"
                                  >
                                    {ref}
                                  </a>
                                </li>
                              ))}
                            </ul>
                          </div>
                        )}
                        
                        {/* Tags */}
                        {result.tags && result.tags.length > 0 && (
                          <div>
                            <h4 className="text-sm font-semibold text-gray-700 mb-2 flex items-center">
                              <TagIcon className="h-4 w-4 mr-1" />
                              Tags
                            </h4>
                            <div className="flex flex-wrap gap-2">
                              {result.tags.map((tag) => (
                                <span key={tag} className="px-2 py-1 bg-gray-100 text-gray-700 rounded text-xs">
                                  {tag}
                                </span>
                              ))}
                            </div>
                          </div>
                        )}
                        
                        {/* Affected Dependencies */}
                        {result.affected_packages && result.affected_packages.length > 0 && (
                          <div className="bg-purple-50 border border-purple-200 rounded-lg p-4">
                            <h4 className="text-sm font-semibold text-purple-900 mb-3 flex items-center">
                              <BuildingOfficeIcon className="h-4 w-4 mr-2" />
                              Affected Dependencies
                            </h4>
                            
                            <div className="space-y-3">
                              {result.affected_packages.map((pkg, index) => (
                                <div key={index} className="bg-white rounded-md p-3 border border-purple-100">
                                  <div className="flex items-center justify-between mb-2">
                                    <span className="font-medium text-purple-900">{pkg}</span>
                                    {result.vulnerable_versions && result.vulnerable_versions[pkg] && (
                                      <span className="px-2 py-1 bg-red-100 text-red-800 rounded text-xs">
                                        Vulnerable
                                      </span>
                                    )}
                                  </div>
                                  
                                  {result.vulnerable_versions && result.vulnerable_versions[pkg] && (
                                    <div className="text-xs text-purple-700 space-y-1">
                                      <div>
                                        <span className="text-purple-600">Vulnerable versions:</span>
                                        <span className="ml-1 font-mono">{Array.isArray(result.vulnerable_versions[pkg]) ? result.vulnerable_versions[pkg].join(', ') : result.vulnerable_versions[pkg]}</span>
                                      </div>
                                      {result.fixed_versions && result.fixed_versions[pkg] && (
                                        <div>
                                          <span className="text-green-600">Fixed in:</span>
                                          <span className="ml-1 font-mono text-green-700">{result.fixed_versions[pkg]}</span>
                                        </div>
                                      )}
                                    </div>
                                  )}
                                </div>
                              ))}
                              
                              {result.dependency_chain && result.dependency_chain.length > 1 && (
                                <div className="mt-3 pt-3 border-t border-purple-200">
                                  <span className="text-xs text-purple-600">Dependency chain:</span>
                                  <div className="mt-1 flex items-center space-x-2 text-xs font-mono text-purple-700">
                                    {result.dependency_chain.map((dep, index) => (
                                      <span key={index} className="flex items-center">
                                        {dep}
                                        {index < result.dependency_chain.length - 1 && (
                                          <span className="mx-1 text-purple-400">→</span>
                                        )}
                                      </span>
                                    ))}
                                  </div>
                                </div>
                              )}
                            </div>
                          </div>
                        )}
                        
                        {/* Additional Metadata */}
                        <div className="grid grid-cols-2 gap-4 text-sm text-gray-600">
                          {result.confidence && (
                            <div>
                              <span className="text-gray-500">Confidence:</span>
                              <span className="ml-2 font-medium capitalize">{result.confidence}</span>
                            </div>
                          )}
                          {result.likelihood && (
                            <div>
                              <span className="text-gray-500">Likelihood:</span>
                              <span className="ml-2 font-medium">{result.likelihood}</span>
                            </div>
                          )}
                        </div>
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
          <div className="mt-8 flex justify-center gap-4">
            <button className="px-6 py-3 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 flex items-center">
              <DocumentTextIcon className="h-5 w-5 mr-2" />
              Generate Full Report
            </button>
            <button className="px-6 py-3 bg-white border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50 flex items-center">
              <ClipboardDocumentIcon className="h-5 w-5 mr-2" />
              Export to JIRA/GitHub
            </button>
          </div>
        )}
      </div>
    </div>
  )
}