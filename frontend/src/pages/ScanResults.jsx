import { useState, useEffect } from 'react'
import { useParams, Link } from 'react-router-dom'
import { apiService as api } from '../services/api'

export default function ScanResults() {
  const { scanId } = useParams()
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

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'critical': return 'text-red-600 bg-red-100'
      case 'high': return 'text-orange-600 bg-orange-100'
      case 'medium': return 'text-yellow-600 bg-yellow-100'
      case 'low': return 'text-blue-600 bg-blue-100'
      default: return 'text-gray-600 bg-gray-100'
    }
  }

  const getSeverityOrder = (severity) => {
    switch (severity) {
      case 'critical': return 0
      case 'high': return 1
      case 'medium': return 2
      case 'low': return 3
      default: return 4
    }
  }

  const filteredResults = results
    .filter(result => filter === 'all' || result.severity === filter)
    .sort((a, b) => {
      if (sortBy === 'severity') {
        return getSeverityOrder(a.severity) - getSeverityOrder(b.severity)
      }
      return a.file_path.localeCompare(b.file_path)
    })

  if (loading) {
    return (
      <div className="flex justify-center items-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-600"></div>
      </div>
    )
  }

  if (!scan) {
    return <div>Scan not found</div>
  }

  const severityCounts = results.reduce((acc, result) => {
    acc[result.severity] = (acc[result.severity] || 0) + 1
    return acc
  }, {})

  return (
    <div>
      <div className="mb-6">
        <Link to={`/projects/${scan.project_id}`} className="text-primary-600 hover:text-primary-700 text-sm mb-2 inline-block">
          ← Back to Project
        </Link>
        <h1 className="text-2xl font-semibold text-gray-900">Scan Results</h1>
        <div className="mt-2 text-sm text-gray-600">
          <span className="capitalize">{scan.scan_type} scan</span>
          <span className="mx-2">•</span>
          <span>{new Date(scan.created_at).toLocaleString()}</span>
          <span className="mx-2">•</span>
          <span className={`font-medium ${scan.status === 'completed' ? 'text-green-600' : 'text-gray-600'}`}>
            {scan.status}
          </span>
        </div>
      </div>

      {scan.status === 'completed' && (
        <>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
            <div className="bg-white shadow rounded-lg p-4">
              <div className="text-2xl font-bold text-red-600">{severityCounts.critical || 0}</div>
              <div className="text-sm text-gray-600">Critical</div>
            </div>
            <div className="bg-white shadow rounded-lg p-4">
              <div className="text-2xl font-bold text-orange-600">{severityCounts.high || 0}</div>
              <div className="text-sm text-gray-600">High</div>
            </div>
            <div className="bg-white shadow rounded-lg p-4">
              <div className="text-2xl font-bold text-yellow-600">{severityCounts.medium || 0}</div>
              <div className="text-sm text-gray-600">Medium</div>
            </div>
            <div className="bg-white shadow rounded-lg p-4">
              <div className="text-2xl font-bold text-blue-600">{severityCounts.low || 0}</div>
              <div className="text-sm text-gray-600">Low</div>
            </div>
          </div>

          <div className="bg-white shadow rounded-lg p-6">
            <div className="flex justify-between items-center mb-4">
              <h2 className="text-lg font-medium text-gray-900">Findings</h2>
              <div className="flex gap-4">
                <select
                  value={filter}
                  onChange={(e) => setFilter(e.target.value)}
                  className="px-3 py-1 border border-gray-300 rounded-md text-sm"
                >
                  <option value="all">All Severities</option>
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>
                <select
                  value={sortBy}
                  onChange={(e) => setSortBy(e.target.value)}
                  className="px-3 py-1 border border-gray-300 rounded-md text-sm"
                >
                  <option value="severity">Sort by Severity</option>
                  <option value="file">Sort by File</option>
                </select>
              </div>
            </div>

            {filteredResults.length === 0 ? (
              <p className="text-gray-500">No findings match the selected filter</p>
            ) : (
              <div className="space-y-4">
                {filteredResults.map((result) => (
                  <div key={result.id} className="border border-gray-200 rounded-lg p-4">
                    <div className="flex justify-between items-start mb-2">
                      <h3 className="font-medium text-gray-900">{result.rule_id || 'Unknown Rule'}</h3>
                      <span className={`px-2 py-1 text-xs font-medium rounded-full ${getSeverityColor(result.severity)}`}>
                        {result.severity}
                      </span>
                    </div>
                    <p className="text-sm text-gray-600 mb-2">{result.message}</p>
                    <div className="text-sm text-gray-500">
                      <span className="font-mono">{result.file_path}</span>
                      {result.line_number && <span>:{result.line_number}</span>}
                    </div>
                    {result.code_snippet && (
                      <pre className="mt-2 p-2 bg-gray-50 rounded text-xs overflow-x-auto">
                        <code>{result.code_snippet}</code>
                      </pre>
                    )}
                    {result.recommendation && (
                      <div className="mt-2 text-sm text-gray-700">
                        <strong>Recommendation:</strong> {result.recommendation}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </>
      )}

      {scan.status === 'running' && (
        <div className="bg-white shadow rounded-lg p-6">
          <div className="flex items-center">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-600 mr-4"></div>
            <div>
              <h2 className="text-lg font-medium text-gray-900">Scan in Progress</h2>
              <p className="text-sm text-gray-600">This scan is currently running. Results will appear when complete.</p>
            </div>
          </div>
        </div>
      )}

      {scan.status === 'failed' && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-6">
          <h2 className="text-lg font-medium text-red-900">Scan Failed</h2>
          <p className="text-sm text-red-700 mt-1">
            {scan.error_message || 'An error occurred during the scan. Please try again.'}
          </p>
        </div>
      )}
    </div>
  )
}