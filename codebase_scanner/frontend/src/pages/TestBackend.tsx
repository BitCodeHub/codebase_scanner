import { useState } from 'react'
import { getApiUrl, getFullApiUrl } from '../utils/api-config'

export default function TestBackend() {
  const [testing, setTesting] = useState(false)
  const [results, setResults] = useState<any>(null)
  
  const testBackend = async () => {
    setTesting(true)
    const apiUrl = getApiUrl()
    
    try {
      // Test health endpoint
      const healthResponse = await fetch(`${apiUrl}/health`)
      const healthData = await healthResponse.json()
      
      // Test root endpoint
      const rootResponse = await fetch(`${apiUrl}/`)
      const rootData = await rootResponse.json()
      
      // Test quick-production endpoint
      const endpointUrl = getFullApiUrl('/api/scans/quick-production')
      
      setResults({
        apiUrl,
        healthStatus: healthResponse.status,
        healthData,
        rootStatus: rootResponse.status,
        rootData,
        quickProductionUrl: endpointUrl,
        timestamp: new Date().toISOString()
      })
    } catch (error) {
      setResults({
        apiUrl,
        error: error instanceof Error ? error.message : 'Unknown error',
        timestamp: new Date().toISOString()
      })
    } finally {
      setTesting(false)
    }
  }
  
  return (
    <div className="p-6">
      <h1 className="text-2xl font-bold mb-4">Backend Connection Test</h1>
      
      <div className="mb-4">
        <p className="text-sm text-gray-600">Current API URL: <code className="bg-gray-100 px-2 py-1 rounded">{getApiUrl()}</code></p>
      </div>
      
      <button
        onClick={testBackend}
        disabled={testing}
        className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 disabled:opacity-50"
      >
        {testing ? 'Testing...' : 'Test Backend Connection'}
      </button>
      
      {results && (
        <div className="mt-6 p-4 bg-gray-100 rounded">
          <h2 className="font-semibold mb-2">Test Results:</h2>
          <pre className="text-xs overflow-auto">
            {JSON.stringify(results, null, 2)}
          </pre>
        </div>
      )}
      
      <div className="mt-6 p-4 bg-yellow-100 border border-yellow-400 rounded">
        <h3 className="font-semibold text-yellow-800 mb-2">⚠️ Important: Duplicate Backend Services</h3>
        <p className="text-sm text-yellow-700 mb-2">
          You have two backend services on Render:
        </p>
        <ul className="list-disc list-inside text-sm text-yellow-700 space-y-1">
          <li><strong>codebase-scanner-backend (python 3)</strong> - Python service</li>
          <li><strong>codebase-scanner-backend-docker (docker)</strong> - Docker service</li>
        </ul>
        <p className="text-sm text-yellow-700 mt-2">
          This can cause conflicts. You should:
        </p>
        <ol className="list-decimal list-inside text-sm text-yellow-700 space-y-1 mt-1">
          <li>Decide which backend to use (Docker is configured in render.yaml)</li>
          <li>Suspend or delete the other service</li>
          <li>Update the frontend to use the correct backend URL</li>
        </ol>
      </div>
    </div>
  )
}