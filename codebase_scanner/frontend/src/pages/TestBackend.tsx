import { useState } from 'react'
import { getApiUrl, getFullApiUrl } from '../utils/api-config'

export default function TestBackend() {
  const [testing, setTesting] = useState(false)
  const [results, setResults] = useState<any>(null)
  
  const testBackend = async () => {
    setTesting(true)
    const apiUrl = getApiUrl()
    const testResults: any = {
      apiUrl,
      timestamp: new Date().toISOString(),
      tests: []
    }
    
    // Test 1: Basic fetch with no credentials
    try {
      console.log('Testing basic fetch to:', `${apiUrl}/health`)
      const response = await fetch(`${apiUrl}/health`, {
        method: 'GET',
        mode: 'cors',
        credentials: 'omit'
      })
      testResults.tests.push({
        test: 'Basic Health Check',
        url: `${apiUrl}/health`,
        status: response.status,
        statusText: response.statusText,
        headers: Object.fromEntries(response.headers.entries()),
        ok: response.ok
      })
      
      if (response.ok) {
        const data = await response.json()
        testResults.tests[0].data = data
      }
    } catch (error) {
      testResults.tests.push({
        test: 'Basic Health Check',
        url: `${apiUrl}/health`,
        error: error instanceof Error ? error.message : 'Unknown error',
        errorType: error instanceof Error ? error.constructor.name : typeof error
      })
    }
    
    // Test 2: Direct browser test
    testResults.directBrowserTest = {
      instruction: 'Try opening this URL directly in your browser:',
      url: `${apiUrl}/health`,
      expected: 'You should see a JSON response with health status'
    }
    
    // Test 3: Check if it's HTTPS issue
    if (apiUrl.startsWith('https://') && window.location.protocol === 'http:') {
      testResults.mixedContentWarning = 'Warning: Trying to fetch HTTPS from HTTP page (mixed content)'
    }
    
    setResults(testResults)
    setTesting(false)
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
        <h3 className="font-semibold text-yellow-800 mb-2">⚠️ Important: Backend Service Issues</h3>
        
        <div className="mb-4">
          <h4 className="font-semibold text-yellow-800">1. Check Your Render Services:</h4>
          <p className="text-sm text-yellow-700 mb-2">
            You mentioned having two backend services:
          </p>
          <ul className="list-disc list-inside text-sm text-yellow-700 space-y-1">
            <li><strong>codebase-scanner-backend (python 3)</strong></li>
            <li><strong>codebase-scanner-backend-docker (docker)</strong></li>
          </ul>
        </div>
        
        <div className="mb-4">
          <h4 className="font-semibold text-yellow-800">2. Check Service URLs in Render:</h4>
          <p className="text-sm text-yellow-700">
            Each service has its own URL. Look for the actual URLs in your Render dashboard:
          </p>
          <ul className="list-disc list-inside text-sm text-yellow-700 space-y-1 mt-1">
            <li>Python service might be: <code className="bg-yellow-200 px-1">https://codebase-scanner-backend.onrender.com</code></li>
            <li>Docker service might be: <code className="bg-yellow-200 px-1">https://codebase-scanner-backend-docker.onrender.com</code></li>
          </ul>
        </div>
        
        <div className="mb-4">
          <h4 className="font-semibold text-yellow-800">3. Common Issues:</h4>
          <ul className="list-disc list-inside text-sm text-yellow-700 space-y-1">
            <li>Backend service might be suspended or not running</li>
            <li>Using wrong URL (check exact URL in Render dashboard)</li>
            <li>CORS not configured properly</li>
            <li>Service is still deploying or crashed</li>
          </ul>
        </div>
        
        <div className="p-3 bg-red-100 border border-red-300 rounded mt-3">
          <h4 className="font-semibold text-red-800">Action Required:</h4>
          <ol className="list-decimal list-inside text-sm text-red-700 space-y-1 mt-1">
            <li>Go to your Render dashboard</li>
            <li>Check which backend service is actually running (green status)</li>
            <li>Copy the exact URL from that service</li>
            <li>Update VITE_API_URL in Render frontend settings to that URL</li>
            <li>Suspend or delete the unused backend service</li>
          </ol>
        </div>
      </div>
    </div>
  )
}