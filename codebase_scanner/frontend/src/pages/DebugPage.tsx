import { useState, useEffect } from 'react'
import { supabase } from '../lib/supabase'
import { runtimeConfig } from '../generated/config'

export default function DebugPage() {
  const [authStatus, setAuthStatus] = useState<any>({})
  const [apiStatus, setApiStatus] = useState<any>({})
  const [projectTest, setProjectTest] = useState<any>({})
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    checkAuthStatus()
  }, [])

  const checkAuthStatus = async () => {
    try {
      const session = await supabase.auth.getSession()
      const user = await supabase.auth.getUser()
      
      setAuthStatus({
        hasSession: !!session.data.session,
        sessionToken: session.data.session?.access_token ? 'Present' : 'Missing',
        tokenPreview: session.data.session?.access_token?.substring(0, 50) + '...',
        user: user.data.user?.email || 'No user',
        userId: user.data.user?.id || 'No ID'
      })
    } catch (error) {
      setAuthStatus({ error: error instanceof Error ? error.message : 'Unknown error' })
    }
  }

  const testAPIConnection = async () => {
    setLoading(true)
    try {
      // Test basic API endpoint
      const response = await fetch(`${runtimeConfig.apiUrl}/api/test`)
      const data = await response.json()
      
      // Test Supabase connection
      const supabaseResponse = await fetch(`${runtimeConfig.apiUrl}/api/supabase/test`)
      const supabaseData = await supabaseResponse.json()
      
      setApiStatus({
        apiUrl: runtimeConfig.apiUrl,
        basicTest: data,
        supabaseTest: supabaseData
      })
    } catch (error) {
      setApiStatus({ error: error instanceof Error ? error.message : 'Unknown error' })
    }
    setLoading(false)
  }

  const testAuthentication = async () => {
    setLoading(true)
    try {
      const session = await supabase.auth.getSession()
      const token = session.data.session?.access_token
      
      if (!token) {
        setApiStatus({ ...apiStatus, authTest: { error: 'No auth token' } })
        return
      }

      // Test auth debug endpoint
      const debugResponse = await fetch(`${runtimeConfig.apiUrl}/api/auth/debug`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ token })
      })
      const debugData = await debugResponse.json()
      
      setApiStatus({ ...apiStatus, authDebug: debugData })
    } catch (error) {
      setApiStatus({ ...apiStatus, authTest: { error: error instanceof Error ? error.message : 'Unknown error' } })
    }
    setLoading(false)
  }

  const testProjectCreation = async () => {
    setLoading(true)
    try {
      const session = await supabase.auth.getSession()
      const token = session.data.session?.access_token
      
      if (!token) {
        setProjectTest({ error: 'No auth token' })
        return
      }

      // Test project creation
      const response = await fetch(`${runtimeConfig.apiUrl}/api/projects/`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          name: 'Debug Test Project ' + new Date().toISOString(),
          description: 'Testing project creation',
          repository_url: 'https://github.com/test/repo'
        })
      })

      const responseText = await response.text()
      let responseData
      try {
        responseData = JSON.parse(responseText)
      } catch {
        responseData = { rawResponse: responseText }
      }

      setProjectTest({
        status: response.status,
        statusText: response.statusText,
        headers: Object.fromEntries(response.headers.entries()),
        data: responseData
      })
    } catch (error) {
      setProjectTest({ error: error instanceof Error ? error.message : 'Unknown error' })
    }
    setLoading(false)
  }

  const testProjectList = async () => {
    setLoading(true)
    try {
      const session = await supabase.auth.getSession()
      const token = session.data.session?.access_token
      
      if (!token) {
        setProjectTest({ ...projectTest, listError: 'No auth token' })
        return
      }

      // Test project list
      const response = await fetch(`${runtimeConfig.apiUrl}/api/projects/`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${token}`
        }
      })

      const data = await response.json()

      setProjectTest({
        ...projectTest,
        listStatus: response.status,
        listData: data
      })
    } catch (error) {
      setProjectTest({ ...projectTest, listError: error instanceof Error ? error.message : 'Unknown error' })
    }
    setLoading(false)
  }

  return (
    <div className="p-6 max-w-4xl mx-auto">
      <h1 className="text-2xl font-bold mb-6">Debug Dashboard</h1>

      {/* Configuration */}
      <div className="mb-8 p-4 bg-gray-100 rounded">
        <h2 className="text-lg font-semibold mb-2">Configuration</h2>
        <pre className="text-xs overflow-auto">
          {JSON.stringify({
            apiUrl: runtimeConfig.apiUrl,
            supabaseUrl: runtimeConfig.supabaseUrl,
            environment: runtimeConfig.environment
          }, null, 2)}
        </pre>
      </div>

      {/* Auth Status */}
      <div className="mb-8 p-4 bg-blue-50 rounded">
        <h2 className="text-lg font-semibold mb-2">Auth Status</h2>
        <pre className="text-xs overflow-auto">
          {JSON.stringify(authStatus, null, 2)}
        </pre>
        <button 
          onClick={checkAuthStatus}
          className="mt-2 px-4 py-2 bg-blue-500 text-white rounded hover:bg-blue-600"
        >
          Refresh Auth Status
        </button>
      </div>

      {/* API Tests */}
      <div className="mb-8 p-4 bg-green-50 rounded">
        <h2 className="text-lg font-semibold mb-2">API Connection Tests</h2>
        <pre className="text-xs overflow-auto max-h-96">
          {JSON.stringify(apiStatus, null, 2)}
        </pre>
        <div className="mt-2 space-x-2">
          <button 
            onClick={testAPIConnection}
            disabled={loading}
            className="px-4 py-2 bg-green-500 text-white rounded hover:bg-green-600 disabled:opacity-50"
          >
            Test API Connection
          </button>
          <button 
            onClick={testAuthentication}
            disabled={loading}
            className="px-4 py-2 bg-green-500 text-white rounded hover:bg-green-600 disabled:opacity-50"
          >
            Test Authentication
          </button>
        </div>
      </div>

      {/* Project Tests */}
      <div className="mb-8 p-4 bg-purple-50 rounded">
        <h2 className="text-lg font-semibold mb-2">Project API Tests</h2>
        <pre className="text-xs overflow-auto max-h-96">
          {JSON.stringify(projectTest, null, 2)}
        </pre>
        <div className="mt-2 space-x-2">
          <button 
            onClick={testProjectCreation}
            disabled={loading}
            className="px-4 py-2 bg-purple-500 text-white rounded hover:bg-purple-600 disabled:opacity-50"
          >
            Test Create Project
          </button>
          <button 
            onClick={testProjectList}
            disabled={loading}
            className="px-4 py-2 bg-purple-500 text-white rounded hover:bg-purple-600 disabled:opacity-50"
          >
            Test List Projects
          </button>
        </div>
      </div>

      {loading && <div className="text-center">Loading...</div>}
    </div>
  )
}