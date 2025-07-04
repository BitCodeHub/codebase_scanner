import { useState, useEffect } from 'react'
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom'
import { subscribeToAuthState } from './lib/supabase-safe'
import { Session } from '@supabase/supabase-js'

// Components
import Layout from './components/layout/Layout'
import AuthPage from './pages/AuthPage'
import Dashboard from './pages/Dashboard'
import ModernProjectsPage from './pages/ModernProjectsPage'
import ProjectDetail from './pages/ProjectDetail'
import ModernScanResults from './pages/ModernScanResults'
import Activity from './pages/Activity'
import DebugPage from './pages/DebugPage'
import LoadingSpinner from './components/ui/LoadingSpinner'
import UniversalScanPage from './pages/UniversalScanPage'
import { ComprehensiveScan } from './components/ComprehensiveScan'
import { EnterpriseGitHubScan } from './components/EnterpriseGitHubScan'
import TestBackend from './pages/TestBackend'

function App() {
  const [session, setSession] = useState<Session | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<Error | null>(null)

  useEffect(() => {
    // Subscribe to auth state changes
    const unsubscribe = subscribeToAuthState((state: { session: Session | null; loading: boolean; error: Error | null }) => {
      setSession(state.session)
      setLoading(state.loading)
      setError(state.error)
    })

    return unsubscribe
  }, [])

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <LoadingSpinner size="lg" />
      </div>
    )
  }

  if (!session) {
    return <AuthPage />
  }

  return (
    <Router>
      <Layout>
        <Routes>
          <Route path="/" element={<Navigate to="/dashboard" replace />} />
          <Route path="/dashboard" element={<ModernProjectsPage />} />
          <Route path="/projects" element={<ModernProjectsPage />} />
          <Route path="/projects/:id" element={<ProjectDetail />} />
          <Route path="/scans/:id/results" element={<ModernScanResults />} />
          <Route path="/activity" element={<Activity />} />
          <Route path="/debug" element={<DebugPage />} />
          <Route path="/scan-file" element={<UniversalScanPage />} />
          <Route path="/security" element={<ComprehensiveScan />} />
          <Route path="/github-scan" element={<EnterpriseGitHubScan />} />
          <Route path="/test-backend" element={<TestBackend />} />
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </Layout>
    </Router>
  )
}

export default App