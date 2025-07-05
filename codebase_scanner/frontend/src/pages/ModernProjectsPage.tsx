import { useState, useEffect } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { db } from '../lib/supabase-proxy'
import { 
  Plus, 
  Shield,
  Zap,
  Search,
  ScanLine,
  ChevronRight,
  Target,
  Activity,
  TrendingUp,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Code2,
  GitBranch,
  Clock,
  Package,
  Bug,
  Lock,
  Sparkles,
  ArrowUpRight,
  BarChart3,
  Users,
  Calendar,
  FileSearch,
  Settings,
  Menu,
  X,
  Github,
  Loader2
} from 'lucide-react'
import LoadingSpinner from '../components/ui/LoadingSpinner'
import CreateProjectModal from '../components/forms/CreateProjectModal'
import { listProjects, Project } from '../services/projectService'
import { getFullApiUrl } from '../utils/api-config'

interface ProjectWithStats extends Project {
  scan_count?: number
  last_scan?: any
  risk_score?: number
}

export default function ModernProjectsPage() {
  const [projects, setProjects] = useState<ProjectWithStats[]>([])
  const [loading, setLoading] = useState(true)
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [scanningProject, setScanningProject] = useState<string | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [selectedFilter, setSelectedFilter] = useState<'all' | 'high-risk' | 'secure' | 'no-scans'>('all')
  const [showMobileMenu, setShowMobileMenu] = useState(false)
  const navigate = useNavigate()

  useEffect(() => {
    loadProjects()
    const interval = setInterval(loadProjects, 30000)
    return () => clearInterval(interval)
  }, [])

  const loadProjects = async () => {
    try {
      console.log('Loading projects...')
      const response = await listProjects(0, 50)
      console.log('Projects response:', response)
      
      const projectsWithStats = await Promise.all(
        response.projects.map(async (project) => {
          try {
            // Use the db helper directly to avoid the proxy issue
            const { data: scans, error: scanError } = await db.scans.list(parseInt(project.id))
            
            if (scanError) {
              console.error(`Error loading scans for project ${project.id}:`, scanError)
            }
            
            // Calculate risk score based on last scan
            let riskScore = 0
            if (scans && scans.length > 0) {
              const lastScan = scans[0]
              riskScore = 
                (lastScan.critical_issues || 0) * 10 +
                (lastScan.high_issues || 0) * 5 +
                (lastScan.medium_issues || 0) * 2 +
                (lastScan.low_issues || 0) * 1
            }
            
            return {
              ...project,
              scan_count: scans?.length || 0,
              last_scan: scans?.[0] || null,
              risk_score: riskScore
            } as ProjectWithStats
          } catch (error) {
            console.error(`Error loading scans for project ${project.id}:`, error)
            return {
              ...project,
              scan_count: 0,
              last_scan: null,
              risk_score: 0
            } as ProjectWithStats
          }
        })
      )

      console.log('Projects with stats:', projectsWithStats)
      setProjects(projectsWithStats)
    } catch (error) {
      console.error('Error loading projects:', error)
    } finally {
      setLoading(false)
    }
  }

  const handleProjectCreated = async () => {
    setShowCreateModal(false)
    setTimeout(() => {
      loadProjects()
    }, 500)
  }

  const handleScan = async (projectId: string) => {
    console.log('Starting scan for project:', projectId)
    setScanningProject(projectId)
    
    try {
      const project = projects.find(p => p.id === projectId)
      if (!project) throw new Error('Project not found')

      const { data: { user } } = await db.auth.getUser()
      if (!user) throw new Error('No user found')

      const repositoryUrl = project.repository_url || 'https://github.com/OWASP/NodeGoat'
      
      const response = await fetch(getFullApiUrl('/api/scans/mobile-app'), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          project_id: projectId,
          repository_url: repositoryUrl,
          branch: 'main',
          scan_type: 'comprehensive',
          user_id: user.id,
          enable_ai_analysis: true
        })
      })

      if (!response.ok) {
        throw new Error(`Scan failed: ${response.statusText}`)
      }

      const scanResult = await response.json()
      console.log('Scan initiated:', scanResult)
      
      // Show success notification
      showNotification('success', 'Security scan started successfully!')
      
      // Refresh projects after a delay
      setTimeout(() => {
        loadProjects()
      }, 2000)

      // Navigate to scan results if we have an ID
      if (scanResult.id) {
        setTimeout(() => {
          navigate(`/scans/${scanResult.id}/results`)
        }, 1500)
      }
    } catch (error) {
      console.error('Error starting scan:', error)
      showNotification('error', error instanceof Error ? error.message : 'Failed to start scan')
    } finally {
      setScanningProject(null)
    }
  }

  const showNotification = (type: 'success' | 'error', message: string) => {
    const notificationDiv = document.createElement('div')
    notificationDiv.className = `fixed bottom-4 right-4 ${
      type === 'success' ? 'bg-green-500' : 'bg-red-500'
    } text-white px-6 py-3 rounded-lg shadow-lg flex items-center space-x-2 animate-slide-up z-50`
    notificationDiv.innerHTML = `
      ${type === 'success' 
        ? '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path></svg>'
        : '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>'
      }
      <span>${message}</span>
    `
    document.body.appendChild(notificationDiv)
    setTimeout(() => notificationDiv.remove(), 3000)
  }

  const filteredProjects = projects.filter(project => {
    const matchesSearch = 
      project.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      project.description?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      project.repository_url?.toLowerCase().includes(searchQuery.toLowerCase())
    
    let matchesFilter = true
    if (selectedFilter === 'high-risk') {
      matchesFilter = (project.risk_score || 0) > 20
    } else if (selectedFilter === 'secure') {
      matchesFilter = project.last_scan && (project.risk_score || 0) === 0
    } else if (selectedFilter === 'no-scans') {
      matchesFilter = !project.last_scan
    }
    
    return matchesSearch && matchesFilter
  })

  const stats = {
    totalProjects: projects.length,
    totalScans: projects.reduce((sum, p) => sum + (p.scan_count || 0), 0),
    highRiskProjects: projects.filter(p => (p.risk_score || 0) > 20).length,
    secureProjects: projects.filter(p => p.last_scan && (p.risk_score || 0) === 0).length
  }

  const getRiskBadge = (riskScore: number = 0) => {
    if (riskScore === 0) return { color: 'bg-green-100 text-green-800', label: 'Secure', icon: CheckCircle }
    if (riskScore <= 10) return { color: 'bg-blue-100 text-blue-800', label: 'Low Risk', icon: Shield }
    if (riskScore <= 20) return { color: 'bg-yellow-100 text-yellow-800', label: 'Medium Risk', icon: AlertTriangle }
    return { color: 'bg-red-100 text-red-800', label: 'High Risk', icon: XCircle }
  }

  if (loading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900 flex items-center justify-center">
        <div className="text-center">
          <div className="relative">
            <div className="w-24 h-24 rounded-full bg-gradient-to-r from-blue-500 to-purple-600 animate-pulse"></div>
            <Shield className="w-12 h-12 text-white absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2" />
          </div>
          <p className="mt-6 text-gray-300 text-lg">Loading your security dashboard...</p>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900">
      {/* Animated background pattern */}
      <div className="fixed inset-0 overflow-hidden pointer-events-none">
        <div className="absolute -top-40 -right-40 w-80 h-80 bg-purple-500 rounded-full mix-blend-multiply filter blur-3xl opacity-10 animate-blob"></div>
        <div className="absolute -bottom-40 -left-40 w-80 h-80 bg-blue-500 rounded-full mix-blend-multiply filter blur-3xl opacity-10 animate-blob animation-delay-2000"></div>
        <div className="absolute top-40 left-40 w-80 h-80 bg-indigo-500 rounded-full mix-blend-multiply filter blur-3xl opacity-10 animate-blob animation-delay-4000"></div>
      </div>

      {/* Header */}
      <header className="relative backdrop-blur-xl bg-gray-900/70 border-b border-gray-700/50 sticky top-0 z-40">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center space-x-4">
              <button
                onClick={() => setShowMobileMenu(!showMobileMenu)}
                className="md:hidden p-2 rounded-lg hover:bg-gray-800 transition-colors"
              >
                {showMobileMenu ? <X className="w-6 h-6 text-gray-300" /> : <Menu className="w-6 h-6 text-gray-300" />}
              </button>
              <div className="flex items-center space-x-3">
                <div className="p-2 bg-gradient-to-r from-blue-500 to-purple-600 rounded-lg">
                  <Shield className="w-6 h-6 text-white" />
                </div>
                <h1 className="text-xl font-bold text-white">Security Scanner</h1>
              </div>
            </div>
            
            <nav className="hidden md:flex items-center space-x-6">
              <Link to="/dashboard" className="text-gray-300 hover:text-white transition-colors flex items-center space-x-2">
                <BarChart3 className="w-4 h-4" />
                <span>Dashboard</span>
              </Link>
              <Link to="/scans" className="text-gray-300 hover:text-white transition-colors flex items-center space-x-2">
                <FileSearch className="w-4 h-4" />
                <span>All Scans</span>
              </Link>
              <Link to="/settings" className="text-gray-300 hover:text-white transition-colors flex items-center space-x-2">
                <Settings className="w-4 h-4" />
                <span>Settings</span>
              </Link>
            </nav>

            <button
              onClick={() => setShowCreateModal(true)}
              className="flex items-center space-x-2 px-4 py-2 bg-gradient-to-r from-blue-500 to-purple-600 text-white rounded-lg hover:from-blue-600 hover:to-purple-700 transition-all transform hover:scale-105 shadow-lg"
            >
              <Plus className="w-5 h-5" />
              <span className="hidden sm:inline">New Project</span>
            </button>
          </div>
        </div>

        {/* Mobile menu */}
        {showMobileMenu && (
          <div className="md:hidden border-t border-gray-700/50 bg-gray-900/90 backdrop-blur-xl">
            <nav className="px-4 py-4 space-y-2">
              <Link to="/dashboard" className="flex items-center space-x-2 text-gray-300 hover:text-white p-2 rounded-lg hover:bg-gray-800 transition-colors">
                <BarChart3 className="w-4 h-4" />
                <span>Dashboard</span>
              </Link>
              <Link to="/scans" className="flex items-center space-x-2 text-gray-300 hover:text-white p-2 rounded-lg hover:bg-gray-800 transition-colors">
                <FileSearch className="w-4 h-4" />
                <span>All Scans</span>
              </Link>
              <Link to="/settings" className="flex items-center space-x-2 text-gray-300 hover:text-white p-2 rounded-lg hover:bg-gray-800 transition-colors">
                <Settings className="w-4 h-4" />
                <span>Settings</span>
              </Link>
            </nav>
          </div>
        )}
      </header>

      {/* Main content */}
      <main className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Hero section */}
        <div className="mb-12 text-center">
          <h2 className="text-4xl md:text-5xl font-bold text-white mb-4">
            <span className="bg-gradient-to-r from-blue-400 to-purple-600 bg-clip-text text-transparent">
              Secure Your Code
            </span>
          </h2>
          <p className="text-gray-400 text-lg max-w-2xl mx-auto">
            AI-powered security scanning for modern applications. Detect vulnerabilities, 
            secrets, and compliance issues before they reach production.
          </p>
        </div>

        {/* Stats cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
          <div className="bg-gradient-to-br from-gray-800/50 to-gray-900/50 backdrop-blur-xl rounded-2xl p-6 border border-gray-700/50">
            <div className="flex items-center justify-between mb-4">
              <div className="p-3 bg-blue-500/20 rounded-lg">
                <Package className="w-6 h-6 text-blue-400" />
              </div>
              <TrendingUp className="w-5 h-5 text-green-400" />
            </div>
            <p className="text-gray-400 text-sm">Total Projects</p>
            <p className="text-3xl font-bold text-white">{stats.totalProjects}</p>
          </div>

          <div className="bg-gradient-to-br from-gray-800/50 to-gray-900/50 backdrop-blur-xl rounded-2xl p-6 border border-gray-700/50">
            <div className="flex items-center justify-between mb-4">
              <div className="p-3 bg-purple-500/20 rounded-lg">
                <ScanLine className="w-6 h-6 text-purple-400" />
              </div>
              <Activity className="w-5 h-5 text-purple-400" />
            </div>
            <p className="text-gray-400 text-sm">Total Scans</p>
            <p className="text-3xl font-bold text-white">{stats.totalScans}</p>
          </div>

          <div className="bg-gradient-to-br from-gray-800/50 to-gray-900/50 backdrop-blur-xl rounded-2xl p-6 border border-gray-700/50">
            <div className="flex items-center justify-between mb-4">
              <div className="p-3 bg-red-500/20 rounded-lg">
                <AlertTriangle className="w-6 h-6 text-red-400" />
              </div>
              <ArrowUpRight className="w-5 h-5 text-red-400" />
            </div>
            <p className="text-gray-400 text-sm">High Risk</p>
            <p className="text-3xl font-bold text-white">{stats.highRiskProjects}</p>
          </div>

          <div className="bg-gradient-to-br from-gray-800/50 to-gray-900/50 backdrop-blur-xl rounded-2xl p-6 border border-gray-700/50">
            <div className="flex items-center justify-between mb-4">
              <div className="p-3 bg-green-500/20 rounded-lg">
                <CheckCircle className="w-6 h-6 text-green-400" />
              </div>
              <Shield className="w-5 h-5 text-green-400" />
            </div>
            <p className="text-gray-400 text-sm">Secure</p>
            <p className="text-3xl font-bold text-white">{stats.secureProjects}</p>
          </div>
        </div>

        {/* Search and filters */}
        <div className="flex flex-col sm:flex-row gap-4 mb-8">
          <div className="flex-1 relative">
            <Search className="absolute left-4 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
            <input
              type="text"
              placeholder="Search projects..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-12 pr-4 py-3 bg-gray-800/50 backdrop-blur-xl border border-gray-700/50 rounded-xl text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500/50 focus:border-transparent transition-all"
            />
          </div>
          
          <div className="flex gap-2">
            {(['all', 'high-risk', 'secure', 'no-scans'] as const).map((filter) => (
              <button
                key={filter}
                onClick={() => setSelectedFilter(filter)}
                className={`px-4 py-2 rounded-lg font-medium transition-all ${
                  selectedFilter === filter
                    ? 'bg-gradient-to-r from-blue-500 to-purple-600 text-white'
                    : 'bg-gray-800/50 text-gray-400 hover:text-white hover:bg-gray-700/50'
                }`}
              >
                {filter === 'all' && 'All'}
                {filter === 'high-risk' && 'High Risk'}
                {filter === 'secure' && 'Secure'}
                {filter === 'no-scans' && 'Not Scanned'}
              </button>
            ))}
          </div>
        </div>

        {/* Projects grid */}
        {filteredProjects.length > 0 ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {filteredProjects.map((project) => {
              const isScanning = scanningProject === project.id
              const riskBadge = getRiskBadge(project.risk_score)
              const RiskIcon = riskBadge.icon
              
              return (
                <div
                  key={project.id}
                  className="group bg-gradient-to-br from-gray-800/50 to-gray-900/50 backdrop-blur-xl rounded-2xl border border-gray-700/50 hover:border-gray-600/50 transition-all hover:transform hover:scale-[1.02] hover:shadow-2xl"
                >
                  <div className="p-6">
                    {/* Header */}
                    <div className="flex items-start justify-between mb-4">
                      <div className="flex-1">
                        <h3 className="text-xl font-semibold text-white mb-2 group-hover:text-blue-400 transition-colors">
                          {project.name}
                        </h3>
                        {project.description && (
                          <p className="text-gray-400 text-sm line-clamp-2">{project.description}</p>
                        )}
                      </div>
                      {project.last_scan && (
                        <div className={`px-3 py-1 rounded-full text-xs font-medium flex items-center space-x-1 ${riskBadge.color}`}>
                          <RiskIcon className="w-3 h-3" />
                          <span>{riskBadge.label}</span>
                        </div>
                      )}
                    </div>

                    {/* Repository info */}
                    {project.repository_url && (
                      <div className="flex items-center text-sm text-gray-500 mb-4">
                        <GitBranch className="w-4 h-4 mr-2" />
                        <span className="truncate">{project.repository_url.replace('https://github.com/', '')}</span>
                      </div>
                    )}

                    {/* Stats */}
                    <div className="grid grid-cols-2 gap-4 mb-4">
                      <div className="bg-gray-900/50 rounded-lg p-3">
                        <div className="flex items-center justify-between">
                          <span className="text-gray-400 text-xs">Scans</span>
                          <ScanLine className="w-4 h-4 text-gray-500" />
                        </div>
                        <p className="text-white font-semibold">{project.scan_count}</p>
                      </div>
                      
                      <div className="bg-gray-900/50 rounded-lg p-3">
                        <div className="flex items-center justify-between">
                          <span className="text-gray-400 text-xs">Issues</span>
                          <Bug className="w-4 h-4 text-gray-500" />
                        </div>
                        <p className="text-white font-semibold">
                          {project.last_scan ? project.last_scan.total_issues || 0 : '-'}
                        </p>
                      </div>
                    </div>

                    {/* Last scan info */}
                    {project.last_scan && (
                      <div className="flex items-center text-xs text-gray-500 mb-4">
                        <Clock className="w-3 h-3 mr-1" />
                        <span>Last scan: {new Date(project.last_scan.created_at).toLocaleDateString()}</span>
                      </div>
                    )}

                    {/* Actions */}
                    <div className="flex gap-2">
                      <Link
                        to={`/projects/${project.id}`}
                        className="flex-1 flex items-center justify-center space-x-2 px-4 py-2 bg-gray-700/50 hover:bg-gray-700 text-gray-300 hover:text-white rounded-lg transition-all"
                      >
                        <span>View Details</span>
                        <ChevronRight className="w-4 h-4" />
                      </Link>
                      
                      <button
                        onClick={() => handleScan(project.id)}
                        disabled={isScanning}
                        className="flex items-center justify-center space-x-2 px-4 py-2 bg-gradient-to-r from-blue-500 to-purple-600 hover:from-blue-600 hover:to-purple-700 text-white rounded-lg transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                      >
                        {isScanning ? (
                          <>
                            <Loader2 className="w-4 h-4 animate-spin" />
                            <span>Scanning...</span>
                          </>
                        ) : (
                          <>
                            <Zap className="w-4 h-4" />
                            <span>Scan</span>
                          </>
                        )}
                      </button>
                    </div>
                  </div>
                </div>
              )
            })}
          </div>
        ) : (
          /* Empty state */
          <div className="text-center py-16">
            <div className="inline-flex items-center justify-center w-24 h-24 rounded-full bg-gray-800/50 mb-6">
              <Target className="w-12 h-12 text-gray-600" />
            </div>
            <h3 className="text-2xl font-semibold text-white mb-2">
              {searchQuery || selectedFilter !== 'all' ? 'No projects found' : 'Start your security journey'}
            </h3>
            <p className="text-gray-400 mb-8 max-w-md mx-auto">
              {searchQuery || selectedFilter !== 'all' 
                ? 'Try adjusting your search or filters'
                : 'Create your first project and scan for vulnerabilities'
              }
            </p>
            {!searchQuery && selectedFilter === 'all' && (
              <button
                onClick={() => setShowCreateModal(true)}
                className="inline-flex items-center space-x-2 px-6 py-3 bg-gradient-to-r from-blue-500 to-purple-600 text-white rounded-lg hover:from-blue-600 hover:to-purple-700 transition-all transform hover:scale-105 shadow-lg"
              >
                <Sparkles className="w-5 h-5" />
                <span>Create Your First Project</span>
              </button>
            )}
          </div>
        )}
      </main>

      {/* Create Project Modal */}
      {showCreateModal && (
        <CreateProjectModal
          onClose={() => setShowCreateModal(false)}
          onSuccess={handleProjectCreated}
        />
      )}

      {/* Styles */}
      <style>{`
        @keyframes blob {
          0% { transform: translate(0px, 0px) scale(1); }
          33% { transform: translate(30px, -50px) scale(1.1); }
          66% { transform: translate(-20px, 20px) scale(0.9); }
          100% { transform: translate(0px, 0px) scale(1); }
        }
        
        .animate-blob {
          animation: blob 7s infinite;
        }
        
        .animation-delay-2000 {
          animation-delay: 2s;
        }
        
        .animation-delay-4000 {
          animation-delay: 4s;
        }
        
        @keyframes slide-up {
          from {
            transform: translateY(100%);
            opacity: 0;
          }
          to {
            transform: translateY(0);
            opacity: 1;
          }
        }
        
        .animate-slide-up {
          animation: slide-up 0.3s ease-out;
        }
        
        .line-clamp-2 {
          overflow: hidden;
          display: -webkit-box;
          -webkit-line-clamp: 2;
          -webkit-box-orient: vertical;
        }
      `}</style>
    </div>
  )
}