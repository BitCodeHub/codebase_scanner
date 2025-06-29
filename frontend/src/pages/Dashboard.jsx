import { useQuery } from 'react-query'
import { Link } from 'react-router-dom'
import { apiService } from '../services/api'
import { 
  ShieldCheckIcon, 
  CodeBracketIcon, 
  ExclamationTriangleIcon,
  CheckCircleIcon,
  ClockIcon,
  ChartBarIcon,
  ArrowTrendingUpIcon,
  FolderOpenIcon,
  SparklesIcon,
  BoltIcon
} from '@heroicons/react/24/outline'
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  LineChart,
  Line,
  Area,
  AreaChart
} from 'recharts'

const SEVERITY_COLORS = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#22c55e',
  info: '#6b7280',
}

export default function Dashboard() {
  const { data: projectsData, isLoading: loadingProjects } = useQuery('projects', apiService.getProjects)
  const { data: recentScans, isLoading: loadingScans } = useQuery('recentScans', async () => {
    // Mock data for now - in real app this would fetch from API
    return [
      { id: 1, project_id: 1, status: 'completed', critical: 2, high: 5, medium: 12, low: 8, created_at: new Date() },
      { id: 2, project_id: 1, status: 'running', critical: 0, high: 0, medium: 0, low: 0, created_at: new Date() },
    ]
  })

  const stats = {
    totalProjects: projectsData?.length || 0,
    totalScans: recentScans?.length || 0,
    activeScans: recentScans?.filter(s => s.status === 'running').length || 0,
    criticalIssues: recentScans?.reduce((acc, scan) => acc + (scan.critical || 0), 0) || 0,
  }

  // Prepare chart data
  const severityData = [
    { name: 'Critical', value: recentScans?.reduce((acc, s) => acc + (s.critical || 0), 0) || 0, color: SEVERITY_COLORS.critical },
    { name: 'High', value: recentScans?.reduce((acc, s) => acc + (s.high || 0), 0) || 0, color: SEVERITY_COLORS.high },
    { name: 'Medium', value: recentScans?.reduce((acc, s) => acc + (s.medium || 0), 0) || 0, color: SEVERITY_COLORS.medium },
    { name: 'Low', value: recentScans?.reduce((acc, s) => acc + (s.low || 0), 0) || 0, color: SEVERITY_COLORS.low },
  ].filter(item => item.value > 0)

  // Mock trend data
  const trendData = [
    { date: 'Mon', scans: 4, issues: 45 },
    { date: 'Tue', scans: 3, issues: 38 },
    { date: 'Wed', scans: 5, issues: 52 },
    { date: 'Thu', scans: 7, issues: 61 },
    { date: 'Fri', scans: 6, issues: 48 },
    { date: 'Sat', scans: 2, issues: 23 },
    { date: 'Sun', scans: 3, issues: 31 },
  ]

  const loading = loadingProjects || loadingScans

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-600"></div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-gray-900">Security Dashboard</h1>
          <p className="mt-2 text-sm text-gray-600">
            Monitor your code security across all projects
          </p>
        </div>

        {/* Quick Actions */}
        <div className="mb-8 bg-gradient-to-r from-indigo-600 to-purple-600 rounded-xl p-6 text-white">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-xl font-semibold mb-2">Welcome back!</h2>
              <p className="text-indigo-100">
                {stats.activeScans > 0 
                  ? `You have ${stats.activeScans} active scan${stats.activeScans > 1 ? 's' : ''} running`
                  : 'All scans completed. Start a new security scan to check your code.'}
              </p>
            </div>
            <div className="flex gap-3">
              <Link 
                to="/projects" 
                className="bg-white text-indigo-600 px-4 py-2 rounded-lg font-medium hover:bg-indigo-50 transition-colors flex items-center gap-2"
              >
                <FolderOpenIcon className="h-5 w-5" />
                View Projects
              </Link>
              <Link 
                to="/projects?new=true" 
                className="bg-indigo-700 text-white px-4 py-2 rounded-lg font-medium hover:bg-indigo-800 transition-colors flex items-center gap-2"
              >
                <BoltIcon className="h-5 w-5" />
                Quick Scan
              </Link>
            </div>
          </div>
        </div>

        {/* Stats Grid */}
        <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-4 mb-8">
          <div className="bg-white rounded-xl shadow-sm p-6 border border-gray-100 hover:shadow-md transition-shadow">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Total Projects</p>
                <p className="text-3xl font-bold text-gray-900 mt-2">{stats.totalProjects}</p>
              </div>
              <div className="bg-indigo-100 rounded-lg p-3">
                <CodeBracketIcon className="h-6 w-6 text-indigo-600" />
              </div>
            </div>
            <div className="mt-4 flex items-center text-sm">
              <span className="text-green-600 font-medium">+12%</span>
              <span className="text-gray-500 ml-2">from last month</span>
            </div>
          </div>

          <div className="bg-white rounded-xl shadow-sm p-6 border border-gray-100 hover:shadow-md transition-shadow">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Total Scans</p>
                <p className="text-3xl font-bold text-gray-900 mt-2">{stats.totalScans}</p>
              </div>
              <div className="bg-purple-100 rounded-lg p-3">
                <ShieldCheckIcon className="h-6 w-6 text-purple-600" />
              </div>
            </div>
            <div className="mt-4 flex items-center text-sm">
              <span className="text-green-600 font-medium">+23%</span>
              <span className="text-gray-500 ml-2">from last month</span>
            </div>
          </div>

          <div className="bg-white rounded-xl shadow-sm p-6 border border-gray-100 hover:shadow-md transition-shadow">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Active Scans</p>
                <p className="text-3xl font-bold text-gray-900 mt-2">{stats.activeScans}</p>
              </div>
              <div className="bg-blue-100 rounded-lg p-3">
                <ClockIcon className="h-6 w-6 text-blue-600" />
              </div>
            </div>
            <div className="mt-4">
              <div className="w-full bg-gray-200 rounded-full h-2">
                <div className="bg-blue-600 h-2 rounded-full animate-pulse" style={{ width: '45%' }}></div>
              </div>
            </div>
          </div>

          <div className="bg-white rounded-xl shadow-sm p-6 border border-gray-100 hover:shadow-md transition-shadow">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Critical Issues</p>
                <p className="text-3xl font-bold text-red-600 mt-2">{stats.criticalIssues}</p>
              </div>
              <div className="bg-red-100 rounded-lg p-3">
                <ExclamationTriangleIcon className="h-6 w-6 text-red-600" />
              </div>
            </div>
            <div className="mt-4 flex items-center text-sm">
              <span className="text-red-600 font-medium">-8%</span>
              <span className="text-gray-500 ml-2">from last month</span>
            </div>
          </div>
        </div>

        {/* Charts Section */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
          {/* Severity Distribution */}
          <div className="bg-white rounded-xl shadow-sm p-6 border border-gray-100">
            <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center">
              <ChartBarIcon className="h-5 w-5 mr-2 text-gray-400" />
              Severity Distribution
            </h3>
            {severityData.length > 0 ? (
              <ResponsiveContainer width="100%" height={250}>
                <PieChart>
                  <Pie
                    data={severityData}
                    cx="50%"
                    cy="50%"
                    innerRadius={60}
                    outerRadius={90}
                    paddingAngle={5}
                    dataKey="value"
                  >
                    {severityData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-[250px] flex items-center justify-center">
                <p className="text-gray-500">No issues found</p>
              </div>
            )}
            <div className="mt-4 space-y-2">
              {severityData.map((item) => (
                <div key={item.name} className="flex items-center justify-between">
                  <div className="flex items-center">
                    <div className="w-3 h-3 rounded-full mr-2" style={{ backgroundColor: item.color }}></div>
                    <span className="text-sm text-gray-600">{item.name}</span>
                  </div>
                  <span className="text-sm font-medium text-gray-900">{item.value}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Weekly Trend */}
          <div className="bg-white rounded-xl shadow-sm p-6 border border-gray-100 lg:col-span-2">
            <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center">
              <ArrowTrendingUpIcon className="h-5 w-5 mr-2 text-gray-400" />
              Weekly Activity
            </h3>
            <ResponsiveContainer width="100%" height={250}>
              <AreaChart data={trendData}>
                <defs>
                  <linearGradient id="colorScans" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#818cf8" stopOpacity={0.8}/>
                    <stop offset="95%" stopColor="#818cf8" stopOpacity={0}/>
                  </linearGradient>
                  <linearGradient id="colorIssues" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#f472b6" stopOpacity={0.8}/>
                    <stop offset="95%" stopColor="#f472b6" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#f3f4f6" />
                <XAxis dataKey="date" tick={{ fontSize: 12 }} tickLine={false} />
                <YAxis tick={{ fontSize: 12 }} tickLine={false} />
                <Tooltip />
                <Area type="monotone" dataKey="scans" stroke="#818cf8" fillOpacity={1} fill="url(#colorScans)" />
                <Area type="monotone" dataKey="issues" stroke="#f472b6" fillOpacity={1} fill="url(#colorIssues)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Recent Activity */}
        <div className="bg-white rounded-xl shadow-sm overflow-hidden border border-gray-100">
          <div className="px-6 py-4 border-b border-gray-100">
            <h3 className="text-lg font-semibold text-gray-900 flex items-center">
              <SparklesIcon className="h-5 w-5 mr-2 text-gray-400" />
              Recent Activity
            </h3>
          </div>
          <div className="p-6">
            {projectsData && projectsData.length > 0 ? (
              <div className="space-y-4">
                {projectsData.slice(0, 5).map((project) => (
                  <div key={project.id} className="flex items-center justify-between p-4 bg-gray-50 rounded-lg hover:bg-gray-100 transition-colors">
                    <div className="flex items-center">
                      <div className="bg-indigo-100 rounded-lg p-2 mr-4">
                        <CodeBracketIcon className="h-5 w-5 text-indigo-600" />
                      </div>
                      <div>
                        <h4 className="text-sm font-medium text-gray-900">{project.name}</h4>
                        <p className="text-xs text-gray-500">Last scan: {project.last_scan_at ? new Date(project.last_scan_at).toLocaleDateString() : 'Never'}</p>
                      </div>
                    </div>
                    <Link 
                      to={`/projects/${project.id}`}
                      className="text-sm font-medium text-indigo-600 hover:text-indigo-700"
                    >
                      View Details →
                    </Link>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center py-8">
                <FolderOpenIcon className="mx-auto h-12 w-12 text-gray-400 mb-3" />
                <p className="text-gray-500">No projects yet</p>
                <Link 
                  to="/projects" 
                  className="mt-3 inline-flex items-center text-sm font-medium text-indigo-600 hover:text-indigo-700"
                >
                  Create your first project →
                </Link>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}