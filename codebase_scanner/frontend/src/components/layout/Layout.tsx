import { ReactNode, useState } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { supabase } from '../../lib/supabase'
import { 
  HomeIcon, 
  FolderIcon, 
  ShieldCheckIcon,
  UserIcon,
  LogOut,
  Settings,
  Activity,
  Bell,
  Menu,
  X,
  Bug,
  Upload
} from 'lucide-react'

interface LayoutProps {
  children: ReactNode
}

export default function Layout({ children }: LayoutProps) {
  const location = useLocation()
  const [isSidebarCollapsed, setIsSidebarCollapsed] = useState(false)

  const navigation = [
    { name: 'Dashboard', href: '/dashboard', icon: HomeIcon, description: 'Overview and metrics' },
    { name: 'Projects', href: '/projects', icon: FolderIcon, description: 'Manage your projects' },
    { name: 'Quick Scan', href: '/scan-file', icon: Upload, description: 'Simple file scanner' },
    { name: 'Deep Scan', href: '/security', icon: ShieldCheckIcon, description: 'Comprehensive analysis' },
    { name: 'GitHub Scan', href: '/github-scan', icon: FolderIcon, description: 'Enterprise GitHub scanner' },
    { name: 'Activity', href: '/activity', icon: Activity, description: 'Recent scans and logs' },
    { name: 'Debug', href: '/debug', icon: Bug, description: 'Debug tools' },
  ]

  const handleSignOut = async () => {
    await supabase.auth.signOut()
  }

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Sidebar */}
      <div className={`fixed inset-y-0 left-0 bg-white shadow-lg border-r border-gray-200 transition-all duration-300 ease-in-out ${
        isSidebarCollapsed ? 'w-16' : 'w-64'
      }`}>
        <div className="flex h-16 items-center justify-between px-4 border-b border-gray-200 bg-gradient-to-r from-blue-600 to-blue-700">
          <div className={`flex items-center ${isSidebarCollapsed ? 'justify-center w-full' : ''}`}>
            <ShieldCheckIcon className="h-8 w-8 text-white flex-shrink-0" />
            {!isSidebarCollapsed && <span className="ml-2 text-xl font-bold text-white">CodeScan</span>}
          </div>
          <button
            onClick={() => setIsSidebarCollapsed(!isSidebarCollapsed)}
            className="text-white hover:bg-blue-800/20 p-1.5 rounded-lg transition-colors"
          >
            {isSidebarCollapsed ? <Menu className="h-5 w-5" /> : <X className="h-5 w-5" />}
          </button>
        </div>
        
        <nav className="mt-6 px-3">
          <div className="space-y-2">
            {navigation.map((item) => {
              const isActive = location.pathname === item.href
              return (
                <Link
                  key={item.name}
                  to={item.href}
                  className={`group flex items-center ${isSidebarCollapsed ? 'justify-center px-3' : 'px-3'} py-3 text-sm font-medium rounded-lg transition-all duration-200 ${
                    isActive
                      ? 'bg-blue-50 text-blue-700'
                      : 'text-gray-700 hover:bg-gray-50 hover:text-gray-900'
                  }`}
                  title={isSidebarCollapsed ? item.name : ''}
                >
                  <item.icon className={`h-5 w-5 ${isSidebarCollapsed ? '' : 'mr-3'} transition-colors ${
                    isActive ? 'text-blue-600' : 'text-gray-400 group-hover:text-gray-600'
                  }`} />
                  {!isSidebarCollapsed && (
                    <div className="flex-1">
                      <div className="font-medium">{item.name}</div>
                      <div className="text-xs text-gray-500 mt-0.5">{item.description}</div>
                    </div>
                  )}
                </Link>
              )
            })}
          </div>
        </nav>

        {/* User menu at bottom */}
        <div className="absolute bottom-0 left-0 right-0 p-3 border-t border-gray-200 bg-gray-50">
          {!isSidebarCollapsed && (
            <div className="mb-3">
              <button className="w-full flex items-center px-3 py-2 text-sm text-gray-700 hover:bg-gray-100 rounded-lg transition-colors">
                <Bell className="h-4 w-4 mr-2 text-gray-400" />
                <span>Notifications</span>
                <span className="ml-auto bg-red-500 text-white text-xs rounded-full h-5 w-5 flex items-center justify-center">3</span>
              </button>
            </div>
          )}
          <div className={`flex items-center ${isSidebarCollapsed ? 'justify-center' : 'justify-between'}`}>
            {isSidebarCollapsed ? (
              <div className="flex flex-col items-center space-y-2">
                <div className="h-9 w-9 rounded-full bg-gradient-to-br from-blue-400 to-blue-600 flex items-center justify-center">
                  <UserIcon className="h-5 w-5 text-white" />
                </div>
                <button
                  onClick={handleSignOut}
                  className="p-1.5 text-gray-400 hover:text-red-600 hover:bg-red-50 rounded-md transition-colors"
                  title="Sign out"
                >
                  <LogOut className="h-4 w-4" />
                </button>
              </div>
            ) : (
              <>
                <div className="flex items-center">
                  <div className="h-9 w-9 rounded-full bg-gradient-to-br from-blue-400 to-blue-600 flex items-center justify-center">
                    <UserIcon className="h-5 w-5 text-white" />
                  </div>
                  <div className="ml-2">
                    <div className="text-sm font-medium text-gray-700">Security Admin</div>
                    <div className="text-xs text-gray-500">admin@codescan.io</div>
                  </div>
                </div>
                <div className="flex items-center space-x-1">
                  <button
                    className="p-1.5 text-gray-400 hover:text-gray-600 hover:bg-gray-100 rounded-md transition-colors"
                    title="Settings"
                  >
                    <Settings className="h-4 w-4" />
                  </button>
                  <button
                    onClick={handleSignOut}
                    className="p-1.5 text-gray-400 hover:text-red-600 hover:bg-red-50 rounded-md transition-colors"
                    title="Sign out"
                  >
                    <LogOut className="h-4 w-4" />
                  </button>
                </div>
              </>
            )}
          </div>
        </div>
      </div>

      {/* Main content */}
      <div className={`transition-all duration-300 ease-in-out ${isSidebarCollapsed ? 'pl-16' : 'pl-64'}`}>
        <main className="flex-1">
          {children}
        </main>
      </div>
    </div>
  )
}