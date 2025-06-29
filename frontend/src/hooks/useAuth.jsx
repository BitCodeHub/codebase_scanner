import { useState, useEffect, createContext, useContext } from 'react'
import { apiService, auth as authApi } from '../services/api'

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    checkAuth()
  }, [])

  const checkAuth = async () => {
    const token = localStorage.getItem('access_token')
    if (token) {
      try {
        const userData = await apiService.getMe()
        setUser(userData)
      } catch (error) {
        localStorage.removeItem('access_token')
      }
    }
    setLoading(false)
  }

  const login = async (username, password) => {
    const response = await apiService.login(username, password)
    localStorage.setItem('access_token', response.data.access_token)
    await checkAuth()
    return response.data
  }

  const register = async (userData) => {
    const response = await apiService.register(userData)
    return response
  }

  const logout = () => {
    localStorage.removeItem('access_token')
    setUser(null)
  }

  const value = {
    user,
    loading,
    login,
    register,
    logout,
    checkAuth,
  }

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth() {
  const context = useContext(AuthContext)
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}