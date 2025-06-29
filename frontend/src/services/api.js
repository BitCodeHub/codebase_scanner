import axios from 'axios'
import toast from 'react-hot-toast'

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000'

const api = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
})

// Request interceptor to add auth token
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('access_token')
    if (token) {
      config.headers.Authorization = `Bearer ${token}`
    }
    return config
  },
  (error) => {
    return Promise.reject(error)
  }
)

// Response interceptor for error handling
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('access_token')
      window.location.href = '/login'
    } else if (error.response?.data?.detail) {
      // Handle both string and object error details
      const errorMessage = typeof error.response.data.detail === 'string' 
        ? error.response.data.detail 
        : error.response.data.detail[0]?.msg || 'An error occurred'
      toast.error(errorMessage)
    } else {
      toast.error('An error occurred')
    }
    return Promise.reject(error)
  }
)

// Auth endpoints
export const auth = {
  login: (credentials) => {
    // OAuth2 expects form data, not JSON
    const formData = new URLSearchParams()
    formData.append('username', credentials.username)
    formData.append('password', credentials.password)
    return api.post('/api/auth/token', formData, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    })
  },
  register: (userData) => api.post('/api/auth/register', userData),
  getMe: () => api.get('/api/auth/me'),
  githubLogin: () => api.get('/api/auth/github/login'),
  githubCallback: (code) => api.post('/api/auth/github/callback', { code }),
}

// Project endpoints
export const projects = {
  list: (params) => api.get('/api/projects', { params }),
  get: (id) => api.get(`/api/projects/${id}`),
  create: (data) => api.post('/api/projects', data),
  update: (id, data) => api.patch(`/api/projects/${id}`, data),
  delete: (id) => api.delete(`/api/projects/${id}`),
  uploadCode: (id, file) => {
    const formData = new FormData()
    formData.append('file', file)
    return api.post(`/api/projects/${id}/upload`, formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    })
  },
}

// Scan endpoints
export const scans = {
  create: (data) => api.post('/api/scans', data),
  list: (params) => api.get('/api/scans', { params }),
  get: (id, includeResults = false) => 
    api.get(`/api/scans/${id}`, { params: { include_results: includeResults } }),
  getResults: (id, params) => api.get(`/api/scans/${id}/results`, { params }),
  cancel: (id) => api.post(`/api/scans/${id}/cancel`),
  markFalsePositive: (scanId, resultId, isFalsePositive) =>
    api.post(`/api/scans/${scanId}/results/${resultId}/false-positive`, {
      is_false_positive: isFalsePositive,
    }),
}

// Report endpoints
export const reports = {
  create: (data) => api.post('/api/reports', data),
  list: (params) => api.get('/api/reports', { params }),
  get: (id) => api.get(`/api/reports/${id}`),
  download: (id) => api.get(`/api/reports/${id}/download`),
  getCompliance: (id) => api.get(`/api/reports/${id}/compliance`),
  getBadge: (id) => api.get(`/api/reports/${id}/badge`),
}

// Convenience methods for components
export const apiService = {
  // Auth
  login: (username, password) => auth.login({ username, password }),
  register: auth.register,
  getMe: auth.getMe,
  
  // Projects
  getProjects: () => projects.list().then(res => res.data),
  getProject: (id) => projects.get(id).then(res => res.data),
  createProject: (data) => projects.create(data).then(res => res.data),
  uploadCodeToProject: (projectId, file) => projects.uploadCode(projectId, file).then(res => res.data),
  
  // Scans
  getProjectScans: (projectId) => scans.list({ project_id: projectId }).then(res => res.data),
  startScan: (projectId, config) => {
    // Transform config to match backend expectations
    const scanData = {
      project_id: projectId,
      scan_type: config.scan_type || 'security',
      scan_config: {
        include_ai_analysis: config.include_ai_analysis || false
      }
    }
    return scans.create(scanData).then(res => res.data)
  },
  getScan: (id) => scans.get(id).then(res => res.data),
  getScanResults: (id) => scans.getResults(id).then(res => res.data),
  
  // Reports
  getReports: () => reports.list().then(res => res.data),
  generateReport: (projectId, config) => reports.create({ project_id: projectId, ...config }).then(res => res.data),
  downloadReport: (id) => reports.download(id).then(res => res.data),
}

export default api