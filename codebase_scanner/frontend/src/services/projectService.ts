import { supabase } from '../lib/supabase'
import { runtimeConfig } from '../generated/config'

const API_BASE_URL = runtimeConfig.apiUrl || import.meta.env.VITE_API_URL || 'http://localhost:8000'

export interface Project {
  id: string
  name: string
  description?: string
  repository_url?: string
  language?: string
  framework?: string
  active: boolean
  created_at: string
  updated_at: string
}

export interface CreateProjectData {
  name: string
  description?: string
  repository_url?: string
  language?: string
  framework?: string
}

export interface UpdateProjectData {
  name?: string
  description?: string
  repository_url?: string
  language?: string
  framework?: string
  active?: boolean
}

export interface ProjectListResponse {
  projects: Project[]
  total: number
  skip: number
  limit: number
}

async function getAuthToken(): Promise<string> {
  const session = await supabase.auth.getSession()
  const token = session.data.session?.access_token
  if (!token) {
    throw new Error('Not authenticated')
  }
  return token
}

export async function createProject(data: CreateProjectData): Promise<Project> {
  const token = await getAuthToken()
  
  const response = await fetch(`${API_BASE_URL}/api/projects/`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(data)
  })

  if (!response.ok) {
    const errorData = await response.json()
    throw new Error(errorData.detail || 'Failed to create project')
  }

  return response.json()
}

export async function listProjects(skip = 0, limit = 20, search?: string, activeOnly = true): Promise<ProjectListResponse> {
  const token = await getAuthToken()
  
  const params = new URLSearchParams({
    skip: skip.toString(),
    limit: limit.toString(),
    active_only: activeOnly.toString()
  })
  
  if (search) {
    params.append('search', search)
  }
  
  const response = await fetch(`${API_BASE_URL}/api/projects/?${params}`, {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${token}`
    }
  })

  if (!response.ok) {
    const errorData = await response.json()
    throw new Error(errorData.detail || 'Failed to list projects')
  }

  return response.json()
}

export async function getProject(projectId: string): Promise<Project> {
  const token = await getAuthToken()
  
  const response = await fetch(`${API_BASE_URL}/api/projects/${projectId}`, {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${token}`
    }
  })

  if (!response.ok) {
    const errorData = await response.json()
    throw new Error(errorData.detail || 'Failed to get project')
  }

  return response.json()
}

export async function updateProject(projectId: string, data: UpdateProjectData): Promise<Project> {
  const token = await getAuthToken()
  
  const response = await fetch(`${API_BASE_URL}/api/projects/${projectId}`, {
    method: 'PATCH',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(data)
  })

  if (!response.ok) {
    const errorData = await response.json()
    throw new Error(errorData.detail || 'Failed to update project')
  }

  return response.json()
}

export async function deleteProject(projectId: string, hardDelete = false): Promise<void> {
  const token = await getAuthToken()
  
  const params = new URLSearchParams({
    hard_delete: hardDelete.toString()
  })
  
  const response = await fetch(`${API_BASE_URL}/api/projects/${projectId}?${params}`, {
    method: 'DELETE',
    headers: {
      'Authorization': `Bearer ${token}`
    }
  })

  if (!response.ok) {
    const errorData = await response.json()
    throw new Error(errorData.detail || 'Failed to delete project')
  }
}