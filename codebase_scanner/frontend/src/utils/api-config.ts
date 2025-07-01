// API Configuration utility
// This ensures the correct API URL is used regardless of how the config was generated

import { runtimeConfig } from '../generated/config'

export function getApiUrl(): string {
  // Priority order for API URL:
  // 1. Runtime config if properly set
  // 2. Environment variable from Vite
  // 3. Check if we're on Render (production)
  // 4. Fallback to production URL
  
  // If runtime config has a valid non-localhost URL, use it
  if (runtimeConfig.apiUrl && !runtimeConfig.apiUrl.includes('localhost')) {
    return runtimeConfig.apiUrl
  }
  
  // Check Vite environment variable
  const viteApiUrl = import.meta.env.VITE_API_URL
  if (viteApiUrl && !viteApiUrl.includes('localhost')) {
    return viteApiUrl
  }
  
  // If we're in production (on Render), use the production URL
  if (window.location.hostname.includes('onrender.com') || 
      window.location.hostname !== 'localhost') {
    return 'https://codebase-scanner-backend.onrender.com'
  }
  
  // Development fallback
  return 'http://localhost:8001'
}

export function getFullApiUrl(endpoint: string): string {
  const baseUrl = getApiUrl()
  const cleanEndpoint = endpoint.startsWith('/') ? endpoint : `/${endpoint}`
  return `${baseUrl}${cleanEndpoint}`
}