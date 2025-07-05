// API Configuration utility
// This ensures the correct API URL is used regardless of how the config was generated

import { runtimeConfig } from '../generated/config'

export function getApiUrl(): string {
  // Priority order for API URL:
  // 1. Runtime config if properly set
  // 2. Environment variable from Vite
  // 3. Check if we're on Render (production)
  // 4. Fallback to production URL
  
  let selectedUrl = '';
  let source = '';
  
  // If runtime config has a valid non-localhost URL, use it
  if (runtimeConfig.apiUrl && !runtimeConfig.apiUrl.includes('localhost')) {
    selectedUrl = runtimeConfig.apiUrl;
    source = 'runtime config';
  }
  // Check Vite environment variable
  else if (import.meta.env.VITE_API_URL && !import.meta.env.VITE_API_URL.includes('localhost')) {
    selectedUrl = import.meta.env.VITE_API_URL;
    source = 'VITE_API_URL env';
  }
  // If we're in production (on Render), use the production URL
  else if (window.location.hostname.includes('onrender.com') || 
           window.location.hostname !== 'localhost') {
    // Use the Docker backend service URL (confirmed working)
    selectedUrl = 'https://codebase-scanner-backend-docker.onrender.com';
    source = 'production default';
  }
  // Development fallback
  else {
    selectedUrl = 'http://localhost:8000';
    source = 'development fallback';
  }
  
  console.log(`[API Config] Using backend URL: ${selectedUrl} (source: ${source})`);
  return selectedUrl;
}

export function getFullApiUrl(endpoint: string): string {
  const baseUrl = getApiUrl()
  const cleanEndpoint = endpoint.startsWith('/') ? endpoint : `/${endpoint}`
  return `${baseUrl}${cleanEndpoint}`
}