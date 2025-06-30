import { createClient } from '@supabase/supabase-js'
import type { Database } from '../types/database'

const supabaseUrl = import.meta.env.VITE_SUPABASE_URL || 'https://placeholder.supabase.co'
const supabaseAnonKey = import.meta.env.VITE_SUPABASE_ANON_KEY || 'placeholder-key'

// Only throw error in production if variables are missing
if (import.meta.env.PROD && (!import.meta.env.VITE_SUPABASE_URL || !import.meta.env.VITE_SUPABASE_ANON_KEY)) {
  console.error('Missing Supabase environment variables in production')
}

export const supabase = createClient<Database>(supabaseUrl, supabaseAnonKey, {
  auth: {
    autoRefreshToken: true,
    persistSession: true,
    detectSessionInUrl: true
  }
})

// Auth helpers
export const auth = {
  signUp: async (email: string, password: string, metadata?: object) => {
    return supabase.auth.signUp({
      email,
      password,
      options: {
        data: metadata
      }
    })
  },

  signIn: async (email: string, password: string) => {
    return supabase.auth.signInWithPassword({
      email,
      password
    })
  },

  signInWithGithub: async () => {
    return supabase.auth.signInWithOAuth({
      provider: 'github',
      options: {
        redirectTo: `${window.location.origin}/auth/callback`
      }
    })
  },

  signOut: async () => {
    return supabase.auth.signOut()
  },

  getSession: async () => {
    return supabase.auth.getSession()
  },

  getUser: async () => {
    return supabase.auth.getUser()
  },

  onAuthStateChange: (callback: (event: string, session: any) => void) => {
    return supabase.auth.onAuthStateChange(callback)
  }
}

// Database helpers
export const db = {
  // Projects
  projects: {
    list: () => supabase.from('projects').select('*').order('created_at', { ascending: false }),
    
    get: (id: number) => supabase.from('projects').select('*').eq('id', id).single(),
    
    create: (project: Omit<Database['public']['Tables']['projects']['Insert'], 'id' | 'created_at' | 'updated_at'>) =>
      supabase.from('projects').insert(project).select().single(),
    
    update: (id: number, updates: Database['public']['Tables']['projects']['Update']) =>
      supabase.from('projects').update(updates).eq('id', id).select().single(),
    
    delete: (id: number) => supabase.from('projects').delete().eq('id', id)
  },

  // Scans
  scans: {
    list: (projectId?: number) => {
      let query = supabase.from('scans').select('*').order('created_at', { ascending: false })
      if (projectId) {
        query = query.eq('project_id', projectId)
      }
      return query
    },
    
    get: (id: number) => supabase.from('scans').select('*').eq('id', id).single(),
    
    create: (scan: Omit<Database['public']['Tables']['scans']['Insert'], 'id' | 'created_at'>) =>
      supabase.from('scans').insert(scan).select().single(),
    
    update: (id: number, updates: Database['public']['Tables']['scans']['Update']) =>
      supabase.from('scans').update(updates).eq('id', id).select().single(),
    
    subscribe: (callback: (payload: any) => void) =>
      supabase.channel('scans')
        .on('postgres_changes', { event: '*', schema: 'public', table: 'scans' }, callback)
        .subscribe()
  },

  // Scan Results
  scanResults: {
    list: (scanId: number, filters?: { severity?: string; category?: string }) => {
      let query = supabase.from('scan_results').select('*').eq('scan_id', scanId)
      
      if (filters?.severity) {
        query = query.eq('severity', filters.severity)
      }
      if (filters?.category) {
        query = query.eq('category', filters.category)
      }
      
      return query.order('fix_priority', { ascending: true })
    },
    
    get: (id: number) => supabase.from('scan_results').select('*').eq('id', id).single(),
    
    markFalsePositive: (id: number, isFalsePositive: boolean) =>
      supabase.from('scan_results').update({ false_positive: isFalsePositive }).eq('id', id)
  },

  // Reports
  reports: {
    list: (projectId?: number) => {
      let query = supabase.from('reports').select('*').order('created_at', { ascending: false })
      if (projectId) {
        query = query.eq('project_id', projectId)
      }
      return query
    },
    
    get: (id: number) => supabase.from('reports').select('*').eq('id', id).single(),
    
    create: (report: Omit<Database['public']['Tables']['reports']['Insert'], 'id' | 'created_at'>) =>
      supabase.from('reports').insert(report).select().single()
  },

  // User Profiles
  userProfiles: {
    get: (userId: string) => supabase.from('user_profiles').select('*').eq('id', userId).single(),
    
    upsert: (profile: Database['public']['Tables']['user_profiles']['Insert'] | Database['public']['Tables']['user_profiles']['Update']) =>
      supabase.from('user_profiles').upsert(profile).select().single()
  }
}

// Storage helpers
export const storage = {
  uploadProjectFile: async (userId: string, projectId: number, file: File) => {
    const fileName = `${Date.now()}-${file.name}`
    const filePath = `${userId}/${projectId}/${fileName}`
    
    return supabase.storage
      .from('project-files')
      .upload(filePath, file)
  },

  downloadProjectFile: (filePath: string) => {
    return supabase.storage
      .from('project-files')
      .download(filePath)
  },

  getProjectFileUrl: (filePath: string) => {
    return supabase.storage
      .from('project-files')
      .getPublicUrl(filePath)
  },

  uploadReport: async (userId: string, reportId: number, file: Blob, fileName: string) => {
    const filePath = `${userId}/${reportId}/${fileName}`
    
    return supabase.storage
      .from('scan-reports')
      .upload(filePath, file)
  },

  downloadReport: (filePath: string) => {
    return supabase.storage
      .from('scan-reports')
      .download(filePath)
  }
}

export default supabase