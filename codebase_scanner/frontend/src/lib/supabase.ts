import { createClient } from '@supabase/supabase-js'
import type { Database } from '../types/database'

const supabaseUrl = import.meta.env.VITE_SUPABASE_URL || 'https://placeholder.supabase.co'
const supabaseAnonKey = import.meta.env.VITE_SUPABASE_ANON_KEY || 'placeholder-key'

// Only throw error in production if variables are missing
if (import.meta.env.PROD && (!import.meta.env.VITE_SUPABASE_URL || !import.meta.env.VITE_SUPABASE_ANON_KEY)) {
  console.error('Missing Supabase environment variables in production')
}

// Log configuration status
console.log('Supabase Configuration:', {
  url: supabaseUrl ? 'Set' : 'Missing',
  key: supabaseAnonKey ? 'Set' : 'Missing',
  urlValue: supabaseUrl?.substring(0, 30) + '...',
  keyValue: supabaseAnonKey?.substring(0, 20) + '...',
  isProd: import.meta.env.PROD,
  mode: import.meta.env.MODE
})

// Create a mock query builder that returns proper chainable methods
const createMockQueryBuilder = () => {
  const mockResult = { data: [], error: null, count: 0 };
  const builder: any = {
    select: () => builder,
    insert: () => builder,
    update: () => builder,
    upsert: () => builder,
    delete: () => builder,
    eq: () => builder,
    neq: () => builder,
    gt: () => builder,
    lt: () => builder,
    gte: () => builder,
    lte: () => builder,
    like: () => builder,
    ilike: () => builder,
    is: () => builder,
    in: () => builder,
    order: () => builder,
    limit: () => builder,
    range: () => builder,
    single: () => Promise.resolve({ data: null, error: null }),
    maybeSingle: () => Promise.resolve({ data: null, error: null }),
    then: (resolve: any) => resolve(mockResult),
    error: null
  };
  return builder;
};

// Create the Supabase client - always use real client when URL starts with https://
const shouldUseRealClient = supabaseUrl && supabaseAnonKey && supabaseUrl.startsWith('https://');

console.log('Using real Supabase client:', shouldUseRealClient);

// Initialize Supabase client with error handling
let supabaseClient: any;

if (shouldUseRealClient) {
  try {
    // Ensure values are strings
    const url = String(supabaseUrl);
    const key = String(supabaseAnonKey);
    
    console.log('Creating Supabase client with:', {
      url: url.substring(0, 30) + '...',
      keyLength: key.length,
      urlType: typeof url,
      keyType: typeof key
    });
    
    supabaseClient = createClient<Database>(url, key, {
      auth: {
        autoRefreshToken: true,
        persistSession: true,
        detectSessionInUrl: true
      }
    });
  } catch (error) {
    console.error('Failed to create Supabase client:', error);
    // Fall back to mock client
    supabaseClient = null;
  }
}

export const supabase = supabaseClient || {
  auth: {
    signUp: async () => ({ data: null, error: new Error('Supabase not configured') }),
    signInWithPassword: async () => ({ data: null, error: new Error('Supabase not configured') }),
    signInWithOAuth: async () => ({ data: null, error: new Error('Supabase not configured') }),
    signOut: async () => ({ error: null }),
    getSession: async () => ({ data: { session: null }, error: null }),
    getUser: async () => ({ data: { user: null }, error: null }),
    onAuthStateChange: () => ({ data: { subscription: { unsubscribe: () => {} } } })
  },
  from: () => createMockQueryBuilder(),
  channel: () => ({
    on: (type: string, filter: any, callback?: any) => ({
      subscribe: () => ({
        unsubscribe: () => {}
      })
    })
  }) as any,
  storage: {
    from: () => ({
      upload: async () => ({ data: null, error: new Error('Supabase not configured') }),
      download: async () => ({ data: null, error: new Error('Supabase not configured') }),
      getPublicUrl: () => ({ data: { publicUrl: '' } })
    })
  }
}

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
    
    subscribe: (callback: (payload: any) => void) => {
      const channel = supabase.channel('scans') as any;
      return channel
        .on('postgres_changes', { event: '*', schema: 'public', table: 'scans' }, callback)
        .subscribe()
    }
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