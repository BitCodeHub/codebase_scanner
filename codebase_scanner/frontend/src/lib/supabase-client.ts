// Separate file for Supabase client initialization
import { createClient } from './supabase-wrapper'
import type { Database } from '../types/database'
import { runtimeConfig } from '../generated/config'

// Use generated config which has build-time environment variables
const supabaseUrl = runtimeConfig.supabaseUrl || import.meta.env.VITE_SUPABASE_URL || ''
const supabaseAnonKey = runtimeConfig.supabaseAnonKey || import.meta.env.VITE_SUPABASE_ANON_KEY || ''

// Filter out empty strings
const finalUrl = supabaseUrl?.trim() || ''
const finalKey = supabaseAnonKey?.trim() || ''

// Initialize client
export function initializeSupabase() {
  console.log('Initializing Supabase with:', {
    url: finalUrl?.substring(0, 30) + '...',
    keyLength: finalKey?.length,
    hasUrl: !!finalUrl,
    hasKey: !!finalKey
  });

  if (!finalUrl || !finalKey || finalUrl === '' || finalKey === '') {
    console.warn('Supabase credentials missing or empty, using mock client');
    return null;
  }

  try {
    // Use the already filtered values
    const url = finalUrl;
    const key = finalKey;
    
    console.log('Creating Supabase client with:', {
      url: url.substring(0, 40) + '...',
      keyLength: key.length,
      urlValid: url.startsWith('http'),
      keyValid: key.startsWith('eyJ')
    });
    
    // Create client with absolutely minimal setup
    try {
      const client = createClient(url, key);
      console.log('Supabase client created successfully');
      return client;
    } catch (innerError) {
      console.error('Inner error creating client:', innerError);
      // Try with empty options object
      const client = createClient(url, key, {});
      console.log('Supabase client created with empty options');
      return client;
    }
  } catch (error) {
    console.error('Failed to create Supabase client:', error);
    return null;
  }
}

// Create mock implementations
export const mockSupabase = {
  auth: {
    signUp: async () => ({ data: null, error: new Error('Supabase not configured') }),
    signInWithPassword: async () => ({ data: null, error: new Error('Supabase not configured') }),
    signInWithOAuth: async () => ({ data: null, error: new Error('Supabase not configured') }),
    signOut: async () => ({ error: null }),
    getSession: async () => ({ data: { session: null }, error: null }),
    getUser: async () => ({ data: { user: null }, error: null }),
    onAuthStateChange: () => ({ data: { subscription: { unsubscribe: () => {} } } })
  },
  from: () => {
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
  },
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
};