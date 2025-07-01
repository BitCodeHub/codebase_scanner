// Dynamic import approach for Supabase to avoid bundling issues
import type { SupabaseClient } from '@supabase/supabase-js'
import type { Database } from '../types/database'
import { runtimeConfig } from '../generated/config'

let supabaseModule: any = null;
let clientInstance: SupabaseClient<Database> | null = null;

export async function getSupabaseClient(): Promise<SupabaseClient<Database>> {
  if (clientInstance) {
    return clientInstance;
  }

  const supabaseUrl = runtimeConfig.supabaseUrl || import.meta.env.VITE_SUPABASE_URL || ''
  const supabaseAnonKey = runtimeConfig.supabaseAnonKey || import.meta.env.VITE_SUPABASE_ANON_KEY || ''

  if (!supabaseUrl || !supabaseAnonKey) {
    throw new Error('Supabase configuration is missing');
  }

  try {
    // Dynamic import to avoid bundling issues
    if (!supabaseModule) {
      supabaseModule = await import('@supabase/supabase-js');
    }

    const { createClient } = supabaseModule;

    clientInstance = createClient<Database>(supabaseUrl, supabaseAnonKey, {
      auth: {
        autoRefreshToken: true,
        persistSession: true,
        detectSessionInUrl: true,
        storage: window.localStorage,
        storageKey: 'supabase.auth.token',
        flowType: 'pkce',
      },
      global: {
        headers: { 'x-application-name': 'codebase-scanner' },
      },
      db: {
        schema: 'public',
      },
    });

    console.log('Supabase client created successfully (dynamic import)');
    return clientInstance;
  } catch (error) {
    console.error('Failed to create Supabase client with dynamic import:', error);
    throw error;
  }
}

// Create a promise-based wrapper for the client
export const supabasePromise = getSupabaseClient();