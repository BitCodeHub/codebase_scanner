// Separate file for Supabase client initialization
import { createClient } from '@supabase/supabase-js'
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
    console.error('Supabase credentials missing or empty');
    throw new Error('Supabase configuration is missing. Please check environment variables.');
  }

  try {
    // Create client with proper configuration
    const client = createClient<Database>(finalUrl, finalKey, {
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
    
    console.log('Supabase client created successfully');
    return client;
  } catch (error) {
    console.error('Failed to create Supabase client:', error);
    throw error;
  }
}