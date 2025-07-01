// Dynamic import approach for Supabase with headers patching
import type { SupabaseClient } from '@supabase/supabase-js'
import type { Database } from '../types/database'
import { runtimeConfig } from '../generated/config'

let supabaseModule: any = null;
let clientInstance: SupabaseClient<Database> | null = null;

// Patch global headers before loading Supabase
function patchHeaders() {
  // Save original Headers if exists
  const OriginalHeaders = typeof Headers !== 'undefined' ? Headers : null;
  
  // Create a patched Headers constructor
  const PatchedHeaders = function(init?: HeadersInit) {
    if (OriginalHeaders) {
      return new OriginalHeaders(init || {});
    }
    // Fallback implementation
    const headers: any = {};
    return {
      append: (key: string, value: string) => { headers[key] = value; },
      delete: (key: string) => { delete headers[key]; },
      get: (key: string) => headers[key] || null,
      has: (key: string) => key in headers,
      set: (key: string, value: string) => { headers[key] = value; },
      forEach: (callback: Function) => {
        Object.entries(headers).forEach(([k, v]) => callback(v, k));
      },
      entries: () => Object.entries(headers),
      keys: () => Object.keys(headers),
      values: () => Object.values(headers),
    };
  } as any;
  
  // Copy static methods if they exist
  if (OriginalHeaders) {
    Object.setPrototypeOf(PatchedHeaders, OriginalHeaders);
    Object.setPrototypeOf(PatchedHeaders.prototype, OriginalHeaders.prototype);
  }
  
  // Patch all global locations
  try {
    (globalThis as any).Headers = PatchedHeaders;
    (window as any).Headers = PatchedHeaders;
    (window as any).global = window;
    (window as any).global.Headers = PatchedHeaders;
  } catch (e) {
    console.warn('Failed to patch some globals:', e);
  }
}

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
    // Patch headers before importing
    patchHeaders();
    
    // Dynamic import to avoid bundling issues
    if (!supabaseModule) {
      supabaseModule = await import('@supabase/supabase-js');
    }

    const { createClient } = supabaseModule;

    // Create client with minimal options
    clientInstance = createClient(supabaseUrl, supabaseAnonKey, {
      auth: {
        persistSession: true,
        storage: window.localStorage,
      }
    }) as SupabaseClient<Database>;

    if (!clientInstance) {
      throw new Error('Failed to create Supabase client instance');
    }

    console.log('Supabase client created successfully (dynamic import with patched headers)');
    return clientInstance;
  } catch (error: any) {
    console.error('Failed to create Supabase client with dynamic import:', error);
    console.error('Error details:', {
      message: error.message,
      stack: error.stack,
      headers: typeof Headers,
      globalHeaders: typeof (globalThis as any).Headers,
      windowHeaders: typeof (window as any).Headers,
    });
    throw error;
  }
}

// Create a promise-based wrapper for the client
export const supabasePromise = getSupabaseClient();