import { createClient as originalCreateClient } from '@supabase/supabase-js'
import type { SupabaseClient } from '@supabase/supabase-js'
import type { Database } from '../types/database'

// Wrapper around createClient to handle initialization issues
export function createClient<T = Database>(url: string, key: string, options?: any): SupabaseClient<T> {
  // Ensure all globals are available
  const requiredGlobals = {
    Headers: globalThis.Headers || (window as any).Headers,
    fetch: globalThis.fetch || (window as any).fetch,
    Request: globalThis.Request || (window as any).Request,
    Response: globalThis.Response || (window as any).Response,
  };

  // Check if any required globals are missing
  const missingGlobals = Object.entries(requiredGlobals)
    .filter(([_, value]) => !value)
    .map(([key]) => key);

  if (missingGlobals.length > 0) {
    console.error('Missing required globals:', missingGlobals);
  }

  // Patch global if needed
  if (!globalThis.Headers && requiredGlobals.Headers) {
    (globalThis as any).Headers = requiredGlobals.Headers;
  }
  if (!globalThis.fetch && requiredGlobals.fetch) {
    (globalThis as any).fetch = requiredGlobals.fetch;
  }

  console.log('Creating Supabase client with patched globals');
  
  try {
    // Try creating with provided options
    if (options) {
      return originalCreateClient<T>(url, key, options);
    }
    // Try without options
    return originalCreateClient<T>(url, key);
  } catch (error: any) {
    console.error('Failed to create Supabase client:', error);
    
    // Log more details about the error
    if (error.message?.includes('headers')) {
      console.error('Headers-related error. Checking environment...');
      console.log('globalThis:', globalThis);
      console.log('globalThis.Headers:', (globalThis as any).Headers);
      console.log('window.Headers:', (window as any).Headers);
    }
    
    throw error;
  }
}