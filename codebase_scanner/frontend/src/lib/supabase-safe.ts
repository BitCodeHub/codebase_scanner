// Safe Supabase initialization that avoids the headers issue
import type { SupabaseClient, Session } from '@supabase/supabase-js'
import type { Database } from '../types/database'

// Global client instance
let client: SupabaseClient<Database> | null = null;
let initPromise: Promise<void> | null = null;

// Initialize Supabase in a safe way
async function initializeSupabase() {
  if (client) return;
  
  try {
    // Import config
    const { runtimeConfig } = await import('../generated/config');
    const url = runtimeConfig.supabaseUrl || import.meta.env.VITE_SUPABASE_URL;
    const key = runtimeConfig.supabaseAnonKey || import.meta.env.VITE_SUPABASE_ANON_KEY;
    
    if (!url || !key) {
      throw new Error('Supabase credentials missing');
    }

    // Wait for the global to be available (loaded from CDN in index.html)
    let attempts = 0;
    while (!(window as any).supabase && attempts < 100) {
      await new Promise(resolve => setTimeout(resolve, 50));
      attempts++;
    }

    if (!(window as any).supabase) {
      throw new Error('Supabase CDN failed to load');
    }

    // Create client using the global
    const { createClient } = (window as any).supabase;
    client = createClient(url, key, {
      auth: {
        persistSession: true,
        storage: window.localStorage,
        storageKey: 'supabase.auth.token',
      }
    }) as SupabaseClient<Database>;

    console.log('Supabase client initialized via CDN');
  } catch (error) {
    console.error('Failed to initialize Supabase:', error);
    throw error;
  }
}

// Ensure initialization happens
if (typeof window !== 'undefined' && !initPromise) {
  initPromise = initializeSupabase();
}

// Auth state management
interface AuthState {
  session: Session | null;
  loading: boolean;
  error: Error | null;
}

const listeners = new Set<(state: AuthState) => void>();
let currentState: AuthState = { session: null, loading: true, error: null };
let authSubscription: any = null;

export function subscribeToAuthState(callback: (state: AuthState) => void) {
  listeners.add(callback);
  callback(currentState);
  
  // Initialize auth state if needed
  if (!authSubscription && client) {
    initAuthSubscription();
  } else if (!client && initPromise) {
    initPromise.then(() => {
      if (client && !authSubscription) {
        initAuthSubscription();
      }
    });
  }
  
  return () => {
    listeners.delete(callback);
  };
}

async function initAuthSubscription() {
  if (!client || authSubscription) return;
  
  try {
    // Get initial session
    const { data: { session }, error } = await client.auth.getSession();
    if (error) throw error;
    
    updateState({ session, loading: false, error: null });
    
    // Subscribe to changes
    const { data: { subscription } } = client.auth.onAuthStateChange((event, session) => {
      updateState({ session, loading: false, error: null });
    });
    
    authSubscription = subscription;
  } catch (error) {
    console.error('Auth subscription error:', error);
    updateState({ session: null, loading: false, error: error as Error });
  }
}

function updateState(state: AuthState) {
  currentState = state;
  listeners.forEach(cb => cb(state));
}

// Export async getter
export async function getSupabase(): Promise<SupabaseClient<Database>> {
  if (client) return client;
  if (initPromise) await initPromise;
  if (!client) throw new Error('Supabase client not initialized');
  return client;
}