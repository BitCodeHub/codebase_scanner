// Supabase initialization with proper error handling and auth state management
import type { SupabaseClient, Session } from '@supabase/supabase-js'
import type { Database } from '../types/database'

// Global state for Supabase client
let supabaseClient: SupabaseClient<Database> | null = null;
let initPromise: Promise<SupabaseClient<Database>> | null = null;
let initError: Error | null = null;

// Initialize Supabase with retries and error handling
async function initializeSupabase(): Promise<SupabaseClient<Database>> {
  if (supabaseClient) return supabaseClient;
  if (initError) throw initError;
  
  if (!initPromise) {
    initPromise = (async () => {
      try {
        // Use the dynamic loader with headers patching
        const { getSupabaseClient } = await import('./supabase-dynamic');
        supabaseClient = await getSupabaseClient();
        
        console.log('Supabase client initialized successfully');
        return supabaseClient;
      } catch (error) {
        console.error('Failed to initialize Supabase:', error);
        initError = error as Error;
        throw error;
      }
    })();
  }
  
  return initPromise;
}

// Auth state management
interface AuthState {
  session: Session | null;
  loading: boolean;
  error: Error | null;
}

const authStateListeners = new Set<(state: AuthState) => void>();
let currentAuthState: AuthState = { session: null, loading: true, error: null };
let authSubscription: any = null;

// Subscribe to auth state changes
export function subscribeToAuthState(callback: (state: AuthState) => void) {
  authStateListeners.add(callback);
  // Immediately call with current state
  callback(currentAuthState);
  
  // Initialize auth state if not already done
  if (currentAuthState.loading && !authSubscription) {
    initializeAuthState();
  }
  
  // Return unsubscribe function
  return () => {
    authStateListeners.delete(callback);
  };
}

// Initialize auth state and subscriptions
async function initializeAuthState() {
  try {
    const client = await initializeSupabase();
    
    // Get initial session
    const { data: { session }, error } = await client.auth.getSession();
    if (error) throw error;
    
    updateAuthState({ session, loading: false, error: null });
    
    // Subscribe to auth changes
    const { data: { subscription } } = client.auth.onAuthStateChange((event, session) => {
      updateAuthState({ session, loading: false, error: null });
    });
    
    authSubscription = subscription;
  } catch (error) {
    console.error('Failed to initialize auth state:', error);
    updateAuthState({ session: null, loading: false, error: error as Error });
  }
}

// Update auth state and notify listeners
function updateAuthState(state: AuthState) {
  currentAuthState = state;
  authStateListeners.forEach(callback => callback(state));
}

// Export async client getter
export async function getSupabase() {
  return initializeSupabase();
}

// Export the current auth state
export function getCurrentAuthState() {
  return currentAuthState;
}