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

  // Temporarily disable Supabase initialization due to bundling issue
  // The production build has an issue with the headers property access
  console.warn('Supabase client initialization is temporarily disabled due to bundling issues.');
  console.warn('Using mock client for all operations.');
  return null;
  
  // Original initialization code commented out for reference
  /*
  try {
    const client = createClient(url, key);
    console.log('Supabase client created successfully');
    return client;
  } catch (error) {
    console.error('Failed to create Supabase client:', error);
    return null;
  }
  */
}

// Create mock implementations with local storage
const MOCK_USER_KEY = 'mock_supabase_user';
const MOCK_SESSION_KEY = 'mock_supabase_session';

function getMockUser() {
  try {
    const stored = localStorage.getItem(MOCK_USER_KEY);
    return stored ? JSON.parse(stored) : null;
  } catch {
    return null;
  }
}

function setMockUser(user: any) {
  try {
    if (user) {
      localStorage.setItem(MOCK_USER_KEY, JSON.stringify(user));
      localStorage.setItem(MOCK_SESSION_KEY, JSON.stringify({ user, access_token: 'mock_token' }));
    } else {
      localStorage.removeItem(MOCK_USER_KEY);
      localStorage.removeItem(MOCK_SESSION_KEY);
    }
  } catch {
    // Ignore storage errors
  }
}

function getMockTableData(table: string): any[] {
  try {
    const stored = localStorage.getItem(`mock_table_${table}`);
    return stored ? JSON.parse(stored) : [];
  } catch {
    return [];
  }
}

function setMockTableData(table: string, data: any[]) {
  try {
    localStorage.setItem(`mock_table_${table}`, JSON.stringify(data));
  } catch {
    // Ignore storage errors
  }
}

export const mockSupabase = {
  auth: {
    signUp: async ({ email, password }: { email: string; password: string }) => {
      console.log('Mock signUp:', email);
      const user = { id: 'mock_' + Date.now(), email, app_metadata: {}, user_metadata: {} };
      setMockUser(user);
      return { data: { user, session: { user, access_token: 'mock_token' } }, error: null };
    },
    signInWithPassword: async ({ email, password }: { email: string; password: string }) => {
      console.log('Mock signIn:', email);
      const user = { id: 'mock_' + Date.now(), email, app_metadata: {}, user_metadata: {} };
      setMockUser(user);
      return { data: { user, session: { user, access_token: 'mock_token' } }, error: null };
    },
    signInWithOAuth: async () => ({ data: null, error: new Error('OAuth not available in mock mode') }),
    signOut: async () => {
      console.log('Mock signOut');
      setMockUser(null);
      return { error: null };
    },
    getSession: async () => {
      const user = getMockUser();
      const session = user ? { user, access_token: 'mock_token' } : null;
      return { data: { session }, error: null };
    },
    getUser: async () => {
      const user = getMockUser();
      return { data: { user }, error: null };
    },
    onAuthStateChange: (callback: (event: string, session: any) => void) => {
      // Call immediately with current state
      const user = getMockUser();
      const session = user ? { user, access_token: 'mock_token' } : null;
      setTimeout(() => callback('INITIAL_SESSION', session), 0);
      
      return { 
        data: { 
          subscription: { 
            unsubscribe: () => {
              console.log('Mock auth state change unsubscribed');
            } 
          } 
        } 
      };
    }
  },
  from: (table: string) => {
    console.log('Mock from table:', table);
    const mockData = getMockTableData(table);
    let result = [...mockData];
    let singleMode = false;
    
    const builder: any = {
      select: (columns?: string) => {
        console.log('Mock select:', columns);
        return builder;
      },
      insert: (data: any) => {
        console.log('Mock insert:', data);
        const newData = Array.isArray(data) ? data : [data];
        newData.forEach((item: any) => {
          item.id = item.id || 'mock_' + Date.now() + '_' + Math.random();
          item.created_at = item.created_at || new Date().toISOString();
          mockData.push(item);
        });
        setMockTableData(table, mockData);
        result = newData;
        return builder;
      },
      update: (data: any) => {
        console.log('Mock update:', data);
        // In a real implementation, this would update matching records
        return builder;
      },
      upsert: (data: any) => {
        console.log('Mock upsert:', data);
        return builder.insert(data);
      },
      delete: () => {
        console.log('Mock delete');
        // In a real implementation, this would delete matching records
        return builder;
      },
      eq: (column: string, value: any) => {
        console.log('Mock eq:', column, value);
        result = result.filter((item: any) => item[column] === value);
        return builder;
      },
      neq: () => builder,
      gt: () => builder,
      lt: () => builder,
      gte: () => builder,
      lte: () => builder,
      like: () => builder,
      ilike: () => builder,
      is: () => builder,
      in: () => builder,
      order: (column: string, options?: { ascending?: boolean }) => {
        console.log('Mock order:', column, options);
        return builder;
      },
      limit: (count: number) => {
        console.log('Mock limit:', count);
        result = result.slice(0, count);
        return builder;
      },
      range: (start: number, end: number) => {
        result = result.slice(start, end + 1);
        return builder;
      },
      single: () => {
        singleMode = true;
        return builder;
      },
      maybeSingle: () => {
        singleMode = true;
        return builder;
      },
      then: (resolve: any) => {
        const response = singleMode 
          ? { data: result[0] || null, error: null }
          : { data: result, error: null, count: result.length };
        return resolve(response);
      },
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