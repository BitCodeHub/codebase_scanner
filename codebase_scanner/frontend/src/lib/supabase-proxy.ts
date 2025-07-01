// Proxy wrapper for Supabase that uses the safe client
import { getSupabase } from './supabase-safe'
import type { Database } from '../types/database'

// Create a proxy that forwards all calls to the safe client
export const supabase = new Proxy({} as any, {
  get(target, prop: string) {
    // For methods that need the client immediately
    if (prop === 'auth' || prop === 'from' || prop === 'storage' || prop === 'channel') {
      return new Proxy({} as any, {
        get(subTarget, subProp: string) {
          return async (...args: any[]) => {
            const client = await getSupabase();
            const service = (client as any)[prop];
            if (prop === 'from' && typeof service === 'function') {
              // Special handling for from() which returns a query builder
              const queryBuilder = service.apply(client, args);
              return queryBuilder[subProp]?.bind(queryBuilder);
            }
            const method = service[subProp];
            if (typeof method === 'function') {
              return method.apply(service, args);
            }
            return method;
          };
        },
        apply(target, thisArg, args) {
          return (async () => {
            const client = await getSupabase();
            const method = (client as any)[prop];
            return method.apply(client, args);
          })();
        }
      });
    }
    
    // Default: return async function
    return async (...args: any[]) => {
      const client = await getSupabase();
      const value = (client as any)[prop];
      if (typeof value === 'function') {
        return value.apply(client, args);
      }
      return value;
    };
  }
});

// Export auth helpers
export const auth = {
  signUp: async (email: string, password: string, metadata?: object) => {
    const client = await getSupabase();
    return client.auth.signUp({
      email,
      password,
      options: metadata ? { data: metadata } : undefined
    });
  },

  signIn: async (email: string, password: string) => {
    const client = await getSupabase();
    return client.auth.signInWithPassword({ email, password });
  },

  signInWithGithub: async () => {
    const client = await getSupabase();
    return client.auth.signInWithOAuth({
      provider: 'github',
      options: {
        redirectTo: `${window.location.origin}/auth/callback`
      }
    });
  },

  signOut: async () => {
    const client = await getSupabase();
    return client.auth.signOut();
  },

  getSession: async () => {
    const client = await getSupabase();
    return client.auth.getSession();
  },

  getUser: async () => {
    const client = await getSupabase();
    return client.auth.getUser();
  }
};

// Export database helpers
export const db = {
  projects: {
    list: async () => {
      const client = await getSupabase();
      return client.from('projects').select('*').order('created_at', { ascending: false });
    },
    get: async (id: number) => {
      const client = await getSupabase();
      return client.from('projects').select('*').eq('id', id).single();
    },
    create: async (project: any) => {
      const client = await getSupabase();
      return client.from('projects').insert(project).select().single();
    },
    update: async (id: number, updates: any) => {
      const client = await getSupabase();
      return client.from('projects').update(updates).eq('id', id).select().single();
    },
    delete: async (id: number) => {
      const client = await getSupabase();
      return client.from('projects').delete().eq('id', id);
    }
  },
  
  scans: {
    list: async (projectId?: number) => {
      const client = await getSupabase();
      let query = client.from('scans').select('*').order('created_at', { ascending: false });
      if (projectId) {
        query = query.eq('project_id', projectId);
      }
      return query;
    },
    get: async (id: number) => {
      const client = await getSupabase();
      return client.from('scans').select('*').eq('id', id).single();
    },
    create: async (scan: any) => {
      const client = await getSupabase();
      return client.from('scans').insert(scan).select().single();
    },
    update: async (id: number, updates: any) => {
      const client = await getSupabase();
      return client.from('scans').update(updates).eq('id', id).select().single();
    }
  }
};

export default supabase;