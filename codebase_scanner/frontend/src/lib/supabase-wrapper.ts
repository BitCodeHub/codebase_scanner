// Wrapper that provides a synchronous-looking interface with dynamic loading
import type { SupabaseClient } from '@supabase/supabase-js'
import type { Database } from '../types/database'
import { getSupabaseClient } from './supabase-dynamic'

let clientPromise: Promise<SupabaseClient<Database>> | null = null;
let resolvedClient: SupabaseClient<Database> | null = null;

// Initialize the client in the background
function initClient() {
  if (!clientPromise) {
    clientPromise = getSupabaseClient().then(client => {
      resolvedClient = client;
      console.log('Supabase client resolved and cached');
      return client;
    }).catch(error => {
      console.error('Failed to initialize Supabase client:', error);
      clientPromise = null; // Reset to allow retry
      throw error;
    });
  }
  return clientPromise;
}

// Start initialization immediately
initClient();

// Create a wrapper that handles both sync and async access patterns
export function createSupabaseWrapper() {
  const handler: ProxyHandler<any> = {
    get(target, prop: string) {
      // If client is already resolved, use it directly
      if (resolvedClient) {
        const value = resolvedClient[prop as keyof typeof resolvedClient];
        if (typeof value === 'function') {
          return value.bind(resolvedClient);
        }
        return value;
      }

      // For properties that return objects (like auth, from, etc.)
      if (prop === 'auth' || prop === 'storage' || prop === 'functions' || prop === 'realtime') {
        return new Proxy({}, {
          get(_, subProp: string) {
            return async (...args: any[]) => {
              const client = await initClient();
              const service = client[prop as keyof typeof client];
              const method = (service as any)[subProp];
              if (typeof method === 'function') {
                return method.apply(service, args);
              }
              return method;
            };
          }
        });
      }

      // For from() method
      if (prop === 'from') {
        return (table: string) => {
          return new Proxy({}, {
            get(_, method: string) {
              return async (...args: any[]) => {
                const client = await initClient();
                const query = client.from(table);
                const queryMethod = (query as any)[method];
                if (typeof queryMethod === 'function') {
                  return queryMethod.apply(query, args);
                }
                return queryMethod;
              };
            }
          });
        };
      }

      // For channel() method
      if (prop === 'channel') {
        return async (name: string) => {
          const client = await initClient();
          return client.channel(name);
        };
      }

      // Default: return an async function
      return async (...args: any[]) => {
        const client = await initClient();
        const method = client[prop as keyof typeof client];
        if (typeof method === 'function') {
          return (method as any).apply(client, args);
        }
        return method;
      };
    }
  };

  return new Proxy({}, handler);
}

// Export the wrapped client
export const supabaseWrapper = createSupabaseWrapper();