// Direct Supabase initialization without wrapper
// This is to test if the issue is with our wrapper or the Supabase client itself

// Force environment setup
if (typeof globalThis === 'undefined') {
  (window as any).globalThis = window;
}

// Import and export directly
export { createClient } from '@supabase/supabase-js';

// Test initialization function
export function testDirectInit() {
  console.log('Testing direct Supabase initialization...');
  
  // Log environment
  console.log('Environment check:', {
    globalThis: typeof globalThis,
    Headers: typeof Headers,
    fetch: typeof fetch,
    'window.Headers': typeof (window as any).Headers,
    'window.fetch': typeof (window as any).fetch,
  });
  
  try {
    // Dynamic import to ensure module is loaded
    import('@supabase/supabase-js').then(({ createClient }) => {
      console.log('Dynamic import successful');
      
      const testUrl = 'https://test.supabase.co';
      const testKey = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.test';
      
      try {
        // Most minimal possible initialization
        const client = createClient(testUrl, testKey);
        console.log('✅ Direct initialization successful!', client);
      } catch (e: any) {
        console.error('❌ Direct initialization failed:', e);
        console.error('Error object:', e);
        console.error('Error constructor:', e.constructor?.name);
        
        // Try to understand what's undefined
        if (e.message?.includes('Cannot read properties of undefined')) {
          console.error('Something is undefined. Checking common issues...');
          
          // Log the actual createClient function
          console.log('createClient function:', createClient);
          console.log('createClient length:', createClient.length);
          
          // Try to see the source
          try {
            console.log('createClient source:', createClient.toString());
          } catch {
            console.log('Cannot access createClient source');
          }
        }
      }
    }).catch(err => {
      console.error('Dynamic import failed:', err);
    });
  } catch (error) {
    console.error('Test failed:', error);
  }
}