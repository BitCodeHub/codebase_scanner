// Diagnostic file to debug Supabase initialization
import { runtimeConfig } from '../generated/config'

export async function runSupabaseDiagnostics() {
  console.group('🔍 Supabase Diagnostics');
  
  // 1. Check runtime config
  console.log('1. Runtime Config:', {
    full: runtimeConfig,
    url: runtimeConfig.supabaseUrl,
    key: runtimeConfig.supabaseAnonKey,
    urlType: typeof runtimeConfig.supabaseUrl,
    keyType: typeof runtimeConfig.supabaseAnonKey,
    urlLength: runtimeConfig.supabaseUrl?.length,
    keyLength: runtimeConfig.supabaseAnonKey?.length
  });
  
  // 2. Check environment variables
  console.log('2. Environment Variables:', {
    VITE_SUPABASE_URL: import.meta.env.VITE_SUPABASE_URL,
    VITE_SUPABASE_ANON_KEY: import.meta.env.VITE_SUPABASE_ANON_KEY,
    urlType: typeof import.meta.env.VITE_SUPABASE_URL,
    keyType: typeof import.meta.env.VITE_SUPABASE_ANON_KEY,
    allViteVars: Object.keys(import.meta.env).filter(k => k.startsWith('VITE_'))
  });
  
  // 3. Test values
  const testUrl = runtimeConfig.supabaseUrl || import.meta.env.VITE_SUPABASE_URL;
  const testKey = runtimeConfig.supabaseAnonKey || import.meta.env.VITE_SUPABASE_ANON_KEY;
  
  console.log('3. Test Values:', {
    testUrl,
    testKey: testKey ? `${testKey.substring(0, 20)}...` : 'MISSING',
    isValidUrl: testUrl && testUrl.includes('supabase.co'),
    isValidKey: testKey && testKey.startsWith('eyJ')
  });
  
  // 4. Try minimal Supabase client creation
  console.log('4. Testing Supabase client creation...');
  
  if (!testUrl || !testKey) {
    console.error('❌ Cannot test - missing credentials');
    console.groupEnd();
    return false;
  }
  
  try {
    // Import using ES modules syntax, not require
    const { createClient } = await import('@supabase/supabase-js');
    console.log('✅ createClient function found');
    
    // Try creating with minimal options
    console.log('Creating client with URL:', testUrl.substring(0, 40) + '...');
    const client = createClient(testUrl, testKey);
    console.log('✅ Client created successfully!', client);
    
    console.groupEnd();
    return true;
  } catch (error: any) {
    console.error('❌ Client creation failed:', error);
    console.error('Error stack:', error.stack);
    console.error('Error details:', {
      message: error.message,
      name: error.name,
      ...error
    });
    console.groupEnd();
    return false;
  }
}

// Also export a function to test with hardcoded values
export async function testHardcodedSupabase() {
  console.group('🧪 Testing with hardcoded values');
  
  try {
    const { createClient } = await import('@supabase/supabase-js');
    
    // These are test values - not real
    const testUrl = 'https://xyzxyzxyz.supabase.co';
    const testKey = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.test';
    
    console.log('Creating client with test values...');
    const client = createClient(testUrl, testKey);
    console.log('✅ Test client created successfully!');
    console.groupEnd();
    return true;
  } catch (error: any) {
    console.error('❌ Even test values failed:', error.message);
    console.groupEnd();
    return false;
  }
}