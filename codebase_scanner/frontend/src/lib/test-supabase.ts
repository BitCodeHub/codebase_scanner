// Test file to debug Supabase initialization
export async function testSupabaseInit() {
  console.group('🧪 Testing Supabase initialization');
  
  try {
    // Test 1: Check if we can import the module
    console.log('Test 1: Importing Supabase module...');
    const supabaseModule = await import('@supabase/supabase-js');
    console.log('✅ Module imported:', Object.keys(supabaseModule));
    
    // Test 2: Check the createClient function
    console.log('Test 2: Checking createClient function...');
    const { createClient } = supabaseModule;
    console.log('createClient type:', typeof createClient);
    console.log('createClient toString:', createClient.toString().substring(0, 200) + '...');
    
    // Test 3: Try different initialization approaches
    console.log('Test 3: Testing initialization approaches...');
    
    const testUrl = 'https://test.supabase.co';
    const testKey = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.test';
    
    // Approach 1: Minimal
    try {
      console.log('Approach 1: Minimal initialization');
      const client1 = createClient(testUrl, testKey);
      console.log('✅ Minimal init succeeded');
    } catch (e: any) {
      console.error('❌ Minimal init failed:', e.message);
      console.error('Stack:', e.stack);
    }
    
    // Approach 2: With empty options
    try {
      console.log('Approach 2: With empty options');
      const client2 = createClient(testUrl, testKey, {});
      console.log('✅ Empty options init succeeded');
    } catch (e: any) {
      console.error('❌ Empty options init failed:', e.message);
    }
    
    // Approach 3: With minimal auth options
    try {
      console.log('Approach 3: With minimal auth options');
      const client3 = createClient(testUrl, testKey, {
        auth: {
          persistSession: false,
        }
      });
      console.log('✅ Minimal auth init succeeded');
    } catch (e: any) {
      console.error('❌ Minimal auth init failed:', e.message);
    }
    
    // Approach 4: With global options
    try {
      console.log('Approach 4: With global options');
      const client4 = createClient(testUrl, testKey, {
        global: {
          headers: {},
        }
      });
      console.log('✅ Global options init succeeded');
    } catch (e: any) {
      console.error('❌ Global options init failed:', e.message);
    }
    
  } catch (error: any) {
    console.error('Test failed:', error);
  } finally {
    console.groupEnd();
  }
}