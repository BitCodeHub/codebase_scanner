// Polyfills for Supabase client compatibility
// This ensures all necessary globals are available

// Ensure global is defined
if (typeof globalThis === 'undefined') {
  (window as any).globalThis = window;
}

// Ensure Headers is available globally
if (typeof Headers === 'undefined') {
  console.warn('Headers not available, Supabase might not work properly');
} else {
  // Make sure Headers is on the global object
  if (!(globalThis as any).Headers) {
    (globalThis as any).Headers = Headers;
  }
}

// Ensure fetch is available globally
if (typeof fetch === 'undefined') {
  console.warn('Fetch not available, Supabase might not work properly');
} else {
  // Make sure fetch is on the global object
  if (!(globalThis as any).fetch) {
    (globalThis as any).fetch = fetch;
  }
}

// Ensure Request and Response are available
if (typeof Request !== 'undefined' && !(globalThis as any).Request) {
  (globalThis as any).Request = Request;
}

if (typeof Response !== 'undefined' && !(globalThis as any).Response) {
  (globalThis as any).Response = Response;
}

// Log what's available
console.log('Polyfills applied. Available globals:', {
  Headers: typeof Headers !== 'undefined',
  fetch: typeof fetch !== 'undefined',
  Request: typeof Request !== 'undefined',
  Response: typeof Response !== 'undefined',
  globalThis: typeof globalThis !== 'undefined'
});