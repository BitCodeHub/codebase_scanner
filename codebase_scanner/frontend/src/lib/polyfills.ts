// Polyfills for Supabase client compatibility
// This ensures all necessary globals are available

// Ensure global is defined
if (typeof globalThis === 'undefined') {
  (window as any).globalThis = window;
}

// Ensure global is also window (some libraries check both)
if (typeof global === 'undefined') {
  (window as any).global = window;
}

// Ensure Headers is available globally
if (typeof Headers === 'undefined') {
  console.warn('Headers not available, Supabase might not work properly');
} else {
  // Make sure Headers is on all global objects
  if (!(globalThis as any).Headers) {
    (globalThis as any).Headers = Headers;
  }
  if (!(window as any).Headers) {
    (window as any).Headers = Headers;
  }
  if (typeof global !== 'undefined' && !(global as any).Headers) {
    (global as any).Headers = Headers;
  }
}

// Ensure fetch is available globally
if (typeof fetch === 'undefined') {
  console.warn('Fetch not available, Supabase might not work properly');
} else {
  // Make sure fetch is on all global objects
  if (!(globalThis as any).fetch) {
    (globalThis as any).fetch = fetch;
  }
  if (!(window as any).fetch) {
    (window as any).fetch = fetch;
  }
  if (typeof global !== 'undefined' && !(global as any).fetch) {
    (global as any).fetch = fetch;
  }
}

// Ensure Request and Response are available
if (typeof Request !== 'undefined') {
  if (!(globalThis as any).Request) {
    (globalThis as any).Request = Request;
  }
  if (!(window as any).Request) {
    (window as any).Request = Request;
  }
  if (typeof global !== 'undefined' && !(global as any).Request) {
    (global as any).Request = Request;
  }
}

if (typeof Response !== 'undefined') {
  if (!(globalThis as any).Response) {
    (globalThis as any).Response = Response;
  }
  if (!(window as any).Response) {
    (window as any).Response = Response;
  }
  if (typeof global !== 'undefined' && !(global as any).Response) {
    (global as any).Response = Response;
  }
}

// Ensure process.env exists (some libraries check for it)
if (typeof process === 'undefined') {
  (window as any).process = { env: {} };
}

// Log what's available
console.log('Polyfills applied. Available globals:', {
  Headers: typeof Headers !== 'undefined',
  fetch: typeof fetch !== 'undefined',
  Request: typeof Request !== 'undefined',
  Response: typeof Response !== 'undefined',
  globalThis: typeof globalThis !== 'undefined',
  global: typeof global !== 'undefined',
  'window.Headers': !!(window as any).Headers,
  'window.fetch': !!(window as any).fetch,
  process: typeof process !== 'undefined'
});