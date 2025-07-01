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

// Ensure window.global exists (some bundlers check this)
if (!(window as any).global) {
  (window as any).global = window;
}

// Create a proper global Headers if needed
if (typeof Headers !== 'undefined' && !(window as any).global.Headers) {
  (window as any).global.Headers = Headers;
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

// Ensure XMLHttpRequest is available (some libraries use it as fallback)
if (typeof XMLHttpRequest !== 'undefined') {
  if (!(globalThis as any).XMLHttpRequest) {
    (globalThis as any).XMLHttpRequest = XMLHttpRequest;
  }
}

// Ensure AbortController is available
if (typeof AbortController !== 'undefined') {
  if (!(globalThis as any).AbortController) {
    (globalThis as any).AbortController = AbortController;
  }
  if (!(window as any).AbortController) {
    (window as any).AbortController = AbortController;
  }
}

// Ensure crypto is available
if (typeof crypto !== 'undefined') {
  if (!(globalThis as any).crypto) {
    (globalThis as any).crypto = crypto;
  }
  if (!(window as any).crypto) {
    (window as any).crypto = crypto;
  }
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