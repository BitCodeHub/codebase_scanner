#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

console.log('🔧 Generating runtime configuration...');

// Read environment variables
const config = {
  supabaseUrl: process.env.VITE_SUPABASE_URL || '',
  supabaseAnonKey: process.env.VITE_SUPABASE_ANON_KEY || '',
  apiUrl: process.env.VITE_API_URL || 'http://localhost:8000',
  environment: process.env.NODE_ENV || 'development',
  buildTime: new Date().toISOString()
};

// Create the generated directory if it doesn't exist
const generatedDir = path.join(process.cwd(), 'src', 'generated');
if (!fs.existsSync(generatedDir)) {
  fs.mkdirSync(generatedDir, { recursive: true });
}

// Generate TypeScript config file
const tsConfigContent = `// This file is auto-generated. Do not edit manually.
// Generated at: ${config.buildTime}

export const runtimeConfig = {
  supabaseUrl: "${config.supabaseUrl}",
  supabaseAnonKey: "${config.supabaseAnonKey}",
  apiUrl: "${config.apiUrl}",
  environment: "${config.environment}",
  buildTime: "${config.buildTime}"
} as const;

export const isConfigured = !!(
  runtimeConfig.supabaseUrl && 
  runtimeConfig.supabaseAnonKey
);
`;

fs.writeFileSync(path.join(generatedDir, 'config.ts'), tsConfigContent);
console.log('✅ Generated src/generated/config.ts');

// Also generate a JSON version for runtime checks
fs.writeFileSync(
  path.join(generatedDir, 'config.json'), 
  JSON.stringify(config, null, 2)
);
console.log('✅ Generated src/generated/config.json');

// Log configuration status
console.log('📊 Configuration Status:');
console.log('- Supabase URL:', config.supabaseUrl ? '✅ Set' : '❌ Not set');
console.log('- Supabase Key:', config.supabaseAnonKey ? '✅ Set' : '❌ Not set');
console.log('- API URL:', config.apiUrl);
console.log('- Generated at:', config.buildTime);