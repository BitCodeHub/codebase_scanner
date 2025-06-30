#!/usr/bin/env node

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Only load .env file if not on Render
const isRender = process.env.RENDER === 'true';
if (!isRender) {
  const envPath = path.join(process.cwd(), '.env');
  if (fs.existsSync(envPath)) {
    const envContent = fs.readFileSync(envPath, 'utf8');
    envContent.split('\n').forEach(line => {
      const trimmedLine = line.trim();
      if (trimmedLine && !trimmedLine.startsWith('#')) {
        const [key, ...valueParts] = trimmedLine.split('=');
        const value = valueParts.join('=');
        if (key && value) {
          process.env[key] = value;
        }
      }
    });
  }
}

console.log('🔧 Generating runtime configuration...');
console.log('Is Render environment:', isRender);
console.log('Environment variables available:', Object.keys(process.env).filter(k => k.startsWith('VITE_')));

// Debug: Log specific env vars (safely)
if (isRender) {
  console.log('VITE_SUPABASE_URL:', process.env.VITE_SUPABASE_URL ? 'Set' : 'Not set');
  console.log('VITE_SUPABASE_ANON_KEY:', process.env.VITE_SUPABASE_ANON_KEY ? 'Set' : 'Not set');
  console.log('VITE_API_URL:', process.env.VITE_API_URL || 'Not set');
}

// Read environment variables
const config = {
  supabaseUrl: process.env.VITE_SUPABASE_URL || '',
  supabaseAnonKey: process.env.VITE_SUPABASE_ANON_KEY || '',
  apiUrl: process.env.VITE_API_URL || 'http://localhost:8000',
  environment: process.env.NODE_ENV || 'development',
  buildTime: new Date().toISOString()
};

// Warn if critical variables are missing
if (!config.supabaseUrl || !config.supabaseAnonKey) {
  console.warn('⚠️  WARNING: Supabase environment variables are missing!');
  console.warn('   VITE_SUPABASE_URL:', config.supabaseUrl ? 'Set' : 'MISSING');
  console.warn('   VITE_SUPABASE_ANON_KEY:', config.supabaseAnonKey ? 'Set' : 'MISSING');
  console.warn('   The app will use mock Supabase client.');
}

// Create the generated directory if it doesn't exist
const generatedDir = path.join(process.cwd(), 'src', 'generated');
if (!fs.existsSync(generatedDir)) {
  fs.mkdirSync(generatedDir, { recursive: true });
}

// Remove old config files to ensure fresh generation
const configPath = path.join(generatedDir, 'config.ts');
const jsonPath = path.join(generatedDir, 'config.json');
if (fs.existsSync(configPath)) {
  fs.unlinkSync(configPath);
  console.log('🗑️  Removed old config.ts');
}
if (fs.existsSync(jsonPath)) {
  fs.unlinkSync(jsonPath);
  console.log('🗑️  Removed old config.json');
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