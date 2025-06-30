#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

console.log('🔧 Setting up environment for build...');
console.log('================================');
console.log('Environment:', process.env.NODE_ENV || 'development');
console.log('Working Directory:', process.cwd());

// Check if we're in a Render environment
const isRender = process.env.RENDER === 'true';
console.log('Is Render environment:', isRender);

// Get environment variables from process.env
const envVars = {
  VITE_SUPABASE_URL: process.env.VITE_SUPABASE_URL || '',
  VITE_SUPABASE_ANON_KEY: process.env.VITE_SUPABASE_ANON_KEY || '',
  VITE_API_URL: process.env.VITE_API_URL || 'http://localhost:8000'
};

// Log what we found (safely)
console.log('📋 Environment variables:');
Object.entries(envVars).forEach(([key, value]) => {
  const displayValue = value ? `✅ Set (${value.substring(0, 20)}...)` : '❌ Not set';
  console.log(`  ${key}: ${displayValue}`);
});

// Create .env file for Vite
const envContent = Object.entries(envVars)
  .map(([key, value]) => `${key}=${value}`)
  .join('\n');

fs.writeFileSync('.env', envContent);
console.log('✅ Created .env file');

// Also create .env.local and .env.production for redundancy
fs.writeFileSync('.env.local', envContent);
fs.writeFileSync('.env.production', envContent);
console.log('✅ Created .env.local and .env.production files');

console.log('✅ Environment setup complete');
console.log('================================');