#!/usr/bin/env node

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

console.log('🔧 Fixing production configuration...');

// Update generated config files if they exist
const generatedDir = path.join(process.cwd(), 'src', 'generated');

if (fs.existsSync(generatedDir)) {
  const configPath = path.join(generatedDir, 'config.ts');
  const jsonPath = path.join(generatedDir, 'config.json');
  
  // Fix TypeScript config
  if (fs.existsSync(configPath)) {
    let content = fs.readFileSync(configPath, 'utf8');
    content = content.replace(
      /apiUrl: "http:\/\/localhost:8001"/g,
      'apiUrl: "https://codebase-scanner-backend.onrender.com"'
    );
    fs.writeFileSync(configPath, content);
    console.log('✅ Fixed src/generated/config.ts');
  }
  
  // Fix JSON config
  if (fs.existsSync(jsonPath)) {
    let content = fs.readFileSync(jsonPath, 'utf8');
    const config = JSON.parse(content);
    if (config.apiUrl && config.apiUrl.includes('localhost')) {
      config.apiUrl = 'https://codebase-scanner-backend.onrender.com';
      fs.writeFileSync(jsonPath, JSON.stringify(config, null, 2));
      console.log('✅ Fixed src/generated/config.json');
    }
  }
}

console.log('✅ Production configuration fixed!');