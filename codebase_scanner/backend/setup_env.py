#!/usr/bin/env python3
"""
Helper script to set up .env file for local development
"""
import os
import shutil

def setup_env():
    env_file = ".env"
    env_example = ".env.example"
    
    if os.path.exists(env_file):
        print("✓ .env file already exists")
        return
    
    if not os.path.exists(env_example):
        print("❌ .env.example not found!")
        return
    
    print("Creating .env file from .env.example...")
    shutil.copy(env_example, env_file)
    print("✓ .env file created")
    
    print("\n⚠️  IMPORTANT: You need to update the .env file with your actual credentials:")
    print("1. Open .env in your editor")
    print("2. Add your Supabase URL and service role key")
    print("3. Add your Anthropic API key (optional, for AI features)")
    print("\nExample:")
    print("SUPABASE_URL=https://your-project.supabase.co")
    print("SUPABASE_SERVICE_ROLE_KEY=your-service-role-key")

if __name__ == "__main__":
    setup_env()