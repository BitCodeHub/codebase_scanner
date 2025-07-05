#!/bin/bash

echo "🔧 Setting up backend environment..."

# Check if .env already exists
if [ -f ".env" ]; then
    echo "⚠️  .env file already exists. Backing up to .env.backup"
    cp .env .env.backup
fi

# Create .env from template
cp .env.example .env

echo ""
echo "✅ Created .env file from template"
echo ""
echo "📝 Next steps:"
echo "1. Edit the .env file and add your Supabase credentials:"
echo "   - SUPABASE_URL: Your Supabase project URL"
echo "   - SUPABASE_SERVICE_ROLE_KEY: Your service role key (from Supabase dashboard)"
echo ""
echo "2. To find your Supabase credentials:"
echo "   - Go to https://app.supabase.com"
echo "   - Select your project"
echo "   - Go to Settings > API"
echo "   - Copy the Project URL and service_role key"
echo ""
echo "3. After adding credentials, test the connection:"
echo "   python test_db_connection.py"
echo ""
echo "4. Restart your backend server on Render"