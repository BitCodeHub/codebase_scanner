# Supabase Setup Guide

## 🚀 Complete Supabase Integration Setup

### Step 1: Create Supabase Project

1. **Visit [Supabase](https://supabase.com)** and create an account
2. **Create New Project**:
   - Organization: Choose or create
   - Project Name: `codebase-scanner`
   - Database Password: Generate strong password
   - Region: Choose closest to your users
   - Pricing: Start with Free tier

3. **Wait for Setup** (2-3 minutes)

### Step 2: Get Project Credentials

From your Supabase dashboard:

1. **Go to Settings → API**
2. **Copy these values**:
   ```
   Project URL: https://your-project.supabase.co
   Anon Key: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
   Service Role Key: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
   ```

3. **Update your `.env` file**:
   ```env
   SUPABASE_URL=https://your-project.supabase.co
   SUPABASE_ANON_KEY=your_anon_key_here
   SUPABASE_SERVICE_KEY=your_service_key_here
   
   VITE_SUPABASE_URL=https://your-project.supabase.co
   VITE_SUPABASE_ANON_KEY=your_anon_key_here
   ```

### Step 3: Database Schema Setup

Run this SQL in your Supabase SQL Editor:

```sql
-- Enable necessary extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Enable Row Level Security
ALTER DATABASE postgres SET row_security = on;

-- Custom types
CREATE TYPE scan_status AS ENUM ('pending', 'running', 'completed', 'failed', 'cancelled');
CREATE TYPE scan_type AS ENUM ('security', 'quality', 'performance', 'launch_ready', 'full');
CREATE TYPE severity AS ENUM ('critical', 'high', 'medium', 'low', 'info');

-- Projects table
CREATE TABLE projects (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    github_repo_url VARCHAR(500),
    github_default_branch VARCHAR(100) DEFAULT 'main',
    uploaded_file_path VARCHAR(500),
    owner_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    is_active BOOLEAN DEFAULT true
);

-- Scans table
CREATE TABLE scans (
    id BIGSERIAL PRIMARY KEY,
    project_id BIGINT REFERENCES projects(id) ON DELETE CASCADE,
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    scan_type scan_type NOT NULL,
    status scan_status DEFAULT 'pending',
    commit_sha VARCHAR(40),
    branch VARCHAR(100),
    triggered_by VARCHAR(50),
    scan_config JSONB DEFAULT '{}',
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    total_issues INTEGER DEFAULT 0,
    critical_issues INTEGER DEFAULT 0,
    high_issues INTEGER DEFAULT 0,
    medium_issues INTEGER DEFAULT 0,
    low_issues INTEGER DEFAULT 0,
    celery_task_id VARCHAR(255),
    error_message TEXT
);

-- Scan results table
CREATE TABLE scan_results (
    id BIGSERIAL PRIMARY KEY,
    scan_id BIGINT REFERENCES scans(id) ON DELETE CASCADE,
    rule_id VARCHAR(100),
    title VARCHAR(255) NOT NULL,
    description TEXT,
    severity severity NOT NULL,
    category VARCHAR(100),
    file_path VARCHAR(500),
    line_number INTEGER,
    column_number INTEGER,
    code_snippet TEXT,
    vulnerability_type VARCHAR(100),
    confidence VARCHAR(50) DEFAULT 'medium',
    fix_recommendation TEXT,
    ai_generated_fix TEXT,
    references JSONB DEFAULT '[]',
    remediation_example TEXT,
    
    -- Risk Assessment
    cvss_score DECIMAL(3,1),
    cvss_vector VARCHAR(255),
    risk_rating VARCHAR(50),
    exploitability TEXT,
    impact TEXT,
    likelihood VARCHAR(50),
    
    -- Compliance & Standards
    owasp_category VARCHAR(255),
    compliance_mappings JSONB DEFAULT '{}',
    
    -- Development Impact
    fix_effort VARCHAR(50),
    fix_priority INTEGER,
    
    -- Additional Context
    code_context JSONB,
    tags JSONB DEFAULT '[]',
    
    -- Dependency Information
    affected_packages JSONB DEFAULT '[]',
    vulnerable_versions JSONB DEFAULT '{}',
    fixed_versions JSONB DEFAULT '{}',
    dependency_chain JSONB DEFAULT '[]',
    
    -- Metadata
    analyzer VARCHAR(100),
    raw_output JSONB,
    false_positive BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Reports table
CREATE TABLE reports (
    id BIGSERIAL PRIMARY KEY,
    scan_id BIGINT REFERENCES scans(id) ON DELETE CASCADE,
    project_id BIGINT REFERENCES projects(id) ON DELETE CASCADE,
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    report_type VARCHAR(50) NOT NULL,
    title VARCHAR(255) NOT NULL,
    summary TEXT,
    recommendations TEXT,
    compliance_status JSONB DEFAULT '{}',
    executive_summary TEXT,
    technical_details JSONB DEFAULT '{}',
    file_path VARCHAR(500),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- User profiles table (extends Supabase auth.users)
CREATE TABLE user_profiles (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    full_name TEXT,
    avatar_url TEXT,
    organization TEXT,
    role TEXT DEFAULT 'user',
    preferences JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX idx_projects_owner_id ON projects(owner_id);
CREATE INDEX idx_scans_project_id ON scans(project_id);
CREATE INDEX idx_scans_user_id ON scans(user_id);
CREATE INDEX idx_scans_status ON scans(status);
CREATE INDEX idx_scans_created_at ON scans(created_at);
CREATE INDEX idx_scan_results_scan_id ON scan_results(scan_id);
CREATE INDEX idx_scan_results_severity ON scan_results(severity);
CREATE INDEX idx_scan_results_file_path ON scan_results(file_path);
CREATE INDEX idx_reports_scan_id ON reports(scan_id);
CREATE INDEX idx_reports_user_id ON reports(user_id);

-- Updated at triggers
CREATE OR REPLACE FUNCTION handle_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER projects_updated_at
    BEFORE UPDATE ON projects
    FOR EACH ROW
    EXECUTE FUNCTION handle_updated_at();

CREATE TRIGGER user_profiles_updated_at
    BEFORE UPDATE ON user_profiles
    FOR EACH ROW
    EXECUTE FUNCTION handle_updated_at();
```

### Step 4: Row Level Security (RLS) Policies

```sql
-- Enable RLS on all tables
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_profiles ENABLE ROW LEVEL SECURITY;

-- Projects policies
CREATE POLICY "Users can view own projects" ON projects
    FOR SELECT USING (auth.uid() = owner_id);

CREATE POLICY "Users can insert own projects" ON projects
    FOR INSERT WITH CHECK (auth.uid() = owner_id);

CREATE POLICY "Users can update own projects" ON projects
    FOR UPDATE USING (auth.uid() = owner_id);

CREATE POLICY "Users can delete own projects" ON projects
    FOR DELETE USING (auth.uid() = owner_id);

-- Scans policies
CREATE POLICY "Users can view scans of own projects" ON scans
    FOR SELECT USING (
        EXISTS (
            SELECT 1 FROM projects 
            WHERE projects.id = scans.project_id 
            AND projects.owner_id = auth.uid()
        )
    );

CREATE POLICY "Users can insert scans for own projects" ON scans
    FOR INSERT WITH CHECK (
        EXISTS (
            SELECT 1 FROM projects 
            WHERE projects.id = scans.project_id 
            AND projects.owner_id = auth.uid()
        )
    );

CREATE POLICY "Users can update scans of own projects" ON scans
    FOR UPDATE USING (
        EXISTS (
            SELECT 1 FROM projects 
            WHERE projects.id = scans.project_id 
            AND projects.owner_id = auth.uid()
        )
    );

-- Scan results policies
CREATE POLICY "Users can view scan results of own projects" ON scan_results
    FOR SELECT USING (
        EXISTS (
            SELECT 1 FROM scans 
            JOIN projects ON projects.id = scans.project_id
            WHERE scans.id = scan_results.scan_id 
            AND projects.owner_id = auth.uid()
        )
    );

CREATE POLICY "Users can insert scan results for own projects" ON scan_results
    FOR INSERT WITH CHECK (
        EXISTS (
            SELECT 1 FROM scans 
            JOIN projects ON projects.id = scans.project_id
            WHERE scans.id = scan_results.scan_id 
            AND projects.owner_id = auth.uid()
        )
    );

-- Reports policies
CREATE POLICY "Users can view own reports" ON reports
    FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY "Users can insert own reports" ON reports
    FOR INSERT WITH CHECK (auth.uid() = user_id);

-- User profiles policies
CREATE POLICY "Users can view own profile" ON user_profiles
    FOR SELECT USING (auth.uid() = id);

CREATE POLICY "Users can update own profile" ON user_profiles
    FOR UPDATE USING (auth.uid() = id);

CREATE POLICY "Users can insert own profile" ON user_profiles
    FOR INSERT WITH CHECK (auth.uid() = id);
```

### Step 5: Storage Setup

1. **Go to Storage in Supabase Dashboard**
2. **Create Buckets**:
   ```sql
   -- Create storage buckets
   INSERT INTO storage.buckets (id, name, public)
   VALUES 
   ('project-files', 'project-files', false),
   ('scan-reports', 'scan-reports', false);
   ```

3. **Storage Policies**:
   ```sql
   -- Project files storage policies
   CREATE POLICY "Users can upload to own folder" ON storage.objects
   FOR INSERT WITH CHECK (
       bucket_id = 'project-files' 
       AND (storage.foldername(name))[1] = auth.uid()::text
   );

   CREATE POLICY "Users can view own files" ON storage.objects
   FOR SELECT USING (
       bucket_id = 'project-files' 
       AND (storage.foldername(name))[1] = auth.uid()::text
   );

   -- Reports storage policies
   CREATE POLICY "Users can upload own reports" ON storage.objects
   FOR INSERT WITH CHECK (
       bucket_id = 'scan-reports' 
       AND (storage.foldername(name))[1] = auth.uid()::text
   );

   CREATE POLICY "Users can view own reports" ON storage.objects
   FOR SELECT USING (
       bucket_id = 'scan-reports' 
       AND (storage.foldername(name))[1] = auth.uid()::text
   );
   ```

### Step 6: Authentication Setup

1. **Go to Authentication → Settings**
2. **Configure Site URL**: `http://localhost:5173` (development)
3. **Add Redirect URLs**:
   - Development: `http://localhost:5173/**`
   - Production: `https://yourdomain.com/**`

4. **Enable Auth Providers** (optional):
   - GitHub OAuth
   - Google OAuth
   - Email/Password (enabled by default)

### Step 7: Edge Functions (Optional)

Create an edge function for background scan processing:

```typescript
// supabase/functions/process-scan/index.ts
import { serve } from "https://deno.land/std@0.168.0/http/server.ts"
import { createClient } from "https://esm.sh/@supabase/supabase-js@2"

serve(async (req) => {
  const { scanId } = await req.json()
  
  const supabase = createClient(
    Deno.env.get('SUPABASE_URL') ?? '',
    Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? ''
  )
  
  // Process scan logic here
  
  return new Response(JSON.stringify({ success: true }), {
    headers: { "Content-Type": "application/json" },
  })
})
```

### Step 8: Real-time Subscriptions

Enable real-time for scan status updates:

```sql
-- Enable real-time for scans table
ALTER PUBLICATION supabase_realtime ADD TABLE scans;
```

### Step 9: Verify Setup

Test your setup:

```javascript
// Test connection
import { createClient } from '@supabase/supabase-js'

const supabase = createClient(
  process.env.VITE_SUPABASE_URL,
  process.env.VITE_SUPABASE_ANON_KEY
)

// Test query
const { data, error } = await supabase
  .from('projects')
  .select('*')
  
console.log('Supabase connected:', !error)
```

## 🎉 You're Ready!

Your Supabase backend is now configured for production-grade security scanning. The setup includes:

- ✅ **Complete database schema** with all necessary tables
- ✅ **Row Level Security** for data isolation
- ✅ **Storage buckets** for file uploads
- ✅ **Authentication** ready for users
- ✅ **Real-time subscriptions** for live updates
- ✅ **Performance indexes** for fast queries
- ✅ **Production-ready policies** for security

Next steps: Set up your frontend and backend code to use these Supabase services!