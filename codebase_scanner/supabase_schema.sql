-- Complete Supabase Schema for Codebase Scanner
-- Run this in your Supabase SQL Editor

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
    reference_links JSONB DEFAULT '[]',
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

-- Create storage buckets
INSERT INTO storage.buckets (id, name, public)
VALUES 
('project-files', 'project-files', false),
('scan-reports', 'scan-reports', false);

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

-- Enable real-time for scans table
ALTER PUBLICATION supabase_realtime ADD TABLE scans;