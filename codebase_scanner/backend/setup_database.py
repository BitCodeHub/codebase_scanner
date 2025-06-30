"""
Setup database tables for the security scanner.
Run this script to create all necessary tables in Supabase.
"""
import os
from dotenv import load_dotenv
from supabase import create_client, Client

# Load environment variables
load_dotenv()

def get_supabase_client() -> Client:
    """Get Supabase client."""
    url = os.getenv("SUPABASE_URL")
    key = os.getenv("SUPABASE_SERVICE_KEY")
    
    if not url or not key:
        raise ValueError("Supabase credentials not configured")
    
    return create_client(url, key)

def create_tables():
    """Create all necessary tables."""
    supabase = get_supabase_client()
    
    # SQL to create tables
    sql_statements = [
        # Users table (if not exists)
        """
        CREATE TABLE IF NOT EXISTS users (
            id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
            email VARCHAR(255) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );
        """,
        
        # Projects table (if not exists)
        """
        CREATE TABLE IF NOT EXISTS projects (
            id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
            user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
            name VARCHAR(255) NOT NULL,
            description TEXT,
            repository_url VARCHAR(500),
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );
        """,
        
        # Scans table
        """
        CREATE TABLE IF NOT EXISTS scans (
            id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
            project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
            user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
            scan_type VARCHAR(50) NOT NULL,
            status VARCHAR(50) NOT NULL,
            file_name VARCHAR(255),
            file_size BIGINT,
            started_at TIMESTAMP WITH TIME ZONE,
            completed_at TIMESTAMP WITH TIME ZONE,
            error_message TEXT,
            total_issues INTEGER DEFAULT 0,
            critical_issues INTEGER DEFAULT 0,
            high_issues INTEGER DEFAULT 0,
            medium_issues INTEGER DEFAULT 0,
            low_issues INTEGER DEFAULT 0,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );
        """,
        
        # Scan results table
        """
        CREATE TABLE IF NOT EXISTS scan_results (
            id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
            scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
            rule_id VARCHAR(255),
            title VARCHAR(500) NOT NULL,
            description TEXT,
            severity VARCHAR(50) NOT NULL,
            category VARCHAR(100),
            vulnerability_type VARCHAR(100),
            owasp_category VARCHAR(100),
            cwe_id VARCHAR(50),
            file_path VARCHAR(500),
            line_number INTEGER,
            column_number INTEGER,
            code_snippet TEXT,
            confidence VARCHAR(50),
            language VARCHAR(50),
            scanner VARCHAR(50),
            fix_recommendation TEXT,
            references JSONB,
            metadata JSONB,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );
        """,
        
        # Create indexes
        """
        CREATE INDEX IF NOT EXISTS idx_scans_project_id ON scans(project_id);
        CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans(user_id);
        CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
        CREATE INDEX IF NOT EXISTS idx_scan_results_scan_id ON scan_results(scan_id);
        CREATE INDEX IF NOT EXISTS idx_scan_results_severity ON scan_results(severity);
        CREATE INDEX IF NOT EXISTS idx_scan_results_category ON scan_results(category);
        """,
        
        # Create RLS policies
        """
        ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
        ALTER TABLE scans ENABLE ROW LEVEL SECURITY;
        ALTER TABLE scan_results ENABLE ROW LEVEL SECURITY;
        """,
        
        # Policies for projects
        """
        CREATE POLICY IF NOT EXISTS "Users can view their own projects" ON projects
            FOR SELECT USING (auth.uid() = user_id);
            
        CREATE POLICY IF NOT EXISTS "Users can create their own projects" ON projects
            FOR INSERT WITH CHECK (auth.uid() = user_id);
            
        CREATE POLICY IF NOT EXISTS "Users can update their own projects" ON projects
            FOR UPDATE USING (auth.uid() = user_id);
            
        CREATE POLICY IF NOT EXISTS "Users can delete their own projects" ON projects
            FOR DELETE USING (auth.uid() = user_id);
        """,
        
        # Policies for scans
        """
        CREATE POLICY IF NOT EXISTS "Users can view their own scans" ON scans
            FOR SELECT USING (auth.uid() = user_id);
            
        CREATE POLICY IF NOT EXISTS "Users can create their own scans" ON scans
            FOR INSERT WITH CHECK (auth.uid() = user_id);
            
        CREATE POLICY IF NOT EXISTS "Users can update their own scans" ON scans
            FOR UPDATE USING (auth.uid() = user_id);
        """,
        
        # Policies for scan results
        """
        CREATE POLICY IF NOT EXISTS "Users can view their scan results" ON scan_results
            FOR SELECT USING (
                EXISTS (
                    SELECT 1 FROM scans 
                    WHERE scans.id = scan_results.scan_id 
                    AND scans.user_id = auth.uid()
                )
            );
        """
    ]
    
    # Execute each statement
    for sql in sql_statements:
        try:
            # Note: Supabase doesn't directly support raw SQL execution via the client
            # You'll need to run these in the Supabase SQL editor
            print(f"SQL to execute:\n{sql}\n")
        except Exception as e:
            print(f"Error: {e}")
    
    print("\nTo create the tables, please:")
    print("1. Go to your Supabase dashboard")
    print("2. Navigate to the SQL editor")
    print("3. Copy and paste each SQL statement above")
    print("4. Execute them in order")

if __name__ == "__main__":
    create_tables()