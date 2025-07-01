-- Database migration to add missing columns for enhanced scanning
-- Run this on your Supabase database to add repository scanning capabilities

-- Add repository_url column to scans table
ALTER TABLE scans ADD COLUMN IF NOT EXISTS repository_url VARCHAR(500);

-- Add github_token column for private repository access (optional)
ALTER TABLE scans ADD COLUMN IF NOT EXISTS github_token VARCHAR(255);

-- Add progress tracking columns
ALTER TABLE scans ADD COLUMN IF NOT EXISTS progress INTEGER DEFAULT 0;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS estimated_duration INTEGER;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS file_count INTEGER DEFAULT 0;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS repository_size INTEGER DEFAULT 0;

-- Add indexes for better performance
CREATE INDEX IF NOT EXISTS idx_scans_repository_url ON scans(repository_url);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans(user_id);
CREATE INDEX IF NOT EXISTS idx_scans_project_id ON scans(project_id);

-- Add comments for documentation
COMMENT ON COLUMN scans.repository_url IS 'URL of the repository being scanned';
COMMENT ON COLUMN scans.branch IS 'Git branch being scanned (default: main)';
COMMENT ON COLUMN scans.progress IS 'Scan progress percentage (0-100)';
COMMENT ON COLUMN scans.file_count IS 'Number of files scanned';
COMMENT ON COLUMN scans.repository_size IS 'Size of repository in bytes';

-- Update existing scans to populate repository_url from scan_config if available
UPDATE scans 
SET repository_url = (scan_config->>'repositoryUrl')
WHERE repository_url IS NULL 
  AND scan_config ? 'repositoryUrl';

-- Grant necessary permissions (adjust as needed)
-- GRANT SELECT, INSERT, UPDATE, DELETE ON scans TO anon;
-- GRANT SELECT, INSERT, UPDATE, DELETE ON scans TO authenticated;

-- Verify the changes
SELECT column_name, data_type, is_nullable, column_default 
FROM information_schema.columns 
WHERE table_name = 'scans' 
  AND table_schema = 'public'
ORDER BY ordinal_position;