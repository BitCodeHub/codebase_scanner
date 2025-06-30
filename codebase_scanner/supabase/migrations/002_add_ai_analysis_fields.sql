-- Add AI analysis fields to existing tables

-- Add AI analysis fields to scans table
ALTER TABLE scans
ADD COLUMN IF NOT EXISTS ai_analysis_status VARCHAR(50) DEFAULT 'pending',
ADD COLUMN IF NOT EXISTS ai_analyzed_count INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS ai_analysis_started_at TIMESTAMPTZ,
ADD COLUMN IF NOT EXISTS ai_analysis_completed_at TIMESTAMPTZ,
ADD COLUMN IF NOT EXISTS ai_analysis_error TEXT;

-- Add AI analysis timestamp to scan_results
ALTER TABLE scan_results
ADD COLUMN IF NOT EXISTS ai_analyzed_at TIMESTAMPTZ;

-- Create index for AI analysis status
CREATE INDEX IF NOT EXISTS idx_scans_ai_analysis_status ON scans(ai_analysis_status);
CREATE INDEX IF NOT EXISTS idx_scan_results_ai_analyzed ON scan_results(ai_analyzed_at);

-- Add AI analysis permissions to RLS policies
-- Allow users to view AI analysis results for their own projects
CREATE POLICY "Users can view AI analysis of own projects" ON scan_results
    FOR SELECT USING (
        EXISTS (
            SELECT 1 FROM scans 
            JOIN projects ON projects.id = scans.project_id
            WHERE scans.id = scan_results.scan_id 
            AND projects.owner_id = auth.uid()
        )
    );