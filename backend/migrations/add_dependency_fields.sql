-- Add dependency-related columns to scan_results table
ALTER TABLE scan_results 
ADD COLUMN IF NOT EXISTS affected_packages JSONB DEFAULT '[]',
ADD COLUMN IF NOT EXISTS vulnerable_versions JSONB DEFAULT '{}',
ADD COLUMN IF NOT EXISTS fixed_versions JSONB DEFAULT '{}',
ADD COLUMN IF NOT EXISTS dependency_chain JSONB DEFAULT '[]';