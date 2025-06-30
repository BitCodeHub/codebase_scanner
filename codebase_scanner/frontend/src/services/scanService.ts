import { supabase } from '../lib/supabase'
import { runtimeConfig } from '../generated/config'

const API_BASE_URL = runtimeConfig.apiUrl || import.meta.env.VITE_API_URL || 'http://localhost:8000'

export interface ScanOptions {
  scanType: 'quick' | 'comprehensive' | 'custom'
  includeTests: boolean
  includeDependencies: boolean
  severityThreshold: 'all' | 'low' | 'medium' | 'high' | 'critical'
  frameworks: string[]
}

export interface RepositoryScanOptions {
  repositoryUrl: string
  branch?: string
  scanType?: 'quick' | 'comprehensive' | 'custom'
}

export async function startFileScan(
  projectId: string, 
  files: File[], 
  options: ScanOptions
): Promise<{ scanId: string; message: string }> {
  const formData = new FormData()
  formData.append('project_id', projectId)
  formData.append('scan_type', options.scanType === 'quick' ? 'QUICK' : 'FULL')
  
  // For now, scan the first file - in production you'd handle multiple files
  if (files.length > 0) {
    formData.append('file', files[0])
  }

  const session = await supabase.auth.getSession()
  const token = session.data.session?.access_token

  const response = await fetch(`${API_BASE_URL}/api/scans/`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`
    },
    body: formData
  })

  if (!response.ok) {
    throw new Error('Failed to start scan')
  }

  const result = await response.json()
  return {
    scanId: result.id,
    message: result.message
  }
}

export async function startRepositoryScan(
  projectId: string,
  options: RepositoryScanOptions
): Promise<{ scanId: string; message: string }> {
  const formData = new FormData()
  formData.append('project_id', projectId)
  formData.append('repository_url', options.repositoryUrl)
  formData.append('branch', options.branch || 'main')
  formData.append('scan_type', options.scanType === 'quick' ? 'QUICK' : 'FULL')

  const session = await supabase.auth.getSession()
  const token = session.data.session?.access_token

  const response = await fetch(`${API_BASE_URL}/api/scans/repository`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`
    },
    body: formData
  })

  if (!response.ok) {
    throw new Error('Failed to start repository scan')
  }

  const result = await response.json()
  return {
    scanId: result.id,
    message: result.message
  }
}

export async function analyzeAllVulnerabilities(scanId: string): Promise<{ message: string; taskId: string }> {
  const session = await supabase.auth.getSession()
  const token = session.data.session?.access_token

  const response = await fetch(`${API_BASE_URL}/api/ai/scan/${scanId}/analyze-all`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    }
  })

  if (!response.ok) {
    throw new Error('Failed to start AI analysis')
  }

  const result = await response.json()
  return {
    message: result.message,
    taskId: result.task_id
  }
}

export async function analyzeSingleVulnerability(vulnerability: any): Promise<any> {
  const session = await supabase.auth.getSession()
  const token = session.data.session?.access_token

  const analysisRequest = {
    vulnerability_id: vulnerability.id,
    cwe_id: vulnerability.rule_id,
    vulnerability_type: vulnerability.vulnerability_type || vulnerability.category,
    owasp_category: vulnerability.owasp_category,
    file_path: vulnerability.file_path,
    line_number: vulnerability.line_number,
    code_snippet: vulnerability.code_snippet,
    language: vulnerability.language || 'python',
    severity: vulnerability.severity,
    context: vulnerability.description
  }

  const response = await fetch(`${API_BASE_URL}/api/ai/analyze-vulnerability`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(analysisRequest)
  })

  if (!response.ok) {
    throw new Error('Failed to analyze vulnerability')
  }

  return await response.json()
}

export async function getVulnerabilityAnalysis(vulnerabilityId: string): Promise<any> {
  const session = await supabase.auth.getSession()
  const token = session.data.session?.access_token

  const response = await fetch(`${API_BASE_URL}/api/ai/analysis/${vulnerabilityId}`, {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${token}`
    }
  })

  if (!response.ok) {
    if (response.status === 404) {
      return null // No analysis found
    }
    throw new Error('Failed to get vulnerability analysis')
  }

  return await response.json()
}

export async function simulateScan(scanId: number, projectId: number) {
  try {
    // Update scan status to running
    await supabase
      .from('scans')
      .update({
        status: 'running',
        started_at: new Date().toISOString()
      })
      .eq('id', scanId)

    // Simulate scanning delay
    await new Promise(resolve => setTimeout(resolve, 3000))

    // Generate mock vulnerabilities for demo
    const mockVulnerabilities = [
      {
        scan_id: scanId,
        rule_id: 'CWE-798',
        title: 'Hardcoded Database Credentials',
        description: 'Database password is hardcoded in the configuration file',
        severity: 'critical',
        category: 'Authentication',
        vulnerability_type: 'Hardcoded Secret',
        file_path: 'src/config/database.js',
        line_number: 15,
        code_snippet: 'const DB_PASSWORD = "admin123"',
        confidence: 'high',
        owasp_category: 'A07:2021 – Identification and Authentication Failures',
        fix_recommendation: 'Use environment variables to store sensitive credentials',
        cvss_score: 9.8
      },
      {
        scan_id: scanId,
        rule_id: 'CWE-89',
        title: 'SQL Injection Vulnerability',
        description: 'User input is directly concatenated into SQL query',
        severity: 'high',
        category: 'Injection',
        vulnerability_type: 'SQL Injection',
        file_path: 'src/api/users.js',
        line_number: 42,
        code_snippet: 'const query = "SELECT * FROM users WHERE id = " + userId',
        confidence: 'high',
        owasp_category: 'A03:2021 – Injection',
        fix_recommendation: 'Use parameterized queries or prepared statements',
        cvss_score: 8.9
      },
      {
        scan_id: scanId,
        rule_id: 'CWE-79',
        title: 'Cross-Site Scripting (XSS)',
        description: 'User input is rendered without proper sanitization',
        severity: 'medium',
        category: 'Injection',
        vulnerability_type: 'XSS',
        file_path: 'src/components/UserProfile.jsx',
        line_number: 28,
        code_snippet: 'dangerouslySetInnerHTML={{ __html: userBio }}',
        confidence: 'medium',
        owasp_category: 'A03:2021 – Injection',
        fix_recommendation: 'Sanitize user input before rendering or use safe rendering methods',
        cvss_score: 6.1
      }
    ]

    // Insert mock vulnerabilities
    const insertResult = await supabase
      .from('scan_results')
      .insert(mockVulnerabilities)
    
    const insertError = 'error' in insertResult ? insertResult.error : null

    if (insertError) throw insertError

    // Count issues by severity
    const critical_issues = mockVulnerabilities.filter(v => v.severity === 'critical').length
    const high_issues = mockVulnerabilities.filter(v => v.severity === 'high').length
    const medium_issues = mockVulnerabilities.filter(v => v.severity === 'medium').length
    const low_issues = mockVulnerabilities.filter(v => v.severity === 'low').length

    // Update scan with completion status
    await supabase
      .from('scans')
      .update({
        status: 'completed',
        completed_at: new Date().toISOString(),
        total_issues: mockVulnerabilities.length,
        critical_issues,
        high_issues,
        medium_issues,
        low_issues
      })
      .eq('id', scanId)

    return { success: true }
  } catch (error) {
    console.error('Scan simulation error:', error)
    
    // Update scan status to failed
    await supabase
      .from('scans')
      .update({
        status: 'failed',
        error_message: error instanceof Error ? error.message : 'Unknown error occurred'
      })
      .eq('id', scanId)

    return { success: false, error }
  }
}