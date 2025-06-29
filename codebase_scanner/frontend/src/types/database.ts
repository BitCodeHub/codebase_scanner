export type Json =
  | string
  | number
  | boolean
  | null
  | { [key: string]: Json | undefined }
  | Json[]

export interface Database {
  public: {
    Tables: {
      projects: {
        Row: {
          id: number
          name: string
          description: string | null
          github_repo_url: string | null
          github_default_branch: string | null
          uploaded_file_path: string | null
          owner_id: string
          created_at: string
          updated_at: string
          is_active: boolean
        }
        Insert: {
          id?: number
          name: string
          description?: string | null
          github_repo_url?: string | null
          github_default_branch?: string | null
          uploaded_file_path?: string | null
          owner_id: string
          created_at?: string
          updated_at?: string
          is_active?: boolean
        }
        Update: {
          id?: number
          name?: string
          description?: string | null
          github_repo_url?: string | null
          github_default_branch?: string | null
          uploaded_file_path?: string | null
          owner_id?: string
          created_at?: string
          updated_at?: string
          is_active?: boolean
        }
      }
      scans: {
        Row: {
          id: number
          project_id: number
          user_id: string
          scan_type: 'security' | 'quality' | 'performance' | 'launch_ready' | 'full'
          status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled'
          commit_sha: string | null
          branch: string | null
          triggered_by: string | null
          scan_config: Json
          started_at: string | null
          completed_at: string | null
          created_at: string
          total_issues: number
          critical_issues: number
          high_issues: number
          medium_issues: number
          low_issues: number
          celery_task_id: string | null
          error_message: string | null
        }
        Insert: {
          id?: number
          project_id: number
          user_id: string
          scan_type: 'security' | 'quality' | 'performance' | 'launch_ready' | 'full'
          status?: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled'
          commit_sha?: string | null
          branch?: string | null
          triggered_by?: string | null
          scan_config?: Json
          started_at?: string | null
          completed_at?: string | null
          created_at?: string
          total_issues?: number
          critical_issues?: number
          high_issues?: number
          medium_issues?: number
          low_issues?: number
          celery_task_id?: string | null
          error_message?: string | null
        }
        Update: {
          id?: number
          project_id?: number
          user_id?: string
          scan_type?: 'security' | 'quality' | 'performance' | 'launch_ready' | 'full'
          status?: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled'
          commit_sha?: string | null
          branch?: string | null
          triggered_by?: string | null
          scan_config?: Json
          started_at?: string | null
          completed_at?: string | null
          created_at?: string
          total_issues?: number
          critical_issues?: number
          high_issues?: number
          medium_issues?: number
          low_issues?: number
          celery_task_id?: string | null
          error_message?: string | null
        }
      }
      scan_results: {
        Row: {
          id: number
          scan_id: number
          rule_id: string | null
          title: string
          description: string | null
          severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
          category: string | null
          file_path: string | null
          line_number: number | null
          column_number: number | null
          code_snippet: string | null
          vulnerability_type: string | null
          confidence: string | null
          fix_recommendation: string | null
          ai_generated_fix: string | null
          references: Json
          remediation_example: string | null
          cvss_score: number | null
          cvss_vector: string | null
          risk_rating: string | null
          exploitability: string | null
          impact: string | null
          likelihood: string | null
          owasp_category: string | null
          compliance_mappings: Json
          fix_effort: string | null
          fix_priority: number | null
          code_context: Json | null
          tags: Json
          affected_packages: Json
          vulnerable_versions: Json
          fixed_versions: Json
          dependency_chain: Json
          analyzer: string | null
          raw_output: Json | null
          false_positive: boolean
          created_at: string
        }
        Insert: {
          id?: number
          scan_id: number
          rule_id?: string | null
          title: string
          description?: string | null
          severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
          category?: string | null
          file_path?: string | null
          line_number?: number | null
          column_number?: number | null
          code_snippet?: string | null
          vulnerability_type?: string | null
          confidence?: string | null
          fix_recommendation?: string | null
          ai_generated_fix?: string | null
          references?: Json
          remediation_example?: string | null
          cvss_score?: number | null
          cvss_vector?: string | null
          risk_rating?: string | null
          exploitability?: string | null
          impact?: string | null
          likelihood?: string | null
          owasp_category?: string | null
          compliance_mappings?: Json
          fix_effort?: string | null
          fix_priority?: number | null
          code_context?: Json | null
          tags?: Json
          affected_packages?: Json
          vulnerable_versions?: Json
          fixed_versions?: Json
          dependency_chain?: Json
          analyzer?: string | null
          raw_output?: Json | null
          false_positive?: boolean
          created_at?: string
        }
        Update: {
          id?: number
          scan_id?: number
          rule_id?: string | null
          title?: string
          description?: string | null
          severity?: 'critical' | 'high' | 'medium' | 'low' | 'info'
          category?: string | null
          file_path?: string | null
          line_number?: number | null
          column_number?: number | null
          code_snippet?: string | null
          vulnerability_type?: string | null
          confidence?: string | null
          fix_recommendation?: string | null
          ai_generated_fix?: string | null
          references?: Json
          remediation_example?: string | null
          cvss_score?: number | null
          cvss_vector?: string | null
          risk_rating?: string | null
          exploitability?: string | null
          impact?: string | null
          likelihood?: string | null
          owasp_category?: string | null
          compliance_mappings?: Json
          fix_effort?: string | null
          fix_priority?: number | null
          code_context?: Json | null
          tags?: Json
          affected_packages?: Json
          vulnerable_versions?: Json
          fixed_versions?: Json
          dependency_chain?: Json
          analyzer?: string | null
          raw_output?: Json | null
          false_positive?: boolean
          created_at?: string
        }
      }
      reports: {
        Row: {
          id: number
          scan_id: number
          project_id: number
          user_id: string
          report_type: string
          title: string
          summary: string | null
          recommendations: string | null
          compliance_status: Json
          executive_summary: string | null
          technical_details: Json
          file_path: string | null
          created_at: string
        }
        Insert: {
          id?: number
          scan_id: number
          project_id: number
          user_id: string
          report_type: string
          title: string
          summary?: string | null
          recommendations?: string | null
          compliance_status?: Json
          executive_summary?: string | null
          technical_details?: Json
          file_path?: string | null
          created_at?: string
        }
        Update: {
          id?: number
          scan_id?: number
          project_id?: number
          user_id?: string
          report_type?: string
          title?: string
          summary?: string | null
          recommendations?: string | null
          compliance_status?: Json
          executive_summary?: string | null
          technical_details?: Json
          file_path?: string | null
          created_at?: string
        }
      }
      user_profiles: {
        Row: {
          id: string
          full_name: string | null
          avatar_url: string | null
          organization: string | null
          role: string | null
          preferences: Json
          created_at: string
          updated_at: string
        }
        Insert: {
          id: string
          full_name?: string | null
          avatar_url?: string | null
          organization?: string | null
          role?: string | null
          preferences?: Json
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          full_name?: string | null
          avatar_url?: string | null
          organization?: string | null
          role?: string | null
          preferences?: Json
          created_at?: string
          updated_at?: string
        }
      }
    }
    Views: {
      [_ in never]: never
    }
    Functions: {
      [_ in never]: never
    }
    Enums: {
      scan_status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled'
      scan_type: 'security' | 'quality' | 'performance' | 'launch_ready' | 'full'
      severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
    }
    CompositeTypes: {
      [_ in never]: never
    }
  }
}