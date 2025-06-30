import { useState } from 'react'
import { 
  Brain, 
  AlertCircle, 
  CheckCircle, 
  Code, 
  Shield, 
  Copy, 
  ExternalLink,
  Loader2,
  FileText,
  ChevronDown,
  ChevronRight
} from 'lucide-react'
import { supabase } from '../../lib/supabase'
import LoadingSpinner from '../ui/LoadingSpinner'

interface AIAnalysisPanelProps {
  vulnerability: any
  scanId: string
  onAnalysisComplete?: () => void
}

interface AnalysisResult {
  vulnerability_id: string
  risk_description: string
  plain_english_explanation: string
  fix_suggestions: string[]
  code_fix: string | null
  compliance_violations: Record<string, any>
  remediation_steps: string[]
  severity_justification: string
  references: string[]
  analyzed_at: string
}

export default function AIAnalysisPanel({ vulnerability, scanId, onAnalysisComplete }: AIAnalysisPanelProps) {
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [analysis, setAnalysis] = useState<AnalysisResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [showDetails, setShowDetails] = useState(false)
  const [copiedCode, setCopiedCode] = useState(false)

  const analyzeWithClaude = async () => {
    setIsAnalyzing(true)
    setError(null)

    try {
      const { analyzeSingleVulnerability } = await import('../../services/scanService')
      const result = await analyzeSingleVulnerability(vulnerability)
      setAnalysis(result)
      
      if (onAnalysisComplete) {
        onAnalysisComplete()
      }
    } catch (err: any) {
      setError(err.message || 'Failed to analyze vulnerability')
    } finally {
      setIsAnalyzing(false)
    }
  }

  const copyCode = async () => {
    if (analysis?.code_fix) {
      await navigator.clipboard.writeText(analysis.code_fix)
      setCopiedCode(true)
      setTimeout(() => setCopiedCode(false), 2000)
    }
  }

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return 'text-red-600 bg-red-50'
      case 'high': return 'text-orange-600 bg-orange-50'
      case 'medium': return 'text-yellow-600 bg-yellow-50'
      case 'low': return 'text-blue-600 bg-blue-50'
      default: return 'text-gray-600 bg-gray-50'
    }
  }

  const getComplianceIcon = (framework: string) => {
    switch (framework) {
      case 'OWASP': return '🛡️'
      case 'ISO27001': return '📋'
      case 'SOC2': return '🔒'
      case 'GDPR': return '🇪🇺'
      default: return '📌'
    }
  }

  if (!vulnerability.ai_analyzed_at && !analysis) {
    return (
      <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center">
            <Brain className="h-5 w-5 text-blue-600 mr-2" />
            <span className="text-sm font-medium text-blue-900">
              AI Analysis Available
            </span>
          </div>
          <button
            onClick={analyzeWithClaude}
            disabled={isAnalyzing}
            className="px-3 py-1.5 bg-blue-600 text-white text-sm font-medium rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            {isAnalyzing ? (
              <>
                <Loader2 className="h-4 w-4 inline mr-1 animate-spin" />
                Analyzing...
              </>
            ) : (
              'Analyze with Claude'
            )}
          </button>
        </div>
      </div>
    )
  }

  if (isAnalyzing) {
    return (
      <div className="bg-white border border-gray-200 rounded-lg p-6">
        <div className="flex flex-col items-center justify-center py-8">
          <Brain className="h-12 w-12 text-blue-600 mb-4 animate-pulse" />
          <h3 className="text-lg font-medium text-gray-900 mb-2">Analyzing with Claude AI</h3>
          <p className="text-sm text-gray-500 text-center max-w-md">
            Claude is analyzing this vulnerability to provide detailed recommendations and fixes...
          </p>
          <LoadingSpinner className="mt-4" />
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="bg-red-50 border border-red-200 rounded-lg p-4">
        <div className="flex items-center">
          <AlertCircle className="h-5 w-5 text-red-600 mr-2" />
          <span className="text-sm text-red-900">{error}</span>
        </div>
      </div>
    )
  }

  if (!analysis) return null

  return (
    <div className="bg-white border border-gray-200 rounded-lg overflow-hidden">
      {/* Header */}
      <div className="bg-gradient-to-r from-blue-600 to-indigo-600 px-6 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center">
            <Brain className="h-6 w-6 text-white mr-2" />
            <h3 className="text-lg font-semibold text-white">Claude AI Analysis</h3>
          </div>
          <span className="text-xs text-blue-100">
            Analyzed {new Date(analysis.analyzed_at).toLocaleString()}
          </span>
        </div>
      </div>

      {/* Main Content */}
      <div className="p-6 space-y-6">
        {/* Risk Description */}
        <div>
          <h4 className="text-sm font-semibold text-gray-700 mb-2 flex items-center">
            <AlertCircle className="h-4 w-4 mr-1" />
            Security Risk
          </h4>
          <p className="text-sm text-gray-600">{analysis.risk_description}</p>
        </div>

        {/* Plain English Explanation */}
        <div className="bg-blue-50 rounded-lg p-4">
          <h4 className="text-sm font-semibold text-blue-900 mb-2">
            💡 Plain English Explanation
          </h4>
          <p className="text-sm text-blue-800">{analysis.plain_english_explanation}</p>
        </div>

        {/* Severity Justification */}
        <div>
          <h4 className="text-sm font-semibold text-gray-700 mb-2">Severity Assessment</h4>
          <div className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-medium ${getSeverityColor(vulnerability.severity)}`}>
            {vulnerability.severity.toUpperCase()}
          </div>
          <p className="text-sm text-gray-600 mt-2">{analysis.severity_justification}</p>
        </div>

        {/* Fix Suggestions */}
        <div>
          <h4 className="text-sm font-semibold text-gray-700 mb-2 flex items-center">
            <CheckCircle className="h-4 w-4 mr-1" />
            Fix Suggestions
          </h4>
          <ul className="space-y-2">
            {analysis.fix_suggestions.map((suggestion, index) => (
              <li key={index} className="flex items-start">
                <span className="text-green-500 mr-2">•</span>
                <span className="text-sm text-gray-600">{suggestion}</span>
              </li>
            ))}
          </ul>
        </div>

        {/* Code Fix */}
        {analysis.code_fix && (
          <div>
            <div className="flex items-center justify-between mb-2">
              <h4 className="text-sm font-semibold text-gray-700 flex items-center">
                <Code className="h-4 w-4 mr-1" />
                Recommended Code Fix
              </h4>
              <button
                onClick={copyCode}
                className="text-sm text-blue-600 hover:text-blue-700 flex items-center"
              >
                {copiedCode ? (
                  <>
                    <CheckCircle className="h-4 w-4 mr-1" />
                    Copied!
                  </>
                ) : (
                  <>
                    <Copy className="h-4 w-4 mr-1" />
                    Copy Code
                  </>
                )}
              </button>
            </div>
            <pre className="bg-gray-900 text-gray-100 p-4 rounded-lg overflow-x-auto">
              <code className="text-sm">{analysis.code_fix}</code>
            </pre>
          </div>
        )}

        {/* Compliance Violations */}
        {Object.keys(analysis.compliance_violations).length > 0 && (
          <div>
            <h4 className="text-sm font-semibold text-gray-700 mb-2 flex items-center">
              <Shield className="h-4 w-4 mr-1" />
              Compliance Violations
            </h4>
            <div className="space-y-2">
              {Object.entries(analysis.compliance_violations).map(([framework, violation]) => (
                <div key={framework} className="bg-gray-50 rounded-lg p-3">
                  <div className="flex items-start">
                    <span className="text-lg mr-2">{getComplianceIcon(framework)}</span>
                    <div className="flex-1">
                      <h5 className="text-sm font-medium text-gray-900">{framework}</h5>
                      <p className="text-xs text-gray-600 mt-1">
                        {typeof violation === 'string' ? violation : JSON.stringify(violation)}
                      </p>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Remediation Steps */}
        <div>
          <button
            onClick={() => setShowDetails(!showDetails)}
            className="flex items-center text-sm font-semibold text-gray-700 mb-2 hover:text-gray-900"
          >
            {showDetails ? <ChevronDown className="h-4 w-4 mr-1" /> : <ChevronRight className="h-4 w-4 mr-1" />}
            Detailed Remediation Steps
          </button>
          {showDetails && (
            <ol className="space-y-2 ml-4">
              {analysis.remediation_steps.map((step, index) => (
                <li key={index} className="flex items-start">
                  <span className="text-blue-600 font-medium mr-2">{index + 1}.</span>
                  <span className="text-sm text-gray-600">{step}</span>
                </li>
              ))}
            </ol>
          )}
        </div>

        {/* References */}
        {analysis.references.length > 0 && (
          <div>
            <h4 className="text-sm font-semibold text-gray-700 mb-2 flex items-center">
              <FileText className="h-4 w-4 mr-1" />
              References
            </h4>
            <ul className="space-y-1">
              {analysis.references.map((ref, index) => (
                <li key={index}>
                  <a
                    href={ref}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-sm text-blue-600 hover:text-blue-700 flex items-center"
                  >
                    <ExternalLink className="h-3 w-3 mr-1" />
                    {ref}
                  </a>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </div>
  )
}