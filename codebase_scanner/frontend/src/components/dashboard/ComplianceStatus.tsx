import React, { useEffect, useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Button } from '@/components/ui/button';
import { FileCheck, AlertCircle, CheckCircle } from 'lucide-react';
import { useApi } from '@/hooks/useApi';

interface ComplianceStatusProps {
  scanId?: string;
}

export function ComplianceStatus({ scanId }: ComplianceStatusProps) {
  const [compliance, setCompliance] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  const assessCompliance = async () => {
    if (!scanId) return;

    setLoading(true);
    try {
      // TODO: Implement actual API call
      // const response = await fetch(`/api/compliance/assess/${scanId}`);
      // const data = await response.json();
      // setCompliance(data);
      
      // Mock data for now
      setCompliance({
        frameworks: [
          { name: 'OWASP Top 10', score: 85, status: 'passed' },
          { name: 'PCI DSS', score: 72, status: 'partial' },
        ],
        overall_score: 78,
      });
    } catch (error) {
      console.error('Failed to assess compliance:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (scanId) {
      assessCompliance();
    }
  }, [scanId]);

  if (!scanId) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Compliance Status</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground">
            Run a scan to check compliance status
          </p>
        </CardContent>
      </Card>
    );
  }

  if (loading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Compliance Status</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-center h-32">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
          </div>
        </CardContent>
      </Card>
    );
  }

  if (!compliance) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Compliance Status</CardTitle>
        </CardHeader>
        <CardContent>
          <Button onClick={assessCompliance} className="w-full">
            <FileCheck className="mr-2 h-4 w-4" />
            Check Compliance
          </Button>
        </CardContent>
      </Card>
    );
  }

  const overallScore = compliance.summary?.overall_compliance_score || 0;
  const frameworkDetails = compliance.framework_details || {};

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center justify-between">
          Compliance Status
          {overallScore >= 80 ? (
            <CheckCircle className="h-5 w-5 text-green-600" />
          ) : (
            <AlertCircle className="h-5 w-5 text-yellow-600" />
          )}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="text-center">
          <div className="text-3xl font-bold">{overallScore}%</div>
          <div className="text-sm text-muted-foreground">Overall Compliance Score</div>
        </div>

        <div className="space-y-3">
          {Object.entries(frameworkDetails).map(([framework, details]: [string, any]) => (
            <div key={framework} className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium">{framework.replace('_', ' ')}</span>
                <Badge variant={details.status === 'compliant' ? 'success' : 'warning'}>
                  {details.status}
                </Badge>
              </div>
              <Progress value={details.coverage?.percentage || 0} className="h-2" />
              <div className="text-xs text-muted-foreground">
                {details.coverage?.covered || 0} of {details.coverage?.total || 0} requirements met
              </div>
            </div>
          ))}
        </div>

        {compliance.priority_actions && compliance.priority_actions.length > 0 && (
          <div className="pt-2 border-t">
            <h4 className="text-sm font-medium mb-2">Priority Actions</h4>
            <ul className="space-y-1">
              {compliance.priority_actions.slice(0, 2).map((action: any, index: number) => (
                <li key={index} className="text-xs text-muted-foreground flex items-start">
                  <span className="mr-1">•</span>
                  <span>{action.action}</span>
                </li>
              ))}
            </ul>
          </div>
        )}

        <Button onClick={assessCompliance} variant="secondary" size="sm" className="w-full">
          <FileCheck className="mr-2 h-3 w-3" />
          Refresh Assessment
        </Button>
      </CardContent>
    </Card>
  );
}