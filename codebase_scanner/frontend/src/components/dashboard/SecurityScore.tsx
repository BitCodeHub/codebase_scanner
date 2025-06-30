import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Progress } from '@/components/ui/progress';
import { Shield, ShieldAlert, ShieldCheck, ShieldX } from 'lucide-react';

interface SecurityScoreProps {
  score: number;
  severityCounts: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
}

export function SecurityScore({ score, severityCounts }: SecurityScoreProps) {
  const getGrade = (score: number) => {
    if (score >= 90) return { grade: 'A+', color: 'text-green-600' };
    if (score >= 80) return { grade: 'A', color: 'text-green-500' };
    if (score >= 70) return { grade: 'B', color: 'text-yellow-600' };
    if (score >= 60) return { grade: 'C', color: 'text-yellow-500' };
    if (score >= 50) return { grade: 'D', color: 'text-orange-500' };
    return { grade: 'F', color: 'text-red-600' };
  };

  const getRiskLevel = (score: number) => {
    if (score >= 90) return { level: 'Very Low', icon: ShieldCheck, color: 'text-green-600' };
    if (score >= 70) return { level: 'Low', icon: Shield, color: 'text-green-500' };
    if (score >= 50) return { level: 'Medium', icon: ShieldAlert, color: 'text-yellow-500' };
    if (score >= 30) return { level: 'High', icon: ShieldAlert, color: 'text-orange-500' };
    return { level: 'Critical', icon: ShieldX, color: 'text-red-600' };
  };

  const { grade, color: gradeColor } = getGrade(score);
  const { level, icon: RiskIcon, color: riskColor } = getRiskLevel(score);

  const totalVulns = Object.values(severityCounts).reduce((a, b) => a + b, 0);

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center justify-between">
          Security Score
          <RiskIcon className={`h-5 w-5 ${riskColor}`} />
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="text-center">
          <div className={`text-5xl font-bold ${gradeColor}`}>{grade}</div>
          <div className="text-2xl font-semibold mt-2">{score}%</div>
          <div className={`text-sm ${riskColor} mt-1`}>Risk Level: {level}</div>
        </div>

        <Progress value={score} className="h-3" />

        <div className="space-y-2 text-sm">
          <div className="flex justify-between">
            <span>Total Vulnerabilities:</span>
            <span className="font-semibold">{totalVulns}</span>
          </div>
          {severityCounts.critical > 0 && (
            <div className="flex justify-between text-red-600">
              <span>Critical Issues:</span>
              <span className="font-semibold">{severityCounts.critical}</span>
            </div>
          )}
          {severityCounts.high > 0 && (
            <div className="flex justify-between text-orange-600">
              <span>High Severity:</span>
              <span className="font-semibold">{severityCounts.high}</span>
            </div>
          )}
        </div>

        <div className="pt-2 border-t">
          <p className="text-xs text-muted-foreground">
            {score >= 80
              ? 'Your code has good security practices. Keep it up!'
              : score >= 60
              ? 'Some security improvements needed. Review high-priority issues.'
              : 'Significant security issues detected. Immediate action recommended.'}
          </p>
        </div>
      </CardContent>
    </Card>
  );
}