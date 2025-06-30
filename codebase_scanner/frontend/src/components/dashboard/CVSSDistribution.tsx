import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { Info } from 'lucide-react';

interface CVSSDistributionProps {
  results: any[];
}

export function CVSSDistribution({ results }: CVSSDistributionProps) {
  // Calculate CVSS distribution
  const cvssRanges = {
    'None (0.0)': 0,
    'Low (0.1-3.9)': 0,
    'Medium (4.0-6.9)': 0,
    'High (7.0-8.9)': 0,
    'Critical (9.0-10.0)': 0,
  };

  let totalCVSS = 0;
  let cvssCount = 0;

  results.forEach((result) => {
    const score = result.cvss_score || result.cvss?.base_score || 0;
    if (score > 0) {
      totalCVSS += score;
      cvssCount++;

      if (score === 0) cvssRanges['None (0.0)']++;
      else if (score < 4.0) cvssRanges['Low (0.1-3.9)']++;
      else if (score < 7.0) cvssRanges['Medium (4.0-6.9)']++;
      else if (score < 9.0) cvssRanges['High (7.0-8.9)']++;
      else cvssRanges['Critical (9.0-10.0)']++;
    }
  });

  const avgCVSS = cvssCount > 0 ? (totalCVSS / cvssCount).toFixed(1) : 0;

  const data = Object.entries(cvssRanges).map(([range, count]) => ({
    range,
    count,
    severity: range.split(' ')[0].toLowerCase(),
  }));

  const getBarColor = (severity: string) => {
    switch (severity) {
      case 'none':
        return '#10b981';
      case 'low':
        return '#84cc16';
      case 'medium':
        return '#f59e0b';
      case 'high':
        return '#ea580c';
      case 'critical':
        return '#dc2626';
      default:
        return '#6b7280';
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center justify-between">
          CVSS Score Distribution
          <Info className="h-4 w-4 text-muted-foreground" />
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-4">
          <div className="text-center">
            <div className="text-3xl font-bold">{avgCVSS}</div>
            <div className="text-sm text-muted-foreground">Average CVSS Score</div>
          </div>

          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={data}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis 
                dataKey="range" 
                angle={-45}
                textAnchor="end"
                height={80}
                tick={{ fontSize: 12 }}
              />
              <YAxis />
              <Tooltip />
              <Bar 
                dataKey="count" 
                fill="#8b5cf6"
                shape={(props: any) => {
                  const { x, y, width, height, payload } = props;
                  return (
                    <rect
                      x={x}
                      y={y}
                      width={width}
                      height={height}
                      fill={getBarColor(payload.severity)}
                    />
                  );
                }}
              />
            </BarChart>
          </ResponsiveContainer>

          <div className="text-xs text-muted-foreground space-y-1">
            <p>CVSS v3.1 Base Scores</p>
            <p>{cvssCount} of {results.length} vulnerabilities have CVSS scores</p>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}