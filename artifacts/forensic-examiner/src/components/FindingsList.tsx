import React from 'react';
import { Finding, FindingSeverity } from '@workspace/api-client-react';
import { AlertCircle, AlertTriangle, Info, ShieldAlert, Shield } from 'lucide-react';

interface FindingsListProps {
  findings: Finding[];
}

const severityConfig: Record<FindingSeverity, { label: string; icon: React.ElementType; classes: string }> = {
  critical: {
    label: 'CRITICAL',
    icon: ShieldAlert,
    classes: 'bg-destructive/10 text-destructive border-destructive/20',
  },
  high: {
    label: 'HIGH',
    icon: AlertTriangle,
    classes: 'bg-orange-500/10 text-orange-500 border-orange-500/20',
  },
  medium: {
    label: 'MEDIUM',
    icon: AlertCircle,
    classes: 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20',
  },
  low: {
    label: 'LOW',
    icon: Shield,
    classes: 'bg-blue-500/10 text-blue-500 border-blue-500/20',
  },
  info: {
    label: 'INFO',
    icon: Info,
    classes: 'bg-secondary text-muted-foreground border-border',
  },
};

const severityRank: Record<FindingSeverity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export function FindingsList({ findings }: FindingsListProps) {
  if (!findings || findings.length === 0) {
    return (
      <div className="p-8 text-center border border-dashed border-border rounded-lg bg-card/50">
        <p className="text-muted-foreground font-mono text-sm">No anomalous findings detected in the document.</p>
      </div>
    );
  }

  const sortedFindings = [...findings].sort((a, b) => severityRank[a.severity] - severityRank[b.severity]);

  return (
    <div className="space-y-3">
      {sortedFindings.map((finding, idx) => {
        const config = severityConfig[finding.severity];
        const Icon = config.icon;

        return (
          <div key={idx} className="flex gap-4 p-4 border border-border rounded-lg bg-card hover:bg-secondary/10 transition-colors">
            <div className="shrink-0 mt-0.5">
              <div className={`p-2 rounded-md ${config.classes}`}>
                <Icon className="w-5 h-5" />
              </div>
            </div>
            <div className="flex-1 space-y-1.5">
              <div className="flex items-center justify-between gap-4">
                <h4 className="font-semibold text-foreground">{finding.title}</h4>
                <div className="flex items-center gap-2">
                  <span className="text-[10px] uppercase font-mono tracking-widest text-muted-foreground">
                    {finding.category}
                  </span>
                  <span className={`text-[10px] px-2 py-0.5 rounded-sm uppercase font-mono tracking-widest border ${config.classes}`}>
                    {config.label}
                  </span>
                </div>
              </div>
              <p className="text-sm text-muted-foreground leading-relaxed">
                {finding.description}
              </p>
            </div>
          </div>
        );
      })}
    </div>
  );
}
