import React from 'react';
import { ShieldCheck, ShieldMinus, AlertTriangle, ShieldAlert, HelpCircle } from 'lucide-react';
import { DocumentAnalysisVerdict } from '@workspace/api-client-react';

interface VerdictBadgeProps {
  verdict?: DocumentAnalysisVerdict | null;
  className?: string;
}

export function VerdictBadge({ verdict, className = '' }: VerdictBadgeProps) {
  if (!verdict) return null;

  switch (verdict) {
    case 'strong_match':
      return (
        <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-sm text-xs font-mono font-medium bg-authentic/10 text-authentic border border-authentic/20 ${className}`}>
          <ShieldCheck className="w-3.5 h-3.5" />
          STRONG MATCH
        </span>
      );
    case 'partial_match':
      return (
        <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-sm text-xs font-mono font-medium bg-primary/10 text-primary border border-primary/20 ${className}`}>
          <ShieldMinus className="w-3.5 h-3.5" />
          PARTIAL MATCH
        </span>
      );
    case 'weak_match':
      return (
        <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-sm text-xs font-mono font-medium bg-suspicious/10 text-suspicious border border-suspicious/20 ${className}`}>
          <AlertTriangle className="w-3.5 h-3.5" />
          WEAK MATCH
        </span>
      );
    case 'inconsistent':
      return (
        <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-sm text-xs font-mono font-medium bg-forged/10 text-forged border border-forged/20 ${className}`}>
          <ShieldAlert className="w-3.5 h-3.5" />
          CLEARLY INCONSISTENT
        </span>
      );
    case 'inconclusive':
      return (
        <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-sm text-xs font-mono font-medium bg-inconclusive/10 text-inconclusive border border-inconclusive/20 ${className}`}>
          <HelpCircle className="w-3.5 h-3.5" />
          INCONCLUSIVE
        </span>
      );
  }
}
