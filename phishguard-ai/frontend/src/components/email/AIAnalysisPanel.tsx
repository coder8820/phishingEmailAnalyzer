import React from 'react'
import { Bot, CheckCircle2, AlertOctagon, HelpCircle, Shield, ListChecks, Quote } from 'lucide-react'
import { Badge } from '@/components/ui/Badge'
import type { AIFinding } from '@/types'

export function AIAnalysisPanel({
  summary,
  assessment,
  confidence,
  findings,
  recommendedActions,
  provider,
  model,
  isAvailable,
}: {
  summary?: string
  assessment?: string
  confidence?: string
  findings?: AIFinding[]
  recommendedActions?: string[]
  provider?: string
  model?: string
  isAvailable?: boolean
}) {
  if (!isAvailable) {
    return (
      <div className="bg-navy-850 border border-navy-600 rounded-xl p-8 text-center space-y-3">
        <Bot className="w-10 h-10 text-slate-500 mx-auto" />
        <h4 className="text-base font-semibold text-slate-300">
          AI Analysis Engine Offline / Unavailable
        </h4>
        <p className="text-sm text-slate-400 max-w-md mx-auto">
          AI provider credentials have not been configured or the provider service is unreachable. Deterministic security and rule-based checks remain fully functional.
        </p>
      </div>
    )
  }

  const assessmentStyles = {
    phishing: {
      color: 'text-red-400',
      bg: 'bg-red-500/10 border-red-500/30',
      icon: <AlertOctagon className="w-5 h-5 text-red-400" />,
      label: 'PHISHING DETECTED',
    },
    suspicious: {
      color: 'text-yellow-400',
      bg: 'bg-yellow-500/10 border-yellow-500/30',
      icon: <HelpCircle className="w-5 h-5 text-yellow-400" />,
      label: 'SUSPICIOUS COMMUNICATION',
    },
    legitimate: {
      color: 'text-green-400',
      bg: 'bg-green-500/10 border-green-500/30',
      icon: <CheckCircle2 className="w-5 h-5 text-green-400" />,
      label: 'LIKELY BENIGN',
    },
  }[assessment?.toLowerCase() || 'suspicious'] || {
    color: 'text-slate-400',
    bg: 'bg-navy-900 border-navy-600',
    icon: <Shield className="w-5 h-5" />,
    label: 'UNKNOWN',
  }

  return (
    <div className="space-y-6">
      {/* Assessment Header */}
      <div className={`p-5 rounded-xl border flex flex-col md:flex-row md:items-center justify-between gap-4 ${assessmentStyles.bg}`}>
        <div className="flex items-center gap-3">
          {assessmentStyles.icon}
          <div>
            <span className={`text-base font-bold tracking-wide uppercase ${assessmentStyles.color}`}>
              {assessmentStyles.label}
            </span>
            <p className="text-xs text-slate-400 mt-0.5">
              Confidence level: <span className="font-semibold text-slate-200">{confidence?.toUpperCase() || 'MEDIUM'}</span>
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono text-slate-400 bg-navy-900/60 px-3 py-1.5 rounded-lg border border-navy-700">
          <Bot className="w-4 h-4 text-accent-cyan" />
          <span>{provider ? `${provider.toUpperCase()} (${model || 'DEFAULT'})` : 'AI GUARD'}</span>
        </div>
      </div>

      {/* Summary Narrative */}
      {summary && (
        <div className="bg-navy-800 border border-navy-600 rounded-xl p-5">
          <h4 className="text-xs font-mono uppercase tracking-wider text-slate-400 mb-2">
            Contextual Threat Summary
          </h4>
          <p className="text-sm text-slate-200 leading-relaxed">{summary}</p>
        </div>
      )}

      {/* Specific AI Findings */}
      {findings && findings.length > 0 && (
        <div className="space-y-3">
          <h4 className="text-xs font-mono uppercase tracking-wider text-slate-400">
            Psychological & Social Engineering Observations
          </h4>
          <div className="grid grid-cols-1 gap-3">
            {findings.map((f, idx) => (
              <div key={idx} className="bg-navy-800 border border-navy-600/80 rounded-xl p-4 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-xs uppercase font-bold text-accent-blue tracking-wide">
                    {f.category.replace('_', ' ')}
                  </span>
                  <Badge variant={f.severity === 'critical' ? 'critical' : f.severity === 'high' ? 'danger' : 'warning'}>
                    {f.severity.toUpperCase()} SEVERITY
                  </Badge>
                </div>
                <p className="text-sm text-slate-300">{f.description}</p>
                {f.evidence_quotes && f.evidence_quotes.length > 0 && (
                  <div className="pt-1">
                    {f.evidence_quotes.map((q, qIdx) => (
                      <div key={qIdx} className="flex items-start gap-2 text-xs font-mono text-slate-400 bg-navy-900 p-2 rounded border border-navy-700">
                        <Quote className="w-3.5 h-3.5 text-accent-cyan shrink-0 mt-0.5" />
                        <span>{q}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Recommended SOC Actions */}
      {recommendedActions && recommendedActions.length > 0 && (
        <div className="bg-navy-800 border border-navy-600 rounded-xl p-5">
          <div className="flex items-center gap-2 text-xs font-mono uppercase tracking-wider text-accent-cyan mb-3">
            <ListChecks className="w-4 h-4" />
            <span>Recommended Incident Response Actions</span>
          </div>
          <ol className="list-decimal list-inside space-y-2 text-sm text-slate-300">
            {recommendedActions.map((action, i) => (
              <li key={i} className="leading-relaxed">
                <span className="font-medium text-slate-100">{action}</span>
              </li>
            ))}
          </ol>
        </div>
      )}
    </div>
  )
}
