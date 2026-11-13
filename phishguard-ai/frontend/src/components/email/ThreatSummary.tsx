import React from 'react'
import { ShieldCheck, ShieldAlert, AlertTriangle, Link2, Paperclip, Search, UserX } from 'lucide-react'
import { RiskScore } from '@/components/ui/RiskScore'
import { Badge } from '@/components/ui/Badge'
import type { EmailAnalysis } from '@/types'

export function ThreatSummary({ analysis }: { analysis: EmailAnalysis }) {
  const getAuthBadgeVariant = (val?: string) => {
    if (!val) return 'outline'
    const lower = val.toLowerCase()
    if (lower === 'pass') return 'success'
    if (lower === 'fail' || lower === 'softfail') return 'critical'
    return 'warning'
  }

  return (
    <div className="bg-navy-800 border border-navy-600 rounded-xl p-6 shadow-xl">
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6 items-center">
        {/* Risk Score Gauge */}
        <div className="flex flex-col items-center justify-center border-b md:border-b-0 md:border-r border-navy-600/70 pb-4 md:pb-0 md:pr-6">
          <RiskScore
            score={analysis.risk_score}
            classification={analysis.risk_classification}
            size="lg"
          />
        </div>

        {/* Auth & Alignment telemetry */}
        <div className="md:col-span-2 space-y-4">
          <div>
            <h4 className="text-xs uppercase font-mono tracking-wider text-slate-400 mb-2">
              Email Authentication Signals
            </h4>
            <div className="flex flex-wrap items-center gap-2.5">
              <div className="flex items-center gap-1.5 px-3 py-1 bg-navy-900 border border-navy-600 rounded-lg text-xs">
                <span className="font-mono text-slate-400">SPF:</span>
                <Badge variant={getAuthBadgeVariant(analysis.spf_result)}>
                  {analysis.spf_result?.toUpperCase() || 'NONE'}
                </Badge>
              </div>

              <div className="flex items-center gap-1.5 px-3 py-1 bg-navy-900 border border-navy-600 rounded-lg text-xs">
                <span className="font-mono text-slate-400">DKIM:</span>
                <Badge variant={getAuthBadgeVariant(analysis.dkim_result)}>
                  {analysis.dkim_result?.toUpperCase() || 'NONE'}
                </Badge>
              </div>

              <div className="flex items-center gap-1.5 px-3 py-1 bg-navy-900 border border-navy-600 rounded-lg text-xs">
                <span className="font-mono text-slate-400">DMARC:</span>
                <Badge variant={getAuthBadgeVariant(analysis.dmarc_result)}>
                  {analysis.dmarc_result?.toUpperCase() || 'NONE'}
                </Badge>
              </div>
            </div>
          </div>

          {/* Spoofing warnings */}
          <div className="flex flex-wrap gap-2 pt-1">
            {analysis.display_name_spoofing && (
              <Badge variant="critical">
                <UserX className="w-3 h-3" /> Display Name Spoofing Detected
              </Badge>
            )}
            {analysis.sender_domain_mismatch && (
              <Badge variant="danger">
                <AlertTriangle className="w-3 h-3" /> Sender Domain Mismatch
              </Badge>
            )}
            {analysis.reply_to_mismatch && (
              <Badge variant="warning">
                <AlertTriangle className="w-3 h-3" /> Reply-To Discrepancy
              </Badge>
            )}
            {!analysis.display_name_spoofing && !analysis.sender_domain_mismatch && (
              <Badge variant="success">
                <ShieldCheck className="w-3 h-3" /> Sender Identity Consistent
              </Badge>
            )}
          </div>
        </div>

        {/* Artifact counters */}
        <div className="grid grid-cols-3 md:grid-cols-1 gap-3 border-t md:border-t-0 md:border-l border-navy-600/70 pt-4 md:pt-0 md:pl-6 text-center md:text-left">
          <div className="flex items-center gap-2">
            <Link2 className="w-4 h-4 text-accent-cyan shrink-0" />
            <div>
              <p className="text-xs text-slate-400">URLs Analyzed</p>
              <p className="text-sm font-bold text-slate-200">
                {analysis.url_count}
                {analysis.malicious_url_count > 0 && (
                  <span className="text-red-400 text-xs font-normal ml-1">
                    ({analysis.malicious_url_count} malicious)
                  </span>
                )}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <Paperclip className="w-4 h-4 text-accent-blue shrink-0" />
            <div>
              <p className="text-xs text-slate-400">Attachments</p>
              <p className="text-sm font-bold text-slate-200">
                {analysis.attachment_count}
                {analysis.malicious_attachment_count > 0 && (
                  <span className="text-red-400 text-xs font-normal ml-1">
                    ({analysis.malicious_attachment_count} risky)
                  </span>
                )}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <Search className="w-4 h-4 text-green-400 shrink-0" />
            <div>
              <p className="text-xs text-slate-400">Extracted IOCs</p>
              <p className="text-sm font-bold text-slate-200">{analysis.ioc_count}</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
