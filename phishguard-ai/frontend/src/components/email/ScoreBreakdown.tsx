import React from 'react'
import { AlertCircle, HelpCircle, ShieldAlert } from 'lucide-react'
import { Badge } from '@/components/ui/Badge'
import type { ScoreSignal } from '@/types'

export function ScoreBreakdown({
  signals,
  explanation,
  missingEvidence,
}: {
  signals?: ScoreSignal[]
  explanation?: string
  missingEvidence?: string[]
}) {
  return (
    <div className="space-y-6">
      {/* Plain text explainability banner */}
      {explanation && (
        <div className="bg-navy-900 border border-navy-600 rounded-xl p-4 flex gap-3 text-sm text-slate-300 leading-relaxed">
          <ShieldAlert className="w-5 h-5 text-accent-blue shrink-0 mt-0.5" />
          <div>
            <span className="font-semibold text-slate-200 block mb-1">
              Scoring Rationale & Explainability:
            </span>
            {explanation}
          </div>
        </div>
      )}

      {/* Signal breakdown table */}
      <div className="border border-navy-600 rounded-xl overflow-hidden">
        <table className="w-full text-left text-sm">
          <thead className="bg-navy-900 text-xs font-mono uppercase text-slate-400 border-b border-navy-600">
            <tr>
              <th className="py-3 px-4">Contributing Signal</th>
              <th className="py-3 px-4">Confidence</th>
              <th className="py-3 px-4">Detection Reason</th>
              <th className="py-3 px-4 text-right">Points Impact</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-navy-600/50 bg-navy-800">
            {signals && signals.length > 0 ? (
              signals.map((sig, idx) => (
                <tr key={idx} className="hover:bg-navy-750/50 transition-colors">
                  <td className="py-3 px-4 font-mono font-medium text-slate-200">
                    {sig.name}
                  </td>
                  <td className="py-3 px-4">
                    <Badge
                      variant={
                        sig.confidence === 'confirmed'
                          ? 'danger'
                          : sig.confidence === 'suspicious'
                          ? 'warning'
                          : 'default'
                      }
                    >
                      {sig.confidence}
                    </Badge>
                  </td>
                  <td className="py-3 px-4 text-slate-400 text-xs max-w-md">
                    {sig.reason}
                  </td>
                  <td className="py-3 px-4 text-right font-mono font-bold text-accent-blue">
                    +{sig.applied_score}
                  </td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan={4} className="py-6 text-center text-slate-500">
                  No anomalous penalty signals fired for this email.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Missing evidence notes */}
      {missingEvidence && missingEvidence.length > 0 && (
        <div className="bg-navy-850 border border-yellow-500/20 rounded-xl p-4 flex gap-3 text-xs text-yellow-400/90">
          <HelpCircle className="w-4 h-4 shrink-0 mt-0.5 text-yellow-400" />
          <div>
            <span className="font-semibold text-yellow-300 block mb-0.5">
              Missing Evidence Gaps:
            </span>
            <ul className="list-disc list-inside space-y-0.5 text-slate-400">
              {missingEvidence.map((gap, i) => (
                <li key={i}>{gap}</li>
              ))}
            </ul>
          </div>
        </div>
      )}
    </div>
  )
}
