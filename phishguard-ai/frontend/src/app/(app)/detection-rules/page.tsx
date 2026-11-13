'use client'

import React, { useEffect, useState } from 'react'
import Link from 'next/link'
import { Zap, Plus, Search, RefreshCw, ShieldCheck, ToggleLeft, ToggleRight, Lock, Key, ArrowRight } from 'lucide-react'
import { toast } from 'sonner'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Badge } from '@/components/ui/Badge'
import { EmptyState } from '@/components/ui/EmptyState'
import { apiClient } from '@/lib/api'
import { useAuthStore } from '@/store/authStore'
import { cn } from '@/lib/utils'

interface Rule {
  id: string
  name: string
  description?: string
  category: string
  rule_type: string
  severity: string
  score_impact: number
  is_enabled: boolean
  is_global: boolean
  created_at: string
}

export default function DetectionRulesPage() {
  const { user } = useAuthStore()
  const isAdmin = user?.role === 'super_admin' || user?.role === 'security_admin'

  const [rules, setRules] = useState<Rule[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [showModal, setShowModal] = useState(false)
  const [hasCustomRuleGrant, setHasCustomRuleGrant] = useState(false)

  // Form states
  const [name, setName] = useState('')
  const [category, setCategory] = useState('phishing_language')
  const [ruleType, setRuleType] = useState('keyword')
  const [keywordPattern, setKeywordPattern] = useState('')
  const [scoreImpact, setScoreImpact] = useState(15)

  const fetchRules = async () => {
    setIsLoading(true)
    try {
      const res = await apiClient.get('/rules')
      setRules(res.data.data || [])

      // Check if user has approved feature for custom rules
      const catRes = await apiClient.get('/feature-approvals/catalog')
      const customRuleFeat = catRes.data?.data?.features?.find(
        (f: any) => f.key === 'custom_detection_rules'
      )
      if (customRuleFeat?.can_access) {
        setHasCustomRuleGrant(true)
      }
    } catch {
      toast.error('Failed to load detection rules')
    } finally {
      setIsLoading(false)
    }
  }

  useEffect(() => {
    fetchRules()
  }, [])

  const canAuthorRules = isAdmin || hasCustomRuleGrant

  const handleToggle = async (rule: Rule) => {
    if (!canAuthorRules) {
      toast.error('Rule modification requires Super Admin approval. Request access in Settings.')
      return
    }
    try {
      await apiClient.put(`/rules/${rule.id}`, { is_enabled: !rule.is_enabled })
      setRules((prev) =>
        prev.map((r) => (r.id === rule.id ? { ...r, is_enabled: !r.is_enabled } : r))
      )
      toast.success(`Rule "${rule.name}" ${!rule.is_enabled ? 'enabled' : 'disabled'}`)
    } catch {
      toast.error('Failed to update rule status')
    }
  }

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!canAuthorRules) {
      toast.error('Custom rule authoring requires Super Admin approval.')
      return
    }
    try {
      await apiClient.post('/rules', {
        name,
        category,
        rule_type: ruleType,
        rule_definition: { pattern: keywordPattern },
        severity: 'high',
        score_impact: scoreImpact,
        is_enabled: true,
      })
      toast.success('Custom detection rule created and deployed')
      setShowModal(false)
      setName('')
      setKeywordPattern('')
      fetchRules()
    } catch {
      toast.error('Failed to create detection rule')
    }
  }

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      <Card className="border-navy-600 bg-navy-800 shadow-xl">
        <CardHeader>
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div>
              <CardTitle className="flex items-center gap-2">
                <Zap className="w-5 h-5 text-accent-cyan" />
                <span>Deterministic SOC Detection Rules</span>
              </CardTitle>
              <p className="text-xs text-slate-400 mt-1">
                Configurable keyword, regex, and heuristic rules executed during static email analysis pipeline.
              </p>
            </div>

            <div className="flex items-center gap-2">
              {canAuthorRules ? (
                <Button size="sm" onClick={() => setShowModal(true)}>
                  <Plus className="w-4 h-4 mr-1" /> New Rule
                </Button>
              ) : (
                <Link
                  href="/settings"
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-navy-900 hover:bg-navy-700 text-slate-300 border border-navy-700 text-xs font-medium"
                >
                  <Lock className="w-3.5 h-3.5 text-amber-400" />
                  <span>Request Rule Authoring Access</span>
                </Link>
              )}
              <Button variant="outline" size="sm" onClick={fetchRules} isLoading={isLoading}>
                <RefreshCw className="w-4 h-4" />
              </Button>
            </div>
          </div>
        </CardHeader>

        <CardContent>
          {rules.length > 0 ? (
            <div className="border border-navy-600 rounded-xl overflow-hidden">
              <table className="w-full text-left text-xs">
                <thead className="bg-navy-900 font-mono uppercase text-slate-400 border-b border-navy-600">
                  <tr>
                    <th className="py-3 px-4">Rule Name</th>
                    <th className="py-3 px-4">Category</th>
                    <th className="py-3 px-4">Type</th>
                    <th className="py-3 px-4">Severity</th>
                    <th className="py-3 px-4">Penalty Impact</th>
                    <th className="py-3 px-4 text-right">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-navy-700/60 bg-navy-800 font-mono">
                  {rules.map((r) => (
                    <tr key={r.id} className="hover:bg-navy-750/50 transition-colors">
                      <td className="py-3.5 px-4 font-semibold text-slate-200">
                        {r.name}
                        {r.is_global && (
                          <span className="ml-2 text-[10px] font-mono px-1.5 py-0.2 rounded bg-navy-900 border border-navy-700 text-slate-400">
                            Global
                          </span>
                        )}
                      </td>
                      <td className="py-3.5 px-4 text-accent-blue uppercase">{r.category}</td>
                      <td className="py-3.5 px-4 text-slate-400">{r.rule_type}</td>
                      <td className="py-3.5 px-4">
                        <Badge variant={r.severity === 'high' ? 'danger' : 'warning'}>
                          {r.severity.toUpperCase()}
                        </Badge>
                      </td>
                      <td className="py-3.5 px-4 text-accent-cyan font-bold">+{r.score_impact} pts</td>
                      <td className="py-3.5 px-4 text-right">
                        <button
                          onClick={() => handleToggle(r)}
                          disabled={!canAuthorRules}
                          className={cn(
                            'font-sans text-xs flex items-center gap-1.5 ml-auto',
                            !canAuthorRules ? 'opacity-60 cursor-not-allowed text-slate-500' : 'text-slate-300 hover:text-white'
                          )}
                          title={!canAuthorRules ? 'Requires Super Admin Approval to toggle' : 'Toggle rule'}
                        >
                          {r.is_enabled ? (
                            <>
                              <span className="w-2 h-2 rounded-full bg-emerald-400" />
                              <span className="text-emerald-400 font-bold">Active</span>
                              <ToggleRight className="w-5 h-5 text-emerald-400" />
                            </>
                          ) : (
                            <>
                              <span className="w-2 h-2 rounded-full bg-slate-500" />
                              <span className="text-slate-500">Disabled</span>
                              <ToggleLeft className="w-5 h-5 text-slate-500" />
                            </>
                          )}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <EmptyState
              title="No Detection Rules"
              description="No rules active in this organization."
            />
          )}
        </CardContent>
      </Card>

      {/* New Rule Modal */}
      {showModal && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-navy-900 border border-navy-600 rounded-2xl max-w-lg w-full p-6 space-y-4 shadow-2xl">
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <Zap className="w-4 h-4 text-accent-cyan" />
              <span>Create Custom SOC Detection Rule</span>
            </h3>

            <form onSubmit={handleCreate} className="space-y-4 text-xs">
              <div>
                <label className="block text-slate-300 font-semibold mb-1">Rule Name</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Wire Fraud Keywords"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  className="w-full bg-navy-950 border border-navy-700 rounded-xl p-2.5 text-white focus:outline-none focus:border-accent-blue"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-300 font-semibold mb-1">Category</label>
                  <select
                    value={category}
                    onChange={(e) => setCategory(e.target.value)}
                    className="w-full bg-navy-950 border border-navy-700 rounded-xl p-2.5 text-white focus:outline-none focus:border-accent-blue"
                  >
                    <option value="phishing_language">Phishing Language</option>
                    <option value="spoofing">Spoofing / Impersonation</option>
                    <option value="url_threat">URL Maliciousness</option>
                    <option value="attachment_threat">Attachment Threat</option>
                    <option value="auth_failure">Authentication Failure</option>
                  </select>
                </div>

                <div>
                  <label className="block text-slate-300 font-semibold mb-1">Rule Type</label>
                  <select
                    value={ruleType}
                    onChange={(e) => setRuleType(e.target.value)}
                    className="w-full bg-navy-950 border border-navy-700 rounded-xl p-2.5 text-white focus:outline-none focus:border-accent-blue"
                  >
                    <option value="keyword">Keyword Matching</option>
                    <option value="regex">Regular Expression</option>
                    <option value="heuristic">Heuristic Signature</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-slate-300 font-semibold mb-1">
                  Pattern / Expression
                </label>
                <input
                  type="text"
                  required
                  placeholder="e.g. urgent payment, remittance required, account suspended"
                  value={keywordPattern}
                  onChange={(e) => setKeywordPattern(e.target.value)}
                  className="w-full bg-navy-950 border border-navy-700 rounded-xl p-2.5 text-white font-mono focus:outline-none focus:border-accent-blue"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-semibold mb-1">
                  Penalty Impact Score (+{scoreImpact} points)
                </label>
                <input
                  type="range"
                  min="5"
                  max="40"
                  step="5"
                  value={scoreImpact}
                  onChange={(e) => setScoreImpact(Number(e.target.value))}
                  className="w-full accent-accent-blue cursor-pointer"
                />
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <Button type="button" variant="ghost" size="sm" onClick={() => setShowModal(false)}>
                  Cancel
                </Button>
                <Button type="submit" size="sm">
                  Deploy Rule
                </Button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}
