'use client'

import React, { useState } from 'react'
import { Shield, Search, Globe, Hash, Server, AlertOctagon, CheckCircle2, HelpCircle } from 'lucide-react'
import { toast } from 'sonner'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Badge } from '@/components/ui/Badge'
import { apiClient } from '@/lib/api'

export default function ThreatIntelligencePage() {
  const [lookupType, setLookupType] = useState<'url' | 'hash' | 'domain' | 'ip'>('url')
  const [queryValue, setQueryValue] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [results, setResults] = useState<any[] | null>(null)

  const handleLookup = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!queryValue.trim()) return

    setIsLoading(true)
    setResults(null)
    try {
      const endpoint = `/intelligence/lookup/${lookupType}`
      const body = {
        [lookupType === 'hash' ? 'sha256' : lookupType]: queryValue.trim(),
      }
      const res = await apiClient.post(endpoint, body)
      setResults(res.data.data.results || [])
      toast.success('Threat intelligence lookup complete')
    } catch {
      toast.error('Lookup request failed')
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      <Card className="border-navy-600 bg-navy-800 shadow-xl">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="w-5 h-5 text-accent-cyan" />
            <span>Threat Intelligence Manual Query Engine</span>
          </CardTitle>
          <p className="text-xs text-slate-400 mt-1">
            Perform safe, isolated lookups for suspicious URLs, file hashes, domains, and IP addresses.
          </p>
        </CardHeader>

        <CardContent>
          {/* Query Type Switcher */}
          <div className="flex bg-navy-900 p-1 rounded-xl border border-navy-700 w-fit mb-6">
            {[
              { id: 'url', label: 'URL Query', icon: Globe },
              { id: 'hash', label: 'File Hash (SHA-256)', icon: Hash },
              { id: 'domain', label: 'Domain Intelligence', icon: Shield },
              { id: 'ip', label: 'IP Address', icon: Server },
            ].map((tab) => {
              const Icon = tab.icon
              const isSelected = lookupType === tab.id
              return (
                <button
                  key={tab.id}
                  onClick={() => {
                    setLookupType(tab.id as any)
                    setResults(null)
                  }}
                  className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-medium transition-all ${
                    isSelected
                      ? 'bg-accent-cyan text-navy-950 font-bold shadow'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <Icon className="w-4 h-4" />
                  <span>{tab.label}</span>
                </button>
              )
            })}
          </div>

          {/* Form */}
          <form onSubmit={handleLookup} className="flex gap-3 mb-8">
            <input
              type="text"
              required
              value={queryValue}
              onChange={(e) => setQueryValue(e.target.value)}
              placeholder={
                lookupType === 'url'
                  ? 'https://login-verify-account.example.com/auth'
                  : lookupType === 'hash'
                  ? 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
                  : lookupType === 'domain'
                  ? 'secure-banking-update.net'
                  : '198.51.100.24'
              }
              className="flex-1 bg-navy-900 border border-navy-600 rounded-xl px-4 py-2.5 font-mono text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-accent-cyan"
            />
            <Button type="submit" isLoading={isLoading}>
              <Search className="w-4 h-4" /> Run Query
            </Button>
          </form>

          {/* Results Display */}
          {results && (
            <div className="space-y-4">
              <h4 className="text-xs font-mono uppercase tracking-wider text-slate-400">
                Threat Intelligence Results ({results.length} Provider Reports)
              </h4>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {results.map((r, idx) => (
                  <div
                    key={idx}
                    className="bg-navy-850 border border-navy-600 rounded-xl p-5 space-y-3"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-xs uppercase font-bold text-accent-cyan">
                        {r.provider}
                      </span>
                      {r.is_demo && <Badge variant="warning">DEMO TELEMETRY</Badge>}
                    </div>

                    <div className="flex items-center gap-3">
                      {r.is_malicious ? (
                        <div className="flex items-center gap-2 text-red-400 text-sm font-bold">
                          <AlertOctagon className="w-5 h-5" />
                          <span>MALICIOUS DETECTED</span>
                        </div>
                      ) : r.is_malicious === false ? (
                        <div className="flex items-center gap-2 text-green-400 text-sm font-bold">
                          <CheckCircle2 className="w-5 h-5" />
                          <span>NO THREAT IDENTIFIED</span>
                        </div>
                      ) : (
                        <div className="flex items-center gap-2 text-slate-400 text-sm">
                          <HelpCircle className="w-5 h-5" />
                          <span>UNRATED / UNKNOWN</span>
                        </div>
                      )}
                    </div>

                    {r.detections !== null && r.detections !== undefined && (
                      <p className="text-xs font-mono text-slate-300">
                        Engine Detections: <span className="font-bold text-accent-blue">{r.detections}</span> / {r.total_engines || '75'}
                      </p>
                    )}

                    {r.tags && r.tags.length > 0 && (
                      <div className="flex flex-wrap gap-1.5 pt-1">
                        {r.tags.map((t: string, tIdx: number) => (
                          <Badge key={tIdx} variant="outline" className="text-[10px]">
                            {t}
                          </Badge>
                        ))}
                      </div>
                    )}

                    {r.error && (
                      <p className="text-xs text-yellow-400/90 font-mono">Notice: {r.error}</p>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
