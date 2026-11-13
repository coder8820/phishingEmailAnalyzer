'use client'

import React, { useEffect, useState } from 'react'
import Link from 'next/link'
import { Plug, Key, CheckCircle, XCircle, ShieldCheck, RefreshCw, Lock, ArrowRight } from 'lucide-react'
import { toast } from 'sonner'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Badge } from '@/components/ui/Badge'
import { apiClient } from '@/lib/api'
import { useAuthStore } from '@/store/authStore'

interface IntegrationStatus {
  provider: string
  is_enabled: boolean
  has_api_key: boolean
  last_used_at?: string
  request_count: number
  error_count: number
  demo_mode: boolean
}

export default function IntegrationsPage() {
  const { user } = useAuthStore()
  const isAdmin = user?.role === 'super_admin' || user?.role === 'security_admin'

  const [integrations, setIntegrations] = useState<IntegrationStatus[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [modalProvider, setModalProvider] = useState<string | null>(null)
  const [apiKeyInput, setApiKeyInput] = useState('')
  const [isEnabledInput, setIsEnabledInput] = useState(true)

  const fetchIntegrations = async () => {
    if (!isAdmin) return
    setIsLoading(true)
    try {
      const res = await apiClient.get('/integrations')
      setIntegrations(res.data.data)
    } catch {
      toast.error('Failed to load integrations')
    } finally {
      setIsLoading(false)
    }
  }

  useEffect(() => {
    fetchIntegrations()
  }, [isAdmin])

  // Restrict access for Normal User
  if (!isAdmin) {
    return (
      <div className="max-w-3xl mx-auto py-16 px-4 text-center space-y-6">
        <div className="w-16 h-16 rounded-2xl bg-accent-blue/10 border border-accent-blue/30 flex items-center justify-center mx-auto text-accent-cyan shadow-xl">
          <Lock className="w-8 h-8" />
        </div>
        <div className="space-y-2">
          <Badge variant="outline" className="text-accent-cyan border-accent-blue/40">
            ADMINISTRATIVE PERIMETER CONTROL
          </Badge>
          <h1 className="text-2xl font-black text-white">Super Admin Access Required</h1>
          <p className="text-sm text-slate-400 max-w-lg mx-auto leading-relaxed">
            External Threat Intelligence credentials (VirusTotal, URLhaus, AbuseIPDB) and SIEM/SOAR API pipelines can only be configured by Super Administrators.
          </p>
        </div>
        <div className="flex flex-wrap items-center justify-center gap-3 pt-2">
          <Link
            href="/dashboard"
            className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-navy-800 hover:bg-navy-700 text-slate-200 border border-navy-600 text-xs font-semibold"
          >
            <span>Return to Dashboard</span>
          </Link>
          <Link
            href="/settings"
            className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-accent-blue hover:bg-blue-600 text-white text-xs font-semibold shadow-lg shadow-accent-blue/20"
          >
            <span>Request Integration Grant in Settings</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </Link>
        </div>
      </div>
    )
  }

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!modalProvider) return
    try {
      await apiClient.put(`/integrations/${modalProvider}`, {
        is_enabled: isEnabledInput,
        api_key: apiKeyInput ? apiKeyInput : undefined,
      })
      toast.success(`${modalProvider.toUpperCase()} configuration updated`)
      setModalProvider(null)
      setApiKeyInput('')
      fetchIntegrations()
    } catch {
      toast.error('Failed to update integration')
    }
  }

  const openConfig = (it: IntegrationStatus) => {
    setModalProvider(it.provider)
    setIsEnabledInput(it.is_enabled)
    setApiKeyInput('')
  }

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-black text-slate-100 flex items-center gap-2">
            <Plug className="w-6 h-6 text-accent-blue" />
            <span>API & Threat Intelligence Integrations</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1 font-mono">
            Manage upstream Threat Intelligence and AI LLM provider credentials. Keys are encrypted at rest with AES-256-GCM.
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={fetchIntegrations} isLoading={isLoading}>
          <RefreshCw className="w-4 h-4 mr-1.5" /> Refresh Status
        </Button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {integrations.map((it) => (
          <Card key={it.provider} className="border-navy-600 bg-navy-800 shadow-xl flex flex-col justify-between">
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <CardTitle className="capitalize text-base font-bold text-white">
                  {it.provider === 'google' ? 'Google Gemini AI' : it.provider}
                </CardTitle>
                <Badge variant={it.is_enabled ? 'success' : 'outline'}>
                  {it.is_enabled ? 'ACTIVE' : 'DISABLED'}
                </Badge>
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-1.5 text-xs font-mono">
                <div className="flex justify-between text-slate-400">
                  <span>API Key Configured:</span>
                  <span className={it.has_api_key ? 'text-green-400 font-bold' : 'text-slate-500'}>
                    {it.has_api_key ? 'Encrypted Vault' : 'Not Set (Demo Mode)'}
                  </span>
                </div>
                <div className="flex justify-between text-slate-400">
                  <span>Queries Handled:</span>
                  <span className="text-slate-200">{it.request_count}</span>
                </div>
                <div className="flex justify-between text-slate-400">
                  <span>Provider Errors:</span>
                  <span className={it.error_count > 0 ? 'text-red-400' : 'text-slate-200'}>
                    {it.error_count}
                  </span>
                </div>
                <div className="flex justify-between text-slate-400">
                  <span>Last Invoked:</span>
                  <span className="text-slate-200">{it.last_used_at ? new Date(it.last_used_at).toLocaleDateString() : 'Never'}</span>
                </div>
              </div>

              <div className="pt-2 border-t border-navy-700">
                <Button size="sm" variant="secondary" className="w-full text-xs" onClick={() => openConfig(it)}>
                  <Key className="w-3.5 h-3.5 mr-1 text-accent-cyan" /> Configure Vault
                </Button>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Configure Modal */}
      {modalProvider && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-navy-900 border border-navy-600 rounded-2xl max-w-md w-full p-6 space-y-4 shadow-2xl">
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <Key className="w-4 h-4 text-accent-cyan" />
              <span>Configure {modalProvider.toUpperCase()} Provider</span>
            </h3>

            <form onSubmit={handleSave} className="space-y-4 text-xs">
              <div className="flex items-center justify-between p-3 bg-navy-950 rounded-xl border border-navy-800">
                <span>Enable Provider for Threat Ingestion</span>
                <input
                  type="checkbox"
                  checked={isEnabledInput}
                  onChange={(e) => setIsEnabledInput(e.target.checked)}
                  className="w-4 h-4 accent-accent-blue cursor-pointer"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-semibold mb-1">
                  Provider Secret Key (Optional - leave blank for demo sandbox)
                </label>
                <input
                  type="password"
                  placeholder="Enter API token..."
                  value={apiKeyInput}
                  onChange={(e) => setApiKeyInput(e.target.value)}
                  className="w-full bg-navy-950 border border-navy-700 rounded-xl p-2.5 text-xs text-white focus:outline-none focus:border-accent-blue"
                />
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <Button type="button" variant="ghost" size="sm" onClick={() => setModalProvider(null)}>
                  Cancel
                </Button>
                <Button type="submit" size="sm">
                  Save Changes
                </Button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}
