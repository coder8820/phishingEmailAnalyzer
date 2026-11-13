'use client'

import React, { useState, useEffect } from 'react'
import { useRouter } from 'next/navigation'
import {
  Mail,
  Shield,
  Zap,
  RefreshCw,
  Search,
  Filter,
  CheckCircle2,
  AlertTriangle,
  Flame,
  ArrowRight,
  ExternalLink,
  Power,
  Sliders,
  Sparkles,
  Lock,
  Layers,
  Inbox,
  Clock,
  Eye,
} from 'lucide-react'
import { toast } from 'sonner'
import {
  getGmailStatus,
  getGmailMessages,
  connectGmail,
  disconnectGmail,
  toggleAutoAnalyze,
  syncGmailInbox,
  analyzeGmailMessageManual,
  analyzeAllGmailPending,
  type GmailStatus,
  type GmailMessageItem,
} from '@/services/gmailService'
import { cn } from '@/lib/utils'

export function GmailDefenseHub() {
  const router = useRouter()
  const [status, setStatus] = useState<GmailStatus | null>(null)
  const [messages, setMessages] = useState<GmailMessageItem[]>([])
  const [loading, setLoading] = useState(true)
  const [syncing, setSyncing] = useState(false)
  const [analyzingAll, setAnalyzingAll] = useState(false)
  const [analyzingId, setAnalyzingId] = useState<string | null>(null)
  const [togglingAuto, setTogglingAuto] = useState(false)

  // Filters
  const [search, setSearch] = useState('')
  const [threatFilter, setThreatFilter] = useState<'all' | 'safe' | 'suspicious' | 'critical'>('all')
  const [statusFilter, setStatusFilter] = useState<'all' | 'analyzed' | 'pending'>('all')

  // Connect Modal state
  const [isConnectModalOpen, setIsConnectModalOpen] = useState(false)
  const [connectEmail, setConnectEmail] = useState('')
  const [appPassword, setAppPassword] = useState('')
  const [connectAutoAnalyze, setConnectAutoAnalyze] = useState(true)
  const [connecting, setConnecting] = useState(false)

  // Fetch Status and Messages
  const loadData = async (silent = false) => {
    if (!silent) setLoading(true)
    try {
      const st = await getGmailStatus()
      setStatus(st)
      if (st.is_connected) {
        const msgsRes = await getGmailMessages({
          search,
          threat_level: threatFilter,
          status_filter: statusFilter,
        })
        setMessages(msgsRes.messages || [])
      } else {
        setMessages([])
      }
    } catch (err: any) {
      console.error('Failed to load Gmail data:', err)
    } finally {
      if (!silent) setLoading(false)
    }
  }

  useEffect(() => {
    loadData()
  }, [threatFilter, statusFilter])

  // Search debounce
  useEffect(() => {
    const handler = setTimeout(() => {
      if (status?.is_connected) {
        getGmailMessages({
          search,
          threat_level: threatFilter,
          status_filter: statusFilter,
        }).then((res) => setMessages(res.messages || []))
      }
    }, 300)
    return () => clearTimeout(handler)
  }, [search])

  const handleConnect = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!connectEmail || !connectEmail.includes('@')) {
      toast.error('Please enter a valid Gmail address')
      return
    }
    setConnecting(true)
    try {
      await connectGmail({
        email_address: connectEmail,
        app_password: appPassword || undefined,
        auto_analyze: connectAutoAnalyze,
        sync_demo_inbox: true,
      })
      toast.success(`Successfully connected ${connectEmail}`)
      setIsConnectModalOpen(false)
      setConnectEmail('')
      setAppPassword('')
      await loadData()
    } catch (err: any) {
      toast.error(err?.response?.data?.detail || 'Failed to connect Gmail')
    } finally {
      setConnecting(false)
    }
  }

  const handleDisconnect = async () => {
    if (!confirm('Are you sure you want to disconnect your Gmail integration?')) return
    try {
      await disconnectGmail()
      toast.success('Gmail account disconnected')
      await loadData()
    } catch (err: any) {
      toast.error('Failed to disconnect Gmail')
    }
  }

  const handleToggleAutoAnalyze = async () => {
    if (!status) return
    const newState = !status.auto_analyze_enabled
    setTogglingAuto(true)
    try {
      await toggleAutoAnalyze(newState)
      setStatus({ ...status, auto_analyze_enabled: newState })
      toast.success(`Auto Gmail Analysis ${newState ? 'Enabled' : 'Disabled'}`)
      if (newState) {
        setTimeout(() => loadData(true), 1500)
      }
    } catch (err: any) {
      toast.error('Failed to update Auto-Analyze setting')
    } finally {
      setTogglingAuto(false)
    }
  }

  const handleSync = async () => {
    setSyncing(true)
    try {
      await syncGmailInbox()
      toast.success('Gmail inbox synchronized successfully')
      await loadData(true)
    } catch (err: any) {
      toast.error('Failed to sync Gmail')
    } finally {
      setSyncing(false)
    }
  }

  const handleAnalyzeManual = async (msgId: string) => {
    setAnalyzingId(msgId)
    try {
      const res = await analyzeGmailMessageManual(msgId)
      toast.success(`Analysis completed: ${res.risk_classification} (${res.risk_score}/100)`)
      await loadData(true)
    } catch (err: any) {
      toast.error('Analysis failed')
    } finally {
      setAnalyzingId(null)
    }
  }

  const handleAnalyzeAll = async () => {
    setAnalyzingAll(true)
    try {
      const res = await analyzeAllGmailPending()
      toast.success(res.message || 'Queued all pending messages for analysis')
      setTimeout(() => loadData(true), 2000)
    } catch (err: any) {
      toast.error('Batch analysis failed')
    } finally {
      setAnalyzingAll(false)
    }
  }

  return (
    <div className="bg-gradient-to-b from-navy-850 to-navy-900 border border-navy-700/80 rounded-2xl p-6 shadow-xl relative overflow-hidden mb-8">
      {/* Background cyber glow accents */}
      <div className="absolute top-0 right-0 w-96 h-96 bg-red-500/5 rounded-full blur-3xl -z-10 pointer-events-none" />
      <div className="absolute bottom-0 left-1/4 w-80 h-80 bg-accent-blue/5 rounded-full blur-3xl -z-10 pointer-events-none" />

      {/* Top Header Row */}
      <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4 pb-6 border-b border-navy-700/70">
        <div className="flex items-center gap-3.5">
          <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-xl text-red-400 shadow-inner">
            <Mail className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2.5">
              <h2 className="text-xl font-bold text-white tracking-tight font-mono">
                Connected Gmail Defense Hub
              </h2>
              {status?.is_connected ? (
                <span className="flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-mono bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                  Active: {status.email_address}
                </span>
              ) : (
                <span className="flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-mono bg-slate-500/15 text-slate-400 border border-slate-600/30">
                  Disconnected
                </span>
              )}
            </div>
            <p className="text-xs text-slate-400 mt-1">
              Live Gmail inbox sync with heuristic sandbox & autonomous AI phishing inspection.
            </p>
          </div>
        </div>

        {/* Global Action Controls */}
        <div className="flex flex-wrap items-center gap-2.5">
          {status?.is_connected ? (
            <>
              {/* Auto-Analyze Switch */}
              <button
                onClick={handleToggleAutoAnalyze}
                disabled={togglingAuto}
                className={cn(
                  'flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-mono font-medium transition-all border',
                  status.auto_analyze_enabled
                    ? 'bg-accent-blue/15 text-accent-blue border-accent-blue/40 shadow-sm shadow-accent-blue/10'
                    : 'bg-navy-800 text-slate-400 border-navy-700 hover:text-slate-200'
                )}
                title="When active, all incoming emails are automatically analyzed in the background"
              >
                <Zap
                  className={cn(
                    'w-3.5 h-3.5',
                    status.auto_analyze_enabled && 'text-accent-blue animate-pulse'
                  )}
                />
                <span>Auto-Analyze:</span>
                <span
                  className={cn(
                    'font-bold',
                    status.auto_analyze_enabled ? 'text-accent-blue' : 'text-slate-500'
                  )}
                >
                  {status.auto_analyze_enabled ? 'ON' : 'OFF'}
                </span>
              </button>

              {/* Sync Button */}
              <button
                onClick={handleSync}
                disabled={syncing}
                className="flex items-center gap-1.5 px-3.5 py-2 bg-navy-800 hover:bg-navy-750 text-slate-200 border border-navy-700 hover:border-slate-500 rounded-xl text-xs font-mono transition-colors"
              >
                <RefreshCw className={cn('w-3.5 h-3.5', syncing && 'animate-spin text-accent-blue')} />
                <span>Sync Inbox</span>
              </button>

              {/* Analyze All Pending */}
              {status.pending_messages > 0 && (
                <button
                  onClick={handleAnalyzeAll}
                  disabled={analyzingAll}
                  className="flex items-center gap-1.5 px-3.5 py-2 bg-red-500/20 hover:bg-red-500/30 text-red-300 border border-red-500/40 rounded-xl text-xs font-mono transition-colors"
                >
                  <Sparkles className={cn('w-3.5 h-3.5', analyzingAll && 'animate-spin')} />
                  <span>Analyze All ({status.pending_messages})</span>
                </button>
              )}

              {/* Disconnect */}
              <button
                onClick={handleDisconnect}
                className="p-2 text-slate-400 hover:text-red-400 hover:bg-red-500/10 rounded-xl border border-transparent hover:border-red-500/30 transition-colors"
                title="Disconnect Gmail Account"
              >
                <Power className="w-4 h-4" />
              </button>
            </>
          ) : (
            <button
              onClick={() => setIsConnectModalOpen(true)}
              className="flex items-center gap-2 px-4 py-2.5 bg-gradient-to-r from-red-600 to-red-500 hover:from-red-500 hover:to-red-400 text-white rounded-xl text-xs font-mono font-semibold shadow-lg shadow-red-600/25 transition-all"
            >
              <Mail className="w-4 h-4" />
              <span>Connect Gmail Account</span>
            </button>
          )}
        </div>
      </div>

      {/* Main Content Area */}
      {status?.is_connected ? (
        <div className="mt-6 space-y-6">
          {/* Quick Stats Grid */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3.5">
            <div className="bg-navy-800/80 border border-navy-700/60 rounded-xl p-3.5 flex items-center justify-between">
              <div>
                <p className="text-[10px] font-mono uppercase tracking-wider text-slate-400">Total Synced</p>
                <p className="text-xl font-bold font-mono text-white mt-1">{status.total_messages}</p>
              </div>
              <Inbox className="w-5 h-5 text-slate-500" />
            </div>

            <div className="bg-navy-800/80 border border-navy-700/60 rounded-xl p-3.5 flex items-center justify-between">
              <div>
                <p className="text-[10px] font-mono uppercase tracking-wider text-slate-400">Analyzed</p>
                <p className="text-xl font-bold font-mono text-emerald-400 mt-1">{status.analyzed_messages}</p>
              </div>
              <CheckCircle2 className="w-5 h-5 text-emerald-500" />
            </div>

            <div className="bg-navy-800/80 border border-navy-700/60 rounded-xl p-3.5 flex items-center justify-between">
              <div>
                <p className="text-[10px] font-mono uppercase tracking-wider text-slate-400">Pending Review</p>
                <p className="text-xl font-bold font-mono text-yellow-400 mt-1">{status.pending_messages}</p>
              </div>
              <Clock className="w-5 h-5 text-yellow-500" />
            </div>

            <div className="bg-navy-800/80 border border-navy-700/60 rounded-xl p-3.5 flex items-center justify-between">
              <div>
                <p className="text-[10px] font-mono uppercase tracking-wider text-slate-400">Hostile Threats</p>
                <p className="text-xl font-bold font-mono text-red-400 mt-1">{status.critical_threats}</p>
              </div>
              <Flame className="w-5 h-5 text-red-500" />
            </div>
          </div>

          {/* Filter Bar */}
          <div className="flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3 bg-navy-800/50 p-3 rounded-xl border border-navy-700/50">
            {/* Search Input */}
            <div className="relative flex-1">
              <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder="Search by sender, subject, or content..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="w-full bg-navy-900 border border-navy-700 rounded-lg pl-10 pr-4 py-2 text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-accent-blue"
              />
            </div>

            {/* Filter Pills */}
            <div className="flex items-center gap-2 overflow-x-auto">
              <div className="flex items-center bg-navy-900 border border-navy-700 rounded-lg p-0.5">
                {(['all', 'critical', 'suspicious', 'safe'] as const).map((tier) => (
                  <button
                    key={tier}
                    onClick={() => setThreatFilter(tier)}
                    className={cn(
                      'px-2.5 py-1 rounded text-[11px] font-mono uppercase transition-colors',
                      threatFilter === tier
                        ? 'bg-accent-blue text-white font-bold'
                        : 'text-slate-400 hover:text-slate-200'
                    )}
                  >
                    {tier}
                  </button>
                ))}
              </div>

              <div className="flex items-center bg-navy-900 border border-navy-700 rounded-lg p-0.5">
                {(['all', 'analyzed', 'pending'] as const).map((st) => (
                  <button
                    key={st}
                    onClick={() => setStatusFilter(st)}
                    className={cn(
                      'px-2.5 py-1 rounded text-[11px] font-mono uppercase transition-colors',
                      statusFilter === st
                        ? 'bg-navy-700 text-slate-100 font-bold'
                        : 'text-slate-400 hover:text-slate-200'
                    )}
                  >
                    {st}
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* Messages Table */}
          <div className="border border-navy-700/80 rounded-xl overflow-hidden bg-navy-900/60">
            {loading ? (
              <div className="py-12 flex flex-col items-center justify-center text-slate-400 gap-2 font-mono text-xs">
                <RefreshCw className="w-5 h-5 animate-spin text-accent-blue" />
                <span>Loading synced Gmail messages...</span>
              </div>
            ) : messages.length === 0 ? (
              <div className="py-12 flex flex-col items-center justify-center text-slate-400 gap-2 font-mono text-xs">
                <Inbox className="w-7 h-7 text-slate-600" />
                <p>No messages found matching your search or filters.</p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="bg-navy-800/80 text-slate-400 font-mono uppercase text-[10px] tracking-wider border-b border-navy-700/80">
                    <tr>
                      <th className="py-3 px-4">Subject & Content</th>
                      <th className="py-3 px-4">Sender</th>
                      <th className="py-3 px-4">Risk Level</th>
                      <th className="py-3 px-4">Status</th>
                      <th className="py-3 px-4 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-navy-800/60 font-mono">
                    {messages.map((m) => {
                      const isCritical = ['critical', 'high', 'malicious'].includes(
                        m.risk_classification?.toLowerCase() || ''
                      )
                      const isSuspicious = ['suspicious', 'medium'].includes(
                        m.risk_classification?.toLowerCase() || ''
                      )

                      return (
                        <tr
                          key={m.id}
                          className="hover:bg-navy-800/40 transition-colors group"
                        >
                          <td className="py-3 px-4 max-w-md">
                            <p className="font-semibold text-slate-200 truncate group-hover:text-white">
                              {m.subject}
                            </p>
                            <p className="text-[11px] text-slate-400 truncate mt-0.5 font-sans">
                              {m.snippet}
                            </p>
                          </td>
                          <td className="py-3 px-4 text-slate-300 max-w-xs truncate text-[11px]">
                            {m.sender}
                          </td>
                          <td className="py-3 px-4">
                            {m.is_analyzed ? (
                              <div className="flex items-center gap-2">
                                <span
                                  className={cn(
                                    'px-2 py-0.5 rounded text-[10px] font-bold uppercase border',
                                    isCritical
                                      ? 'bg-red-500/15 text-red-400 border-red-500/30'
                                      : isSuspicious
                                      ? 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30'
                                      : 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30'
                                  )}
                                >
                                  {m.risk_classification}
                                </span>
                                <span className="text-[10px] text-slate-400">
                                  {m.risk_score?.toFixed(0)}/100
                                </span>
                              </div>
                            ) : (
                              <span className="text-[10px] text-slate-500">Unassessed</span>
                            )}
                          </td>
                          <td className="py-3 px-4">
                            {m.is_analyzed ? (
                              <span className="flex items-center gap-1.5 text-emerald-400 text-[11px]">
                                <CheckCircle2 className="w-3.5 h-3.5" />
                                <span>Analyzed</span>
                              </span>
                            ) : m.analysis_status === 'processing' ? (
                              <span className="flex items-center gap-1.5 text-accent-blue text-[11px]">
                                <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                                <span>Scanning...</span>
                              </span>
                            ) : (
                              <span className="flex items-center gap-1.5 text-yellow-400/80 text-[11px]">
                                <Clock className="w-3.5 h-3.5" />
                                <span>Pending</span>
                              </span>
                            )}
                          </td>
                          <td className="py-3 px-4 text-right">
                            <div className="flex items-center justify-end gap-2">
                              {m.email_id ? (
                                <button
                                  onClick={() => router.push(`/analyses/${m.email_id}`)}
                                  className="flex items-center gap-1 px-2.5 py-1 bg-navy-800 hover:bg-navy-700 text-slate-300 hover:text-white rounded border border-navy-700 text-[11px] transition-colors"
                                >
                                  <Eye className="w-3 h-3" />
                                  <span>View Report</span>
                                </button>
                              ) : (
                                <button
                                  onClick={() => handleAnalyzeManual(m.id)}
                                  disabled={analyzingId === m.id}
                                  className="flex items-center gap-1 px-2.5 py-1 bg-accent-blue/15 hover:bg-accent-blue/25 text-accent-blue border border-accent-blue/30 rounded text-[11px] transition-colors"
                                >
                                  <Zap className={cn('w-3 h-3', analyzingId === m.id && 'animate-spin')} />
                                  <span>Analyze Now</span>
                                </button>
                              )}
                            </div>
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      ) : (
        /* Disconnected Hero Call-to-Action */
        <div className="mt-6 p-8 border border-navy-700/60 rounded-xl bg-navy-850/40 text-center flex flex-col items-center justify-center">
          <div className="p-4 bg-red-500/10 border border-red-500/20 rounded-2xl text-red-400 mb-4 shadow-lg shadow-red-500/5">
            <Shield className="w-8 h-8" />
          </div>
          <h3 className="text-lg font-bold text-white font-mono">
            Connect Your Gmail Account For Continuous Defense
          </h3>
          <p className="text-xs text-slate-400 max-w-md mt-1.5 leading-relaxed">
            Link your Google Workspace or personal Gmail inbox to monitor incoming emails, automatically
            detonate malicious payloads, verify sender SPF/DKIM/DMARC authenticity, and quarantine zero-day phishing threats.
          </p>

          <button
            onClick={() => setIsConnectModalOpen(true)}
            className="mt-6 flex items-center gap-2 px-5 py-2.5 bg-gradient-to-r from-red-600 to-red-500 hover:from-red-500 hover:to-red-400 text-white rounded-xl text-xs font-mono font-semibold shadow-lg shadow-red-600/30 transition-all cursor-pointer"
          >
            <Mail className="w-4 h-4" />
            <span>Connect Gmail Now</span>
          </button>
        </div>
      )}

      {/* Connect Modal */}
      {isConnectModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm animate-in fade-in duration-200">
          <div className="bg-navy-850 border border-navy-700 rounded-2xl w-full max-w-md p-6 shadow-2xl relative">
            <div className="flex items-center gap-3 pb-4 border-b border-navy-700">
              <div className="p-2.5 bg-red-500/15 border border-red-500/30 rounded-xl text-red-400">
                <Mail className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-base font-bold text-white font-mono">Connect Gmail Inbox</h3>
                <p className="text-xs text-slate-400">Authorize automated phishing inspection</p>
              </div>
            </div>

            <form onSubmit={handleConnect} className="mt-4 space-y-4 text-xs font-mono">
              <div>
                <label className="block text-slate-300 font-semibold mb-1">
                  Gmail Address <span className="text-red-400">*</span>
                </label>
                <input
                  type="email"
                  required
                  placeholder="e.g. yourname@gmail.com"
                  value={connectEmail}
                  onChange={(e) => setConnectEmail(e.target.value)}
                  className="w-full bg-navy-900 border border-navy-700 rounded-lg p-2.5 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-accent-blue"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-semibold mb-1">
                  Google App Password <span className="text-slate-500 font-normal">(Optional for Direct IMAP)</span>
                </label>
                <input
                  type="password"
                  placeholder="16-character Google App Password (optional)"
                  value={appPassword}
                  onChange={(e) => setAppPassword(e.target.value)}
                  className="w-full bg-navy-900 border border-navy-700 rounded-lg p-2.5 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-accent-blue"
                />
                <p className="text-[10px] text-slate-400 mt-1">
                  If left blank, PhishGuard AI connects securely via OAuth Sandbox Sync.
                </p>
              </div>

              <div className="flex items-center gap-2.5 pt-2">
                <input
                  type="checkbox"
                  id="auto_analyze_box"
                  checked={connectAutoAnalyze}
                  onChange={(e) => setConnectAutoAnalyze(e.target.checked)}
                  className="w-4 h-4 rounded bg-navy-900 border-navy-700 text-accent-blue focus:ring-0"
                />
                <label htmlFor="auto_analyze_box" className="text-slate-300 cursor-pointer text-xs">
                  Enable <span className="text-accent-blue font-bold">Auto-Analyze</span> on all incoming emails
                </label>
              </div>

              <div className="pt-4 flex items-center justify-end gap-2.5 border-t border-navy-700">
                <button
                  type="button"
                  onClick={() => setIsConnectModalOpen(false)}
                  className="px-4 py-2 bg-navy-800 hover:bg-navy-700 text-slate-300 rounded-lg transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={connecting}
                  className="flex items-center gap-1.5 px-4 py-2 bg-red-600 hover:bg-red-500 text-white font-bold rounded-lg shadow-lg shadow-red-600/20 transition-all disabled:opacity-50"
                >
                  {connecting && <RefreshCw className="w-3.5 h-3.5 animate-spin" />}
                  <span>{connecting ? 'Connecting...' : 'Authorize & Connect'}</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}
