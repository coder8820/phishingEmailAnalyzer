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
  X,
  FileText,
} from 'lucide-react'
import { toast } from 'sonner'
import {
  getGmailStatus,
  getGmailMessages,
  getGoogleOAuthUrl,
  disconnectGmail,
  toggleAutoAnalyze,
  syncGmailInbox,
  runInitialInboxScan,
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

  // Real Google OAuth 2.0 flow states
  const [isStartingOAuth, setIsStartingOAuth] = useState(false)
  const [configError, setConfigError] = useState<string | null>(null)

  // Initial Scan explicit consent states
  const [showConsentModal, setShowConsentModal] = useState(false)
  const [consentChecked, setConsentChecked] = useState(false)
  const [scanLimit, setScanLimit] = useState(25)
  const [runningInitialScan, setRunningInitialScan] = useState(false)

  // Check URL query parameters on return from backend callback
  useEffect(() => {
    if (typeof window !== 'undefined') {
      const urlParams = new URLSearchParams(window.location.search)
      if (urlParams.get('gmail_connected') === 'true') {
        const email = urlParams.get('email')
        toast.success(`Google Account successfully connected and verified! ${email ? `(${email})` : ''}`)
        window.history.replaceState({}, document.title, window.location.pathname)
        loadData()
      } else if (urlParams.get('gmail_error')) {
        const error = urlParams.get('gmail_error')
        toast.error(`Google Connection Error: ${error}`)
        window.history.replaceState({}, document.title, window.location.pathname)
      }
    }
  }, [])

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

  const handleStartGoogleOAuth = async () => {
    setIsStartingOAuth(true)
    setConfigError(null)
    try {
      const res = await getGoogleOAuthUrl()
      if (res.authorization_url) {
        toast.info('Redirecting to Google Identity Services...')
        window.location.href = res.authorization_url
      } else {
        toast.error('Invalid response from Google OAuth service')
      }
    } catch (err: any) {
      const detail = err.response?.data?.detail || err.message || 'Failed to initiate Google OAuth'
      setConfigError(detail)
      toast.error(detail)
    } finally {
      setIsStartingOAuth(false)
    }
  }

  const handleDisconnect = async () => {
    if (!confirm('Are you sure you want to disconnect your Gmail integration and revoke Google OAuth access?')) return
    try {
      await disconnectGmail()
      toast.success('Gmail account disconnected and Google OAuth grant revoked')
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
      const res = await syncGmailInbox()
      toast.success(res.message || `Synchronized: ${res.synced_count} new messages retrieved (${res.skipped_count} skipped)`)
      await loadData(true)
    } catch (err: any) {
      const detail = err.response?.data?.detail || err.message || 'Failed to sync Gmail'
      toast.error(detail)
    } finally {
      setSyncing(false)
    }
  }

  const handleInitialScanSubmit = async () => {
    if (!consentChecked) {
      toast.error('Explicit consent must be confirmed before proceeding.')
      return
    }
    setRunningInitialScan(true)
    try {
      const res = await runInitialInboxScan({
        consent_acknowledged: true,
        max_messages: scanLimit,
      })
      toast.success(res.message || `Initial Scan Complete: ${res.synced_count} messages retrieved (${res.skipped_count} skipped)`)
      setShowConsentModal(false)
      setConsentChecked(false)
      await loadData(true)
    } catch (err: any) {
      const detail = err.response?.data?.detail || err.message || 'Initial scan failed'
      toast.error(detail)
    } finally {
      setRunningInitialScan(false)
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
                <div className="flex flex-wrap items-center gap-2">
                  <span className="flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-mono bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                    Active: {status.email_address}
                  </span>
                  <span className="px-2 py-0.5 rounded-md text-[10px] font-mono bg-navy-800 text-slate-300 border border-navy-700">
                    Scope: gmail.modify
                  </span>
                  <span className="px-2 py-0.5 rounded-md text-[10px] font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                    Token: {status.token_status || 'valid'}
                  </span>
                </div>
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

              {/* Initial Inbox Scan with Explicit Consent */}
              <button
                onClick={() => setShowConsentModal(true)}
                disabled={syncing || runningInitialScan}
                className="flex items-center gap-1.5 px-3.5 py-2 bg-amber-500/10 hover:bg-amber-500/20 text-amber-300 border border-amber-500/30 hover:border-amber-500/50 rounded-xl text-xs font-mono transition-colors"
                title="Scan historical inbox emails with explicit user consent"
              >
                <Shield className="w-3.5 h-3.5 text-amber-400" />
                <span>Initial Scan</span>
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
                title="Disconnect Gmail Account & Revoke OAuth"
              >
                <Power className="w-4 h-4" />
              </button>
            </>
          ) : (
            <button
              onClick={handleStartGoogleOAuth}
              disabled={isStartingOAuth}
              className="flex items-center gap-2 px-4 py-2.5 bg-white hover:bg-slate-100 text-slate-900 rounded-xl text-xs font-mono font-semibold shadow-lg shadow-white/10 transition-all cursor-pointer disabled:opacity-60"
            >
              {isStartingOAuth ? (
                <RefreshCw className="w-4 h-4 animate-spin text-slate-700" />
              ) : (
                <svg className="w-4 h-4" viewBox="0 0 24 24">
                  <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" />
                  <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" />
                  <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z" />
                  <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z" />
                </svg>
              )}
              <span>{isStartingOAuth ? 'Redirecting to Google...' : 'Connect with Google'}</span>
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
        /* Disconnected Hero Call-to-Action with Genuine Google OAuth 2.0 */
        <div className="mt-6 p-8 border border-navy-700/60 rounded-xl bg-navy-850/40 text-center flex flex-col items-center justify-center">
          <div className="p-4 bg-red-500/10 border border-red-500/20 rounded-2xl text-red-400 mb-4 shadow-lg shadow-red-500/5">
            <Shield className="w-8 h-8" />
          </div>
          <h3 className="text-lg font-bold text-white font-mono">
            Connect Your Gmail Account with Official Google OAuth 2.0
          </h3>
          <p className="text-xs text-slate-400 max-w-lg mt-1.5 leading-relaxed">
            Link your Google account securely via Google's official consent screen. PhishGuard requests the least-privilege
            <code className="text-accent-blue bg-navy-900 px-1 py-0.5 rounded mx-1">gmail.modify</code>
            scope for inspection and quarantine. All refresh tokens are AES-128 encrypted at rest.
          </p>

          {configError && (
            <div className="mt-4 p-4 max-w-md w-full bg-red-500/10 border border-red-500/30 rounded-xl text-left space-y-1.5">
              <div className="flex items-center gap-2 text-red-400 font-semibold font-mono text-xs">
                <AlertTriangle className="w-4 h-4 shrink-0" />
                <span>Google OAuth Configuration Missing</span>
              </div>
              <p className="text-[11px] text-red-300 font-mono leading-relaxed">
                {configError}
              </p>
              <p className="text-[10px] text-slate-400 font-mono pt-1">
                Configure <code className="text-white">GOOGLE_CLIENT_ID</code> and <code className="text-white">GOOGLE_CLIENT_SECRET</code> in <code className="text-white">backend/.env</code>.
              </p>
            </div>
          )}

          <button
            onClick={handleStartGoogleOAuth}
            disabled={isStartingOAuth}
            className="mt-6 flex items-center gap-2.5 px-6 py-3 bg-white hover:bg-slate-100 text-slate-900 rounded-xl text-xs font-mono font-bold shadow-xl shadow-white/10 transition-all cursor-pointer disabled:opacity-50"
          >
            {isStartingOAuth ? (
              <RefreshCw className="w-4 h-4 animate-spin text-slate-700" />
            ) : (
              <svg className="w-4 h-4" viewBox="0 0 24 24">
                <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" />
                <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" />
                <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z" />
                <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z" />
              </svg>
            )}
            <span>{isStartingOAuth ? 'Redirecting to Google...' : 'Sign in & Connect with Google'}</span>
          </button>

          <p className="text-[10px] text-slate-500 font-mono mt-3">
            Offline access enabled for autonomous background monitoring & quarantine.
          </p>
        </div>
      )}

      {/* Explicit Consent Modal for Initial Historical Inbox Scan */}
      {showConsentModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="bg-navy-900 border border-navy-700 rounded-2xl max-w-lg w-full p-6 shadow-2xl relative space-y-5 animate-in fade-in duration-200">
            <div className="flex items-start justify-between">
              <div className="flex items-center gap-3">
                <div className="p-2.5 bg-amber-500/15 border border-amber-500/30 rounded-xl text-amber-400">
                  <Shield className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-base font-bold text-white font-mono">
                    Initial Gmail Inbox Scan
                  </h3>
                  <p className="text-xs text-slate-400 font-mono">
                    Explicit Authorization Required
                  </p>
                </div>
              </div>
              <button
                onClick={() => setShowConsentModal(false)}
                className="text-slate-400 hover:text-white p-1 rounded-lg transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="bg-navy-800/80 border border-navy-700/60 rounded-xl p-4 text-xs font-mono text-slate-300 space-y-2.5">
              <p className="leading-relaxed">
                PhishGuard AI requires explicit user consent before retrieving historical emails from your connected Google account:
              </p>
              <ul className="list-disc list-inside space-y-1 text-slate-400 pl-1">
                <li>Retrieves only messages currently in your <strong className="text-slate-200">INBOX</strong>.</li>
                <li>Strictly excludes <strong className="text-slate-200">Sent, Drafts, Spam, and Trash</strong>.</li>
                <li>Raw MIME content is decoded losslessly and evaluated with zero data leakage.</li>
                <li>Duplicate analyses are strictly prevented via idempotent message tracking.</li>
              </ul>
            </div>

            {/* Scan Limit Selector */}
            <div className="flex items-center justify-between text-xs font-mono text-slate-300">
              <span>Maximum messages to inspect:</span>
              <div className="flex items-center gap-2">
                {[10, 25, 50].map((num) => (
                  <button
                    key={num}
                    type="button"
                    onClick={() => setScanLimit(num)}
                    className={cn(
                      'px-2.5 py-1 rounded-lg border transition-colors',
                      scanLimit === num
                        ? 'bg-accent-blue/20 text-accent-blue border-accent-blue/50 font-bold'
                        : 'bg-navy-800 text-slate-400 border-navy-700 hover:text-white'
                    )}
                  >
                    {num}
                  </button>
                ))}
              </div>
            </div>

            {/* Explicit Consent Checkbox */}
            <label className="flex items-start gap-3 p-3.5 bg-amber-500/10 border border-amber-500/25 rounded-xl cursor-pointer">
              <input
                type="checkbox"
                checked={consentChecked}
                onChange={(e) => setConsentChecked(e.target.checked)}
                className="mt-0.5 rounded border-navy-700 bg-navy-800 text-amber-500 focus:ring-0 cursor-pointer"
              />
              <span className="text-xs text-amber-200/90 font-mono leading-relaxed select-none">
                I explicitly consent to PhishGuard AI scanning up to {scanLimit} historical messages from my connected Gmail INBOX for phishing threat analysis.
              </span>
            </label>

            {/* Modal Actions */}
            <div className="flex items-center justify-end gap-3 pt-2">
              <button
                type="button"
                onClick={() => setShowConsentModal(false)}
                className="px-4 py-2 rounded-xl text-xs font-mono text-slate-400 hover:text-white transition-colors"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleInitialScanSubmit}
                disabled={!consentChecked || runningInitialScan}
                className="flex items-center gap-2 px-5 py-2.5 bg-amber-500 hover:bg-amber-400 disabled:bg-slate-750 disabled:text-slate-500 text-slate-950 rounded-xl text-xs font-mono font-bold transition-all disabled:cursor-not-allowed shadow-lg shadow-amber-500/10"
              >
                {runningInitialScan ? (
                  <>
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    <span>Scanning INBOX...</span>
                  </>
                ) : (
                  <>
                    <Shield className="w-3.5 h-3.5" />
                    <span>Authorize & Start Scan</span>
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
