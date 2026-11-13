'use client'

import React, { useState, useEffect, Suspense } from 'react'
import { useSearchParams } from 'next/navigation'
import {
  Mail,
  Upload,
  FileText,
  AlertTriangle,
  Link as LinkIcon,
  Paperclip,
  Search,
  Bot,
  ShieldCheck,
  ShieldAlert,
  Loader2,
  RefreshCw,
  PlusCircle,
  FileDown,
  ExternalLink,
  CheckCircle2,
  XCircle,
  HelpCircle,
} from 'lucide-react'
import { toast } from 'sonner'
import { UploadZone } from '@/components/email/UploadZone'
import { ThreatSummary } from '@/components/email/ThreatSummary'
import { ScoreBreakdown } from '@/components/email/ScoreBreakdown'
import { AIAnalysisPanel } from '@/components/email/AIAnalysisPanel'
import { Button } from '@/components/ui/Button'
import { Badge } from '@/components/ui/Badge'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/Card'
import {
  uploadEmailFile,
  submitRawEmail,
  getEmail,
  getEmailAnalysis,
  getEmailURLs,
  getEmailAttachments,
  getEmailIOCs,
} from '@/services/emailService'
import { createIncident } from '@/services/incidentService'
import { formatDate } from '@/lib/utils'
import type { Email, EmailAnalysis, ExtractedURL, Attachment, IOC } from '@/types'

function EmailAnalyzerContent() {
  const searchParams = useSearchParams()
  const initialEmailId = searchParams.get('id') || searchParams.get('email_id')

  const [activeTab, setActiveTab] = useState<'upload' | 'raw'>('upload')
  const [rawText, setRawText] = useState('')
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [analysisStatus, setAnalysisStatus] = useState<string | null>(null)

  // Loaded analysis results
  const [emailData, setEmailData] = useState<Email | null>(null)
  const [analysis, setAnalysis] = useState<EmailAnalysis | null>(null)
  const [urls, setUrls] = useState<ExtractedURL[]>([])
  const [attachments, setAttachments] = useState<Attachment[]>([])
  const [iocs, setIocs] = useState<IOC[]>([])

  // Workspace subtab
  const [workspaceTab, setWorkspaceTab] = useState<
    'overview' | 'headers' | 'urls' | 'attachments' | 'ai' | 'iocs'
  >('overview')

  const loadExistingEmail = async (emailId: string) => {
    setIsSubmitting(true)
    setAnalysisStatus('Retrieving forensic analysis results...')
    try {
      const [em, ana, u, att, iocList] = await Promise.all([
        getEmail(emailId),
        getEmailAnalysis(emailId).catch(() => null),
        getEmailURLs(emailId).catch(() => []),
        getEmailAttachments(emailId).catch(() => []),
        getEmailIOCs(emailId).catch(() => []),
      ])
      setEmailData(em)
      setAnalysis(ana)
      setUrls(u)
      setAttachments(att)
      setIocs(iocList)
    } catch {
      toast.error('Could not fetch email analysis records')
    } finally {
      setIsSubmitting(false)
      setAnalysisStatus(null)
    }
  }

  useEffect(() => {
    if (initialEmailId) {
      loadExistingEmail(initialEmailId)
    }
  }, [initialEmailId])

  const handleStartAnalysis = async () => {
    setIsSubmitting(true)
    setAnalysisStatus('Submitting email for sandboxed processing...')
    try {
      let res: { email_id: string; status: string }
      if (activeTab === 'upload') {
        if (!selectedFile) {
          toast.error('Please select an .eml file first')
          setIsSubmitting(false)
          return
        }
        res = await uploadEmailFile(selectedFile)
      } else {
        if (!rawText.trim()) {
          toast.error('Please paste raw email headers and body text')
          setIsSubmitting(false)
          return
        }
        res = await submitRawEmail(rawText)
      }

      toast.success('Email ingested into analysis pipeline')
      pollAnalysis(res.email_id)
    } catch (err: any) {
      toast.error(err.response?.data?.error?.message || 'Failed to submit email')
      setIsSubmitting(false)
      setAnalysisStatus(null)
    }
  }

  const pollAnalysis = async (emailId: string) => {
    setAnalysisStatus('Parsing MIME hierarchy and running security engines...')
    let attempts = 0
    const maxAttempts = 25

    const interval = setInterval(async () => {
      attempts++
      try {
        const em = await getEmail(emailId)
        if (em.analysis_status === 'complete') {
          clearInterval(interval)
          setAnalysisStatus('Analysis complete! Rendering results...')
          const [ana, u, att, iocList] = await Promise.all([
            getEmailAnalysis(emailId),
            getEmailURLs(emailId).catch(() => []),
            getEmailAttachments(emailId).catch(() => []),
            getEmailIOCs(emailId).catch(() => []),
          ])
          setEmailData(em)
          setAnalysis(ana)
          setUrls(u)
          setAttachments(att)
          setIocs(iocList)
          setIsSubmitting(false)
          setAnalysisStatus(null)
          toast.success('Threat investigation completed')
        } else if (em.analysis_status === 'failed') {
          clearInterval(interval)
          setIsSubmitting(false)
          setAnalysisStatus(null)
          toast.error('Analysis pipeline reported an error processing this email')
        } else if (attempts >= maxAttempts) {
          clearInterval(interval)
          setIsSubmitting(false)
          setAnalysisStatus(null)
          toast.error('Analysis timed out. Please check investigation history.')
        }
      } catch {
        clearInterval(interval)
        setIsSubmitting(false)
        setAnalysisStatus(null)
      }
    }, 2000)
  }

  const handleCreateIncident = async () => {
    if (!analysis || !emailData) return
    try {
      const res = await createIncident({
        title: `Suspicious Email Incident: ${emailData.subject || 'Threat Detection'}`,
        description: `Automated incident created from PhishGuard AI analysis.\nRisk Score: ${analysis.risk_score}/100 (${analysis.risk_classification.toUpperCase()})\nSender: ${emailData.sender_email || emailData.sender_raw || 'Unknown'}\nIngested: ${emailData.created_at || 'Just now'}`,
        severity: analysis.risk_score > 70 ? 'high' : analysis.risk_score > 40 ? 'medium' : 'low',
        email_ids: [emailData.id],
        ioc_ids: iocs.map((i) => i.id),
      })
      toast.success(`Incident #${res.incident_number} created successfully`)
    } catch {
      toast.error('Failed to create incident')
    }
  }

  const getAuthBadge = (res?: string) => {
    const val = (res || 'none').toLowerCase()
    if (val === 'pass') {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-mono font-semibold bg-emerald-950/60 text-emerald-300 border border-emerald-600/40">
          <CheckCircle2 className="w-3.5 h-3.5" /> PASS
        </span>
      )
    }
    if (val === 'fail') {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-mono font-semibold bg-rose-950/60 text-rose-300 border border-rose-600/40">
          <XCircle className="w-3.5 h-3.5" /> FAIL
        </span>
      )
    }
    if (val === 'softfail' || val === 'neutral') {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-mono font-semibold bg-amber-950/60 text-amber-300 border border-amber-600/40">
          <AlertTriangle className="w-3.5 h-3.5" /> {val.toUpperCase()}
        </span>
      )
    }
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-mono font-semibold bg-navy-900 text-slate-400 border border-navy-700">
        <HelpCircle className="w-3.5 h-3.5" /> {val.toUpperCase()}
      </span>
    )
  }

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Top Banner / Ingestion Section */}
      <Card className="border-navy-600 bg-navy-800 shadow-xl">
        <CardHeader>
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div>
              <CardTitle className="flex items-center gap-2">
                <Mail className="w-5 h-5 text-accent-blue" />
                <span>Email Threat Ingestion Workspace</span>
              </CardTitle>
              <p className="text-xs text-slate-400 mt-1">
                Upload raw RFC 822 EML files or paste raw SMTP headers and MIME bodies for multi-layer threat analysis.
              </p>
            </div>

            {/* Mode switch */}
            <div className="flex bg-navy-900 p-1 rounded-lg border border-navy-700 self-start md:self-auto">
              <button
                onClick={() => setActiveTab('upload')}
                className={`px-3 py-1.5 rounded-md text-xs font-medium transition-all ${
                  activeTab === 'upload'
                    ? 'bg-accent-blue text-white shadow-sm'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Upload EML File
              </button>
              <button
                onClick={() => setActiveTab('raw')}
                className={`px-3 py-1.5 rounded-md text-xs font-medium transition-all ${
                  activeTab === 'raw'
                    ? 'bg-accent-blue text-white shadow-sm'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Paste Raw Text
              </button>
            </div>
          </div>
        </CardHeader>

        <CardContent>
          {activeTab === 'upload' ? (
            <div className="space-y-4">
              <UploadZone
                onFileSelect={(file) => setSelectedFile(file)}
                disabled={isSubmitting}
              />
              <div className="flex justify-end">
                <Button
                  onClick={handleStartAnalysis}
                  disabled={!selectedFile || isSubmitting}
                  isLoading={isSubmitting}
                >
                  <ShieldCheck className="w-4 h-4 mr-1.5" /> Run Security Scans
                </Button>
              </div>
            </div>
          ) : (
            <div className="space-y-4">
              <textarea
                rows={8}
                value={rawText}
                onChange={(e) => setRawText(e.target.value)}
                placeholder="Paste raw email content here (RFC 5322 format with headers, boundary delimiters, and body)..."
                disabled={isSubmitting}
                className="w-full bg-navy-900 border border-navy-600 rounded-xl p-3 text-xs font-mono text-slate-200 focus:outline-none focus:border-accent-blue"
              />
              <div className="flex justify-end">
                <Button
                  onClick={handleStartAnalysis}
                  disabled={!rawText.trim() || isSubmitting}
                  isLoading={isSubmitting}
                >
                  <ShieldCheck className="w-4 h-4 mr-1.5" /> Analyze Raw Headers & Body
                </Button>
              </div>
            </div>
          )}

          {/* Progress / Status banner */}
          {analysisStatus && (
            <div className="mt-4 p-3 bg-navy-900/90 border border-accent-blue/40 rounded-xl flex items-center gap-3 text-xs text-accent-cyan">
              <Loader2 className="w-4 h-4 animate-spin text-accent-blue" />
              <span className="font-mono">{analysisStatus}</span>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Analysis Results Display */}
      {analysis && emailData && (
        <div className="space-y-6">
          {/* Header Action Bar */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-navy-800 border border-navy-600 rounded-xl p-4">
            <div>
              <span className="text-xs font-mono uppercase text-slate-400">Analysis Target:</span>
              <h3 className="text-base font-bold text-slate-100 truncate max-w-xl">
                {emailData.subject || '(Untitled / Missing Subject)'}
              </h3>
              <p className="text-xs text-slate-400 font-mono mt-0.5">
                Sender: {emailData.sender_email || emailData.sender_raw || 'Unknown'} | Ingested: {formatDate(emailData.created_at)}
              </p>
            </div>

            <div className="flex items-center gap-2">
              <Button size="sm" onClick={handleCreateIncident}>
                <PlusCircle className="w-4 h-4 mr-1.5" /> Escalate to Incident
              </Button>
            </div>
          </div>

          {/* Threat Summary Gauge & Category Breakdown */}
          <ThreatSummary analysis={analysis} />

          {/* Navigation Subtabs */}
          <div className="flex border-b border-navy-700 space-x-1 overflow-x-auto">
            {[
              { id: 'overview', label: 'Signal Breakdown', icon: ShieldAlert },
              { id: 'headers', label: 'Authentication & Headers', icon: FileText },
              { id: 'urls', label: `Extracted URLs (${urls.length})`, icon: LinkIcon },
              { id: 'attachments', label: `Attachments (${attachments.length})`, icon: Paperclip },
              { id: 'ai', label: 'GenAI Cognitive Report', icon: Bot },
              { id: 'iocs', label: `Observed IOCs (${iocs.length})`, icon: Search },
            ].map((tab) => {
              const Icon = tab.icon
              const isActive = workspaceTab === tab.id
              return (
                <button
                  key={tab.id}
                  onClick={() => setWorkspaceTab(tab.id as any)}
                  className={`flex items-center gap-2 px-4 py-2.5 text-xs font-medium border-b-2 transition-all whitespace-nowrap ${
                    isActive
                      ? 'border-accent-blue text-accent-cyan bg-navy-800/40 font-semibold'
                      : 'border-transparent text-slate-400 hover:text-slate-200 hover:border-slate-600'
                  }`}
                >
                  <Icon className="w-4 h-4" />
                  <span>{tab.label}</span>
                </button>
              )
            })}
          </div>

          {/* Subtab Contents */}
          <div className="pt-2">
            {workspaceTab === 'overview' && (
              <ScoreBreakdown
                signals={analysis.score_breakdown?.signals}
                explanation={analysis.score_breakdown?.explanation}
                missingEvidence={analysis.missing_evidence}
              />
            )}

            {workspaceTab === 'headers' && (
              <div className="space-y-4">
                {/* Email Authentication Security Banner */}
                <div className="bg-navy-800 border border-navy-600 rounded-xl p-5 shadow-lg">
                  <h4 className="text-xs font-mono uppercase tracking-wider text-slate-400 mb-4 flex items-center gap-2">
                    <ShieldCheck className="w-4 h-4 text-accent-cyan" />
                    <span>Inbound RFC Email Authentication Standards</span>
                  </h4>
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                    <div className="bg-navy-900 border border-navy-700 rounded-lg p-3">
                      <p className="text-[11px] font-mono text-slate-400 uppercase">SPF Check</p>
                      <div className="mt-1 flex items-center justify-between">
                        {getAuthBadge(analysis.spf_result)}
                        <span className="text-[10px] text-slate-500 font-mono">RFC 7208</span>
                      </div>
                    </div>
                    <div className="bg-navy-900 border border-navy-700 rounded-lg p-3">
                      <p className="text-[11px] font-mono text-slate-400 uppercase">DKIM Check</p>
                      <div className="mt-1 flex items-center justify-between">
                        {getAuthBadge(analysis.dkim_result)}
                        <span className="text-[10px] text-slate-500 font-mono">RFC 6376</span>
                      </div>
                    </div>
                    <div className="bg-navy-900 border border-navy-700 rounded-lg p-3">
                      <p className="text-[11px] font-mono text-slate-400 uppercase">DMARC Policy</p>
                      <div className="mt-1 flex items-center justify-between">
                        {getAuthBadge(analysis.dmarc_result)}
                        <span className="text-[10px] text-slate-500 font-mono">RFC 7489</span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Parsed MIME Envelope Headers */}
                <div className="bg-navy-800 border border-navy-600 rounded-xl overflow-hidden shadow-lg">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-navy-900 font-mono uppercase text-slate-400 border-b border-navy-600">
                      <tr>
                        <th className="py-3 px-4 w-48">Header Parameter</th>
                        <th className="py-3 px-4">Observed Value</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-navy-700/60 font-mono">
                      <tr>
                        <td className="py-3 px-4 text-slate-400 font-semibold">Subject</td>
                        <td className="py-3 px-4 text-slate-200">{emailData.subject || '(None)'}</td>
                      </tr>
                      <tr>
                        <td className="py-3 px-4 text-slate-400 font-semibold">From (Raw)</td>
                        <td className="py-3 px-4 text-slate-200">{emailData.sender_raw || 'N/A'}</td>
                      </tr>
                      <tr>
                        <td className="py-3 px-4 text-slate-400 font-semibold">Parsed Sender Email</td>
                        <td className="py-3 px-4 text-slate-200 font-bold text-accent-cyan">
                          {emailData.sender_email || 'N/A'}
                        </td>
                      </tr>
                      <tr>
                        <td className="py-3 px-4 text-slate-400 font-semibold">Reply-To</td>
                        <td className="py-3 px-4 text-slate-200">{emailData.reply_to || '(None)'}</td>
                      </tr>
                      <tr>
                        <td className="py-3 px-4 text-slate-400 font-semibold">Return-Path</td>
                        <td className="py-3 px-4 text-slate-200">{emailData.return_path || '(None)'}</td>
                      </tr>
                      <tr>
                        <td className="py-3 px-4 text-slate-400 font-semibold">Message-ID</td>
                        <td className="py-3 px-4 text-slate-200 select-all">{emailData.message_id || 'N/A'}</td>
                      </tr>
                      <tr>
                        <td className="py-3 px-4 text-slate-400 font-semibold">SHA-256 EML Hash</td>
                        <td className="py-3 px-4 text-slate-400 select-all">{emailData.file_hash_sha256 || 'N/A'}</td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {workspaceTab === 'urls' && (
              <div className="bg-navy-800 border border-navy-600 rounded-xl overflow-hidden shadow-lg">
                <table className="w-full text-left text-xs">
                  <thead className="bg-navy-900 font-mono uppercase text-slate-400 border-b border-navy-600">
                    <tr>
                      <th className="py-3 px-4">Extracted URL</th>
                      <th className="py-3 px-4">Domain</th>
                      <th className="py-3 px-4">Threat Indicators & Evasion</th>
                      <th className="py-3 px-4 text-right">Reputation</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-navy-700/60">
                    {urls.length > 0 ? (
                      urls.map((u, i) => {
                        const reasons = (u.detection_reasons || []).join(' ').toLowerCase()
                        const hasDeceptiveAnchor =
                          reasons.includes('anchor') || reasons.includes('deceptive')
                        const hasFormAction = reasons.includes('form') || reasons.includes('action')
                        const hasMetaRefresh =
                          reasons.includes('meta refresh') || reasons.includes('refresh')

                        return (
                          <tr key={i} className="hover:bg-navy-750/50">
                            <td className="py-3 px-4 font-mono text-slate-300 max-w-sm truncate select-all">
                              {u.url_raw}
                            </td>
                            <td className="py-3 px-4 font-mono text-slate-400">{u.domain || 'N/A'}</td>
                            <td className="py-3 px-4">
                              <div className="flex flex-wrap gap-1.5">
                                {hasDeceptiveAnchor && (
                                  <Badge variant="critical">Deceptive Anchor</Badge>
                                )}
                                {hasFormAction && (
                                  <Badge variant="danger">Form Action Target</Badge>
                                )}
                                {hasMetaRefresh && (
                                  <Badge variant="danger">Meta Refresh Redirect</Badge>
                                )}
                                {u.is_shortener && <Badge variant="warning">Shortener</Badge>}
                                {u.is_ip_based && <Badge variant="danger">IP-Based</Badge>}
                                {u.is_punycode && <Badge variant="danger">Punycode</Badge>}
                                {u.has_suspicious_params && (
                                  <Badge variant="warning">Suspicious Params</Badge>
                                )}
                                {!u.is_shortener &&
                                  !u.is_ip_based &&
                                  !u.is_punycode &&
                                  !u.has_suspicious_params &&
                                  !hasDeceptiveAnchor &&
                                  !hasFormAction &&
                                  !hasMetaRefresh && (
                                    <Badge variant="outline">Standard</Badge>
                                  )}
                              </div>
                            </td>
                            <td className="py-3 px-4 text-right">
                              {u.is_malicious ? (
                                <Badge variant="critical">CONFIRMED MALICIOUS</Badge>
                              ) : (
                                <Badge variant="outline">BENIGN / UNRATED</Badge>
                              )}
                            </td>
                          </tr>
                        )
                      })
                    ) : (
                      <tr>
                        <td colSpan={4} className="py-6 text-center text-slate-500">
                          No embedded hyperlinks found in email content.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            )}

            {workspaceTab === 'attachments' && (
              <div className="bg-navy-800 border border-navy-600 rounded-xl overflow-hidden shadow-lg">
                <table className="w-full text-left text-xs">
                  <thead className="bg-navy-900 font-mono uppercase text-slate-400 border-b border-navy-600">
                    <tr>
                      <th className="py-3 px-4">Original Filename</th>
                      <th className="py-3 px-4">Declared MIME</th>
                      <th className="py-3 px-4">Magic Byte Detected</th>
                      <th className="py-3 px-4">Size</th>
                      <th className="py-3 px-4">SHA-256 Hash</th>
                      <th className="py-3 px-4 text-right">Risk Assessment</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-navy-700/60 font-mono">
                    {attachments.length > 0 ? (
                      attachments.map((a, i) => (
                        <tr key={i} className="hover:bg-navy-750/50">
                          <td className="py-3 px-4 font-semibold text-slate-200">
                            {a.filename_sanitized || 'attachment'}
                          </td>
                          <td className="py-3 px-4 text-slate-400">{a.mime_type_declared || 'N/A'}</td>
                          <td className="py-3 px-4">
                            {a.mime_type_mismatch ? (
                              <div className="flex items-center gap-1.5 text-rose-400 font-bold">
                                <AlertTriangle className="w-4 h-4 shrink-0" />
                                <span>{a.mime_type_detected || 'Executable (Mismatch)'}</span>
                              </div>
                            ) : (
                              <span className="text-slate-400">
                                {a.mime_type_detected || a.mime_type_declared || 'Verified'}
                              </span>
                            )}
                          </td>
                          <td className="py-3 px-4 text-slate-400">
                            {a.file_size_bytes ? `${Math.round(a.file_size_bytes / 1024)} KB` : 'N/A'}
                          </td>
                          <td className="py-3 px-4 text-slate-400 truncate max-w-xs select-all">
                            {a.sha256_hash}
                          </td>
                          <td className="py-3 px-4 text-right">
                            <Badge
                              variant={
                                a.is_executable || a.mime_type_mismatch || a.risk_level === 'critical'
                                  ? 'critical'
                                  : a.has_macro_indicator || a.risk_level === 'high'
                                  ? 'danger'
                                  : 'outline'
                              }
                            >
                              {a.mime_type_mismatch
                                ? 'CRITICAL DISGUISED'
                                : (a.risk_level || 'UNKNOWN').toUpperCase()}
                            </Badge>
                          </td>
                        </tr>
                      ))
                    ) : (
                      <tr>
                        <td colSpan={6} className="py-6 text-center text-slate-500">
                          No file attachments detected in this message.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            )}

            {workspaceTab === 'ai' && (
              <AIAnalysisPanel
                summary={analysis.ai_summary}
                assessment={analysis.ai_phishing_assessment}
                confidence={analysis.ai_confidence}
                findings={analysis.ai_findings}
                recommendedActions={analysis.ai_recommended_actions}
                provider={analysis.ai_provider}
                model={analysis.ai_model}
                isAvailable={analysis.ai_analysis_available}
              />
            )}

            {workspaceTab === 'iocs' && (
              <div className="bg-navy-800 border border-navy-600 rounded-xl overflow-hidden shadow-lg">
                <table className="w-full text-left text-xs">
                  <thead className="bg-navy-900 font-mono uppercase text-slate-400 border-b border-navy-600">
                    <tr>
                      <th className="py-3 px-4">IOC Type</th>
                      <th className="py-3 px-4">Observable Value</th>
                      <th className="py-3 px-4">Extraction Source</th>
                      <th className="py-3 px-4">Risk</th>
                      <th className="py-3 px-4">Detection Reason</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-navy-700/60 font-mono">
                    {iocs.length > 0 ? (
                      iocs.map((ioc, i) => (
                        <tr key={i} className="hover:bg-navy-750/50">
                          <td className="py-3 px-4 font-bold text-accent-cyan uppercase">
                            {ioc.ioc_type}
                          </td>
                          <td className="py-3 px-4 text-slate-200 select-all">{ioc.ioc_value}</td>
                          <td className="py-3 px-4 text-slate-400">{ioc.source_location || 'Body'}</td>
                          <td className="py-3 px-4">
                            <Badge
                              variant={
                                ioc.risk_level === 'critical' || ioc.risk_level === 'high'
                                  ? 'danger'
                                  : 'warning'
                              }
                            >
                              {ioc.risk_level}
                            </Badge>
                          </td>
                          <td className="py-3 px-4 text-slate-400 font-sans text-xs">
                            {ioc.detection_reason || 'Extracted IOC indicator'}
                          </td>
                        </tr>
                      ))
                    ) : (
                      <tr>
                        <td colSpan={5} className="py-6 text-center text-slate-500">
                          No indicators of compromise extracted.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

export default function EmailAnalyzerPage() {
  return (
    <Suspense
      fallback={
        <div className="flex items-center justify-center min-h-[50vh] text-slate-400">
          <Loader2 className="w-8 h-8 animate-spin text-accent-blue" />
        </div>
      }
    >
      <EmailAnalyzerContent />
    </Suspense>
  )
}
