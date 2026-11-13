'use client'

import React, { useEffect, useState } from 'react'
import { FileText, Download, Search, RefreshCw, FileCode, CheckCircle2, Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Badge } from '@/components/ui/Badge'
import { EmptyState } from '@/components/ui/EmptyState'
import { listEmails } from '@/services/emailService'
import { apiClient } from '@/lib/api'
import { formatDate } from '@/lib/utils'
import type { Email } from '@/types'

export default function ReportsPage() {
  const [emails, setEmails] = useState<Email[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [downloadingId, setDownloadingId] = useState<string | null>(null)

  const fetchAnalyzed = async () => {
    setIsLoading(true)
    try {
      const res = await listEmails({ page: 1, page_size: 100, status: 'complete' })
      setEmails(res.items)
    } catch {
      toast.error('Failed to load analyzed emails')
    } finally {
      setIsLoading(false)
    }
  }

  useEffect(() => {
    fetchAnalyzed()
  }, [])

  const handleDownloadReport = async (emailId: string, format: 'json' | 'csv' | 'txt') => {
    const key = `${emailId}_${format}`
    setDownloadingId(key)
    try {
      const res = await apiClient.get(`/reports/email/${emailId}?format=${format}`, {
        responseType: 'blob',
      })
      const mimeType =
        format === 'json'
          ? 'application/json'
          : format === 'csv'
          ? 'text/csv'
          : 'text/plain'
      const blob = new Blob([res.data], { type: mimeType })
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `phishguard_report_${emailId.slice(0, 8)}.${format}`
      document.body.appendChild(a)
      a.click()
      window.URL.revokeObjectURL(url)
      document.body.removeChild(a)
      toast.success(`Exported ${format.toUpperCase()} incident report`)
    } catch {
      toast.error('Failed to download investigation report')
    } finally {
      setDownloadingId(null)
    }
  }

  const filtered = emails.filter((em) => {
    return (
      (em.subject || '').toLowerCase().includes(search.toLowerCase()) ||
      (em.sender_email || '').toLowerCase().includes(search.toLowerCase())
    )
  })

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      <Card className="border-navy-600 bg-navy-800 shadow-xl">
        <CardHeader>
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div>
              <CardTitle className="flex items-center gap-2">
                <FileText className="w-5 h-5 text-accent-cyan" />
                <span>Executive & Technical Forensic Reports</span>
              </CardTitle>
              <p className="text-xs text-slate-400 mt-1">
                Generate and export tamper-evident forensic dossiers in JSON, CSV, and plain-text executive formats.
              </p>
            </div>

            <Button variant="outline" size="sm" onClick={fetchAnalyzed} isLoading={isLoading}>
              <RefreshCw className="w-4 h-4" /> Refresh
            </Button>
          </div>
        </CardHeader>

        <CardContent className="space-y-4">
          <div className="relative max-w-md">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search reports by subject or sender..."
              className="w-full bg-navy-900 border border-navy-600 rounded-lg pl-9 pr-4 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-accent-blue"
            />
          </div>

          {filtered.length > 0 ? (
            <div className="border border-navy-600 rounded-xl overflow-hidden">
              <table className="w-full text-left text-xs">
                <thead className="bg-navy-900 font-mono uppercase text-slate-400 border-b border-navy-600">
                  <tr>
                    <th className="py-3 px-4">Subject</th>
                    <th className="py-3 px-4">Sender Address</th>
                    <th className="py-3 px-4">Analysis Date</th>
                    <th className="py-3 px-4 text-right">Available Exports</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-navy-700/60 bg-navy-800">
                  {filtered.map((em) => (
                    <tr key={em.id} className="hover:bg-navy-750/50 transition-colors">
                      <td className="py-3.5 px-4 font-semibold text-slate-200 max-w-sm truncate">
                        {em.subject || '(No Subject)'}
                      </td>
                      <td className="py-3.5 px-4 font-mono text-slate-400 max-w-xs truncate">
                        {em.sender_email || 'Unknown'}
                      </td>
                      <td className="py-3.5 px-4 text-slate-400 font-mono">{formatDate(em.created_at)}</td>
                      <td className="py-3.5 px-4 text-right space-x-2">
                        <Button
                          variant="outline"
                          size="sm"
                          disabled={downloadingId === `${em.id}_json`}
                          onClick={() => handleDownloadReport(em.id, 'json')}
                        >
                          {downloadingId === `${em.id}_json` ? (
                            <Loader2 className="w-3.5 h-3.5 animate-spin" />
                          ) : (
                            <FileCode className="w-3.5 h-3.5" />
                          )}{' '}
                          JSON
                        </Button>
                        <Button
                          variant="outline"
                          size="sm"
                          disabled={downloadingId === `${em.id}_csv`}
                          onClick={() => handleDownloadReport(em.id, 'csv')}
                        >
                          {downloadingId === `${em.id}_csv` ? (
                            <Loader2 className="w-3.5 h-3.5 animate-spin" />
                          ) : (
                            <Download className="w-3.5 h-3.5" />
                          )}{' '}
                          CSV
                        </Button>
                        <Button
                          variant="outline"
                          size="sm"
                          disabled={downloadingId === `${em.id}_txt`}
                          onClick={() => handleDownloadReport(em.id, 'txt')}
                        >
                          {downloadingId === `${em.id}_txt` ? (
                            <Loader2 className="w-3.5 h-3.5 animate-spin" />
                          ) : (
                            <FileText className="w-3.5 h-3.5" />
                          )}{' '}
                          Executive TXT
                        </Button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <EmptyState
              icon={<FileText className="w-10 h-10 text-slate-500" />}
              title="No Completed Analyses for Reports"
              description="Analyze suspicious emails in the Email Analyzer to generate downloadable SOC reports."
            />
          )}
        </CardContent>
      </Card>
    </div>
  )
}
