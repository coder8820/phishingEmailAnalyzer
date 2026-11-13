'use client'

import React, { useEffect, useState } from 'react'
import Link from 'next/link'
import { useRouter } from 'next/navigation'
import { History, Search, RefreshCw, Trash2, ExternalLink, ShieldCheck, Mail, ArrowUpRight } from 'lucide-react'
import { toast } from 'sonner'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Badge } from '@/components/ui/Badge'
import { EmptyState } from '@/components/ui/EmptyState'
import { listEmails, deleteEmail } from '@/services/emailService'
import { formatDate, cn } from '@/lib/utils'
import type { Email } from '@/types'

export default function InvestigationHistoryPage() {
  const router = useRouter()
  const [emails, setEmails] = useState<Email[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState<string>('all')

  const fetchEmails = async () => {
    setIsLoading(true)
    try {
      const data = await listEmails({ page: 1, page_size: 50 })
      setEmails(data.items)
    } catch {
      toast.error('Failed to load investigation history')
    } finally {
      setIsLoading(false)
    }
  }

  useEffect(() => {
    fetchEmails()
  }, [])

  const handleDelete = async (id: string) => {
    if (!confirm('Are you sure you want to delete this email from history?')) return
    try {
      await deleteEmail(id)
      setEmails((prev) => prev.filter((e) => e.id !== id))
      toast.success('Investigation record removed')
    } catch {
      toast.error('Failed to delete email record')
    }
  }

  const filtered = emails.filter((e) => {
    const matchesSearch =
      (e.subject || '').toLowerCase().includes(search.toLowerCase()) ||
      (e.sender_email || '').toLowerCase().includes(search.toLowerCase())
    const matchesStatus = statusFilter === 'all' || e.analysis_status === statusFilter
    return matchesSearch && matchesStatus
  })

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      <Card className="border-navy-600 bg-navy-800 shadow-xl">
        <CardHeader>
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div>
              <CardTitle className="flex items-center gap-2">
                <History className="w-5 h-5 text-accent-blue" />
                <span>Investigation History</span>
              </CardTitle>
              <p className="text-xs text-slate-400 mt-1">
                Audit trail and telemetry for all analyzed email submissions.
              </p>
            </div>

            <Button variant="outline" size="sm" onClick={fetchEmails} isLoading={isLoading}>
              <RefreshCw className="w-4 h-4" /> Refresh
            </Button>
          </div>
        </CardHeader>

        <CardContent>
          {/* Filters */}
          <div className="flex flex-col md:flex-row gap-3 mb-6">
            <div className="relative flex-1">
              <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search by subject or sender email..."
                className="w-full bg-navy-900 border border-navy-600 rounded-lg pl-9 pr-4 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-accent-blue"
              />
            </div>

            <div className="flex gap-2">
              {['all', 'complete', 'processing', 'failed'].map((st) => (
                <button
                  key={st}
                  onClick={() => setStatusFilter(st)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-mono uppercase transition-colors ${
                    statusFilter === st
                      ? 'bg-accent-blue text-white font-semibold'
                      : 'bg-navy-900 border border-navy-700 text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {st}
                </button>
              ))}
            </div>
          </div>

          {/* Table */}
          {filtered.length > 0 ? (
            <div className="border border-navy-600 rounded-xl overflow-hidden">
              <table className="w-full text-left text-xs">
                <thead className="bg-navy-900 font-mono uppercase text-slate-400 border-b border-navy-600">
                  <tr>
                    <th className="py-3 px-4">Subject Line</th>
                    <th className="py-3 px-4">Sender Address</th>
                    <th className="py-3 px-4">Ingested At</th>
                    <th className="py-3 px-4">Status</th>
                    <th className="py-3 px-4 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-navy-700/60 bg-navy-800">
                  {filtered.map((em) => (
                    <tr
                      key={em.id}
                      onClick={() => router.push(`/email-analyzer?id=${em.id}`)}
                      className="hover:bg-navy-750/70 transition-colors cursor-pointer group"
                    >
                      <td className="py-3.5 px-4 font-semibold text-slate-200 max-w-xs truncate group-hover:text-accent-cyan transition-colors">
                        {em.subject || '(No Subject)'}
                      </td>
                      <td className="py-3.5 px-4 font-mono text-slate-400 max-w-xs truncate">
                        {em.sender_email || 'Unknown'}
                      </td>
                      <td className="py-3.5 px-4 text-slate-400">{formatDate(em.created_at)}</td>
                      <td className="py-3.5 px-4">
                        <Badge
                          variant={
                            em.analysis_status === 'complete'
                              ? 'success'
                              : em.analysis_status === 'failed'
                              ? 'critical'
                              : 'warning'
                          }
                        >
                          {em.analysis_status.toUpperCase()}
                        </Badge>
                      </td>
                      <td className="py-3.5 px-4 text-right space-x-1" onClick={(e) => e.stopPropagation()}>
                        <button
                          onClick={() => router.push(`/email-analyzer?id=${em.id}`)}
                          className="p-1.5 text-slate-400 hover:text-accent-cyan hover:bg-navy-700 rounded transition-colors inline-flex items-center gap-1"
                          title="Open in Threat Workspace"
                        >
                          <ArrowUpRight className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => handleDelete(em.id)}
                          className="p-1.5 text-slate-400 hover:text-red-400 hover:bg-navy-700 rounded transition-colors inline-flex items-center"
                          title="Delete"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <EmptyState
              icon={<Mail className="w-10 h-10 text-slate-500" />}
              title="No Email Records Found"
              description="No analyzed emails match your search parameters or no emails have been ingested yet."
              action={
                <Link href="/email-analyzer">
                  <Button size="sm">Go to Analyzer</Button>
                </Link>
              }
            />
          )}
        </CardContent>
      </Card>
    </div>
  )
}
