'use client'

import React, { useEffect, useState } from 'react'
import Link from 'next/link'
import { ScrollText, Search, RefreshCw, ShieldAlert, Filter, Lock, ArrowRight, ShieldCheck } from 'lucide-react'
import { toast } from 'sonner'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Badge } from '@/components/ui/Badge'
import { EmptyState } from '@/components/ui/EmptyState'
import { apiClient } from '@/lib/api'
import { formatDate } from '@/lib/utils'
import { useAuthStore } from '@/store/authStore'

interface AuditLogEntry {
  id: string
  action: string
  resource_type?: string
  resource_id?: string
  ip_address?: string
  user_id?: string
  severity: string
  details: Record<string, any>
  created_at: string
}

export default function AuditLogsPage() {
  const { user } = useAuthStore()
  const isAdmin = user?.role === 'super_admin' || user?.role === 'security_admin'

  const [logs, setLogs] = useState<AuditLogEntry[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [search, setSearch] = useState('')

  const fetchLogs = async () => {
    if (!isAdmin) return
    setIsLoading(true)
    try {
      const res = await apiClient.get('/audit-logs?page=1&page_size=100')
      setLogs(res.data.data.items || [])
    } catch {
      toast.error('Failed to load audit logs')
    } finally {
      setIsLoading(false)
    }
  }

  useEffect(() => {
    fetchLogs()
  }, [isAdmin])

  // If Normal User (Not Admin), restrict access
  if (!isAdmin) {
    return (
      <div className="max-w-3xl mx-auto py-16 px-4 text-center space-y-6">
        <div className="w-16 h-16 rounded-2xl bg-purple-500/10 border border-purple-500/30 flex items-center justify-center mx-auto text-purple-400 shadow-xl">
          <Lock className="w-8 h-8" />
        </div>
        <div className="space-y-2">
          <Badge variant="outline" className="text-purple-300 border-purple-500/40">
            RESTRICTED AUDIT VAULT
          </Badge>
          <h1 className="text-2xl font-black text-white">Super Admin Access Required</h1>
          <p className="text-sm text-slate-400 max-w-lg mx-auto leading-relaxed">
            Immutable SOC Audit Trails and tenant compliance event logs are restricted exclusively to Super Administrators and Security Administrators.
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
            <span>Contact Super Admin Desk</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </Link>
        </div>
      </div>
    )
  }

  const filtered = logs.filter(
    (l) =>
      l.action.toLowerCase().includes(search.toLowerCase()) ||
      (l.ip_address || '').includes(search)
  )

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      <Card className="border-navy-600 bg-navy-800 shadow-xl">
        <CardHeader>
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div>
              <CardTitle className="flex items-center gap-2">
                <ScrollText className="w-5 h-5 text-accent-blue" />
                <span>Immutable Security Audit Log</span>
              </CardTitle>
              <p className="text-xs text-slate-400 mt-1">
                Tamper-resistant audit events for administrative operations, authentication flows, and security actions.
              </p>
            </div>

            <Button variant="outline" size="sm" onClick={fetchLogs} isLoading={isLoading}>
              <RefreshCw className="w-4 h-4" /> Refresh
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          <div className="mb-4">
            <div className="relative w-full max-w-md">
              <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
              <input
                type="text"
                placeholder="Search audit actions, IP addresses..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="w-full bg-navy-900 border border-navy-700 rounded-lg pl-9 pr-4 py-2 text-xs text-slate-200 focus:outline-none focus:border-accent-blue placeholder-slate-500"
              />
            </div>
          </div>

          <div className="overflow-x-auto rounded-lg border border-navy-700">
            <table className="w-full text-left text-xs">
              <thead className="bg-navy-900 border-b border-navy-700 text-slate-400 uppercase font-mono text-[10px]">
                <tr>
                  <th className="py-3 px-4">Timestamp</th>
                  <th className="py-3 px-4">Action</th>
                  <th className="py-3 px-4">Resource</th>
                  <th className="py-3 px-4">IP Address</th>
                  <th className="py-3 px-4">Severity</th>
                  <th className="py-3 px-4">Telemetry</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-navy-700/60 font-mono">
                {filtered.map((log) => (
                  <tr key={log.id} className="hover:bg-navy-700/30 transition-colors">
                    <td className="py-3 px-4 text-slate-400 whitespace-nowrap">
                      {formatDate(log.created_at)}
                    </td>
                    <td className="py-3 px-4 font-bold text-slate-200">{log.action}</td>
                    <td className="py-3 px-4 text-slate-300">
                      {log.resource_type ? `${log.resource_type}` : 'System'}
                    </td>
                    <td className="py-3 px-4 text-slate-400">{log.ip_address || 'Internal'}</td>
                    <td className="py-3 px-4">
                      <Badge
                        variant={
                          log.severity === 'critical'
                            ? 'critical'
                            : log.severity === 'high'
                            ? 'warning'
                            : 'outline'
                        }
                      >
                        {log.severity.toUpperCase()}
                      </Badge>
                    </td>
                    <td className="py-3 px-4 text-slate-400 max-w-xs truncate text-[11px]">
                      {JSON.stringify(log.details)}
                    </td>
                  </tr>
                ))}
                {filtered.length === 0 && !isLoading && (
                  <tr>
                    <td colSpan={6} className="text-center py-8 text-slate-500">
                      No audit events matching criteria.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
