'use client'

import React, { useEffect, useState } from 'react'
import { Search, Download, CheckCircle, AlertOctagon, RefreshCw, Filter } from 'lucide-react'
import { toast } from 'sonner'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Badge } from '@/components/ui/Badge'
import { EmptyState } from '@/components/ui/EmptyState'
import { listIOCs, updateIOC, exportIOCs } from '@/services/iocService'
import { formatDate } from '@/lib/utils'
import type { IOC } from '@/types'

export default function IOCExplorerPage() {
  const [iocs, setIocs] = useState<IOC[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [typeFilter, setTypeFilter] = useState('all')

  const fetchIOCs = async () => {
    setIsLoading(true)
    try {
      const res = await listIOCs({ page: 1, page_size: 100 })
      setIocs(res.items)
    } catch {
      toast.error('Failed to load IOC repository')
    } finally {
      setIsLoading(false)
    }
  }

  useEffect(() => {
    fetchIOCs()
  }, [])

  const handleToggleFP = async (ioc: IOC) => {
    const updatedStatus = !ioc.is_false_positive
    try {
      await updateIOC(ioc.id, { is_false_positive: updatedStatus })
      setIocs((prev) =>
        prev.map((i) => (i.id === ioc.id ? { ...i, is_false_positive: updatedStatus } : i))
      )
      toast.success(
        updatedStatus ? 'Marked observable as False Positive' : 'Restored observable to Active IOC'
      )
    } catch {
      toast.error('Failed to update observable state')
    }
  }

  const handleExport = async (format: 'json' | 'csv') => {
    try {
      const blob = await exportIOCs(format)
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `phishguard_iocs_${new Date().toISOString().slice(0, 10)}.${format}`
      document.body.appendChild(a)
      a.click()
      window.URL.revokeObjectURL(url)
      toast.success(`Exported IOCs as ${format.toUpperCase()}`)
    } catch {
      toast.error('Failed to export observables')
    }
  }

  const filtered = iocs.filter((ioc) => {
    const matchesSearch =
      ioc.ioc_value.toLowerCase().includes(search.toLowerCase()) ||
      (ioc.detection_reason || '').toLowerCase().includes(search.toLowerCase())
    const matchesType = typeFilter === 'all' || ioc.ioc_type === typeFilter
    return matchesSearch && matchesType
  })

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      <Card className="border-navy-600 bg-navy-800 shadow-xl">
        <CardHeader>
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div>
              <CardTitle className="flex items-center gap-2">
                <Search className="w-5 h-5 text-accent-cyan" />
                <span>Indicators of Compromise (IOC) Explorer</span>
              </CardTitle>
              <p className="text-xs text-slate-400 mt-1">
                Extracted malicious observables, network endpoints, file hashes, and threat artifacts.
              </p>
            </div>

            <div className="flex items-center gap-2">
              <Button variant="secondary" size="sm" onClick={() => handleExport('json')}>
                <Download className="w-4 h-4" /> JSON
              </Button>
              <Button variant="secondary" size="sm" onClick={() => handleExport('csv')}>
                <Download className="w-4 h-4" /> CSV
              </Button>
              <Button variant="outline" size="sm" onClick={fetchIOCs} isLoading={isLoading}>
                <RefreshCw className="w-4 h-4" />
              </Button>
            </div>
          </div>
        </CardHeader>

        <CardContent>
          {/* Filter Bar */}
          <div className="flex flex-col md:flex-row gap-3 mb-6">
            <div className="relative flex-1">
              <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search IOC observable value or reason..."
                className="w-full bg-navy-900 border border-navy-600 rounded-lg pl-9 pr-4 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-accent-cyan"
              />
            </div>

            <div className="flex flex-wrap gap-1.5">
              {['all', 'ip', 'domain', 'url', 'hash_sha256', 'email'].map((t) => (
                <button
                  key={t}
                  onClick={() => setTypeFilter(t)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-mono uppercase transition-colors ${
                    typeFilter === t
                      ? 'bg-accent-cyan text-navy-950 font-bold'
                      : 'bg-navy-900 border border-navy-700 text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {t.replace('hash_sha256', 'sha256')}
                </button>
              ))}
            </div>
          </div>

          {/* IOC Table */}
          {filtered.length > 0 ? (
            <div className="border border-navy-600 rounded-xl overflow-hidden">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-navy-900 uppercase text-slate-400 border-b border-navy-600">
                  <tr>
                    <th className="py-3 px-4">Type</th>
                    <th className="py-3 px-4">Observable Artifact</th>
                    <th className="py-3 px-4">Confidence</th>
                    <th className="py-3 px-4">Detection Reason</th>
                    <th className="py-3 px-4">First Observed</th>
                    <th className="py-3 px-4 text-right">False Positive</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-navy-700/60 bg-navy-800">
                  {filtered.map((ioc) => (
                    <tr
                      key={ioc.id}
                      className={`hover:bg-navy-750/50 transition-colors ${
                        ioc.is_false_positive ? 'opacity-50' : ''
                      }`}
                    >
                      <td className="py-3.5 px-4 font-bold text-accent-cyan uppercase">
                        {ioc.ioc_type.replace('hash_', '')}
                      </td>
                      <td className="py-3.5 px-4 text-slate-200 select-all max-w-sm truncate">
                        {ioc.ioc_value}
                      </td>
                      <td className="py-3.5 px-4">
                        <Badge
                          variant={
                            ioc.is_false_positive
                              ? 'outline'
                              : ioc.risk_level === 'critical' || ioc.risk_level === 'high'
                              ? 'critical'
                              : 'warning'
                          }
                        >
                          {ioc.is_false_positive ? 'FP SUPPRESSED' : ioc.risk_level?.toUpperCase()}
                        </Badge>
                      </td>
                      <td className="py-3.5 px-4 font-sans text-slate-400 max-w-xs truncate">
                        {ioc.detection_reason || 'Identified during email inspection'}
                      </td>
                      <td className="py-3.5 px-4 text-slate-400">{formatDate(ioc.created_at)}</td>
                      <td className="py-3.5 px-4 text-right">
                        <button
                          onClick={() => handleToggleFP(ioc)}
                          className={`px-2.5 py-1 rounded text-[11px] font-sans transition-colors ${
                            ioc.is_false_positive
                              ? 'bg-navy-700 text-slate-300 hover:bg-navy-600'
                              : 'bg-yellow-500/10 text-yellow-400 hover:bg-yellow-500/20'
                          }`}
                        >
                          {ioc.is_false_positive ? 'Unmark FP' : 'Mark FP'}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <EmptyState
              icon={<Search className="w-10 h-10 text-slate-500" />}
              title="No Observables Found"
              description="No IOCs match your filter criteria."
            />
          )}
        </CardContent>
      </Card>
    </div>
  )
}
