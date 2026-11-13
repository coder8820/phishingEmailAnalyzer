'use client'

import React, { useEffect, useState } from 'react'
import {
  AlertTriangle,
  Plus,
  Search,
  RefreshCw,
  Clock,
  CheckCircle2,
  User,
  ShieldAlert,
  Flame,
  FileText,
  MessageSquare,
  Send,
  X,
  ExternalLink,
  ChevronRight,
  Filter,
} from 'lucide-react'
import { toast } from 'sonner'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Badge } from '@/components/ui/Badge'
import { EmptyState } from '@/components/ui/EmptyState'
import {
  listIncidents,
  getIncident,
  createIncident,
  updateIncident,
  addIncidentNote,
} from '@/services/incidentService'
import { formatDate } from '@/lib/utils'
import type { Incident, InvestigationNote } from '@/types'

export default function IncidentsPage() {
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState('all')

  // Create Modal
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [newTitle, setNewTitle] = useState('')
  const [newDesc, setNewDesc] = useState('')
  const [newSeverity, setNewSeverity] = useState('medium')

  // Selected Incident Detail Drawer
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null)
  const [incidentDetail, setIncidentDetail] = useState<(Incident & { notes: InvestigationNote[] }) | null>(null)
  const [isLoadingDetail, setIsLoadingDetail] = useState(false)
  const [newNoteContent, setNewNoteContent] = useState('')
  const [newNoteType, setNewNoteType] = useState('note')
  const [isSubmittingNote, setIsSubmittingNote] = useState(false)

  const fetchIncidents = async () => {
    setIsLoading(true)
    try {
      const res = await listIncidents({ page: 1, page_size: 100 })
      setIncidents(res.items)
    } catch {
      toast.error('Failed to load SOC incidents')
    } finally {
      setIsLoading(false)
    }
  }

  useEffect(() => {
    fetchIncidents()
  }, [])

  const loadIncidentDetail = async (id: string) => {
    setSelectedIncidentId(id)
    setIsLoadingDetail(true)
    try {
      const detail = await getIncident(id)
      setIncidentDetail(detail)
    } catch {
      toast.error('Failed to fetch incident details')
      setSelectedIncidentId(null)
    } finally {
      setIsLoadingDetail(false)
    }
  }

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!newTitle.trim()) return
    try {
      const res = await createIncident({
        title: newTitle,
        description: newDesc,
        severity: newSeverity,
      })
      toast.success(`Incident #${res.incident_number} created successfully`)
      setShowCreateModal(false)
      setNewTitle('')
      setNewDesc('')
      fetchIncidents()
      loadIncidentDetail(res.id)
    } catch {
      toast.error('Failed to create incident')
    }
  }

  const handleStatusChange = async (id: string, newStatus: string) => {
    try {
      await updateIncident(id, { status: newStatus })
      setIncidents((prev) =>
        prev.map((inc) => (inc.id === id ? { ...inc, status: newStatus as any } : inc))
      )
      if (incidentDetail && incidentDetail.id === id) {
        setIncidentDetail({ ...incidentDetail, status: newStatus as any })
      }
      toast.success('Incident status updated')
    } catch {
      toast.error('Failed to update incident status')
    }
  }

  const handleSeverityChange = async (id: string, newSeverity: string) => {
    try {
      await updateIncident(id, { severity: newSeverity })
      setIncidents((prev) =>
        prev.map((inc) => (inc.id === id ? { ...inc, severity: newSeverity } : inc))
      )
      if (incidentDetail && incidentDetail.id === id) {
        setIncidentDetail({ ...incidentDetail, severity: newSeverity })
      }
      toast.success('Severity rating updated')
    } catch {
      toast.error('Failed to update severity')
    }
  }

  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!selectedIncidentId || !newNoteContent.trim()) return
    setIsSubmittingNote(true)
    try {
      const createdNote = await addIncidentNote(selectedIncidentId, {
        content: newNoteContent.trim(),
        note_type: newNoteType,
      })
      if (incidentDetail) {
        setIncidentDetail({
          ...incidentDetail,
          notes: [...(incidentDetail.notes || []), createdNote],
        })
      }
      setNewNoteContent('')
      toast.success('Investigation note recorded')
    } catch {
      toast.error('Failed to add note')
    } finally {
      setIsSubmittingNote(false)
    }
  }

  const filtered = incidents.filter((inc) => {
    const matchesStatus = statusFilter === 'all' ? true : inc.status === statusFilter
    const matchesSearch =
      (inc.title || '').toLowerCase().includes(search.toLowerCase()) ||
      (inc.description || '').toLowerCase().includes(search.toLowerCase()) ||
      String(inc.incident_number || '').includes(search)
    return matchesStatus && matchesSearch
  })

  // Summary Metrics
  const totalCount = incidents.length
  const investigatingCount = incidents.filter((i) => i.status === 'under_investigation').length
  const escalatedCount = incidents.filter((i) => i.status === 'escalated' || i.severity === 'critical').length
  const resolvedCount = incidents.filter((i) => i.status === 'resolved' || i.status === 'false_positive').length

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Top SOC Metrics Summary */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-navy-800 border border-navy-600 rounded-xl p-4 shadow-lg flex items-center gap-4">
          <div className="w-12 h-12 rounded-xl bg-accent-blue/15 flex items-center justify-center border border-accent-blue/30 text-accent-cyan">
            <FileText className="w-6 h-6" />
          </div>
          <div>
            <p className="text-xs uppercase font-mono tracking-wider text-slate-400">Total Incidents</p>
            <p className="text-2xl font-bold font-mono text-slate-100">{totalCount}</p>
          </div>
        </div>

        <div className="bg-navy-800 border border-navy-600 rounded-xl p-4 shadow-lg flex items-center gap-4">
          <div className="w-12 h-12 rounded-xl bg-amber-500/15 flex items-center justify-center border border-amber-500/30 text-amber-400">
            <Clock className="w-6 h-6" />
          </div>
          <div>
            <p className="text-xs uppercase font-mono tracking-wider text-slate-400">Under Investigation</p>
            <p className="text-2xl font-bold font-mono text-amber-400">{investigatingCount}</p>
          </div>
        </div>

        <div className="bg-navy-800 border border-navy-600 rounded-xl p-4 shadow-lg flex items-center gap-4">
          <div className="w-12 h-12 rounded-xl bg-red-500/15 flex items-center justify-center border border-red-500/30 text-red-400">
            <Flame className="w-6 h-6" />
          </div>
          <div>
            <p className="text-xs uppercase font-mono tracking-wider text-slate-400">Critical / Escalated</p>
            <p className="text-2xl font-bold font-mono text-red-400">{escalatedCount}</p>
          </div>
        </div>

        <div className="bg-navy-800 border border-navy-600 rounded-xl p-4 shadow-lg flex items-center gap-4">
          <div className="w-12 h-12 rounded-xl bg-emerald-500/15 flex items-center justify-center border border-emerald-500/30 text-emerald-400">
            <CheckCircle2 className="w-6 h-6" />
          </div>
          <div>
            <p className="text-xs uppercase font-mono tracking-wider text-slate-400">Resolved Cases</p>
            <p className="text-2xl font-bold font-mono text-emerald-400">{resolvedCount}</p>
          </div>
        </div>
      </div>

      {/* Main Incident Card */}
      <Card className="border-navy-600 bg-navy-800 shadow-xl">
        <CardHeader>
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div>
              <CardTitle className="flex items-center gap-2">
                <ShieldAlert className="w-5 h-5 text-accent-cyan" />
                <span>Enterprise SOC Incident Management</span>
              </CardTitle>
              <p className="text-xs text-slate-400 mt-1">
                Security operations command center for threat tracking, forensic timeline notes, and team remediation.
              </p>
            </div>

            <div className="flex items-center gap-2">
              <Button size="sm" onClick={() => setShowCreateModal(true)}>
                <Plus className="w-4 h-4" /> Create Incident
              </Button>
              <Button variant="outline" size="sm" onClick={fetchIncidents} isLoading={isLoading}>
                <RefreshCw className="w-4 h-4" />
              </Button>
            </div>
          </div>
        </CardHeader>

        <CardContent className="space-y-4">
          {/* Search and Filter controls */}
          <div className="flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3">
            <div className="relative flex-1 max-w-md">
              <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search by ID, keyword, or summary..."
                className="w-full bg-navy-900 border border-navy-600 rounded-lg pl-9 pr-4 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-accent-blue"
              />
            </div>

            {/* Status Filter Tabs */}
            <div className="flex flex-wrap gap-1.5">
              {['all', 'new', 'under_investigation', 'escalated', 'resolved', 'false_positive'].map(
                (st) => (
                  <button
                    key={st}
                    onClick={() => setStatusFilter(st)}
                    className={`px-3 py-1.5 rounded-lg text-xs font-mono uppercase transition-colors ${
                      statusFilter === st
                        ? 'bg-accent-blue text-white font-semibold shadow'
                        : 'bg-navy-900 border border-navy-700 text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {st.replace('_', ' ')}
                  </button>
                )
              )}
            </div>
          </div>

          {/* Incident Table */}
          {filtered.length > 0 ? (
            <div className="border border-navy-600 rounded-xl overflow-hidden">
              <table className="w-full text-left text-xs">
                <thead className="bg-navy-900 font-mono uppercase text-slate-400 border-b border-navy-600">
                  <tr>
                    <th className="py-3 px-4 w-28">Incident #</th>
                    <th className="py-3 px-4">Title & Context</th>
                    <th className="py-3 px-4 w-28">Severity</th>
                    <th className="py-3 px-4 w-36">Status</th>
                    <th className="py-3 px-4 w-32">Created</th>
                    <th className="py-3 px-4 text-right w-24">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-navy-700/60 bg-navy-800">
                  {filtered.map((inc) => (
                    <tr
                      key={inc.id}
                      onClick={() => loadIncidentDetail(inc.id)}
                      className={`cursor-pointer transition-colors ${
                        selectedIncidentId === inc.id
                          ? 'bg-navy-700/70'
                          : 'hover:bg-navy-750/50'
                      }`}
                    >
                      <td className="py-3.5 px-4 font-mono font-bold text-accent-cyan">
                        #{inc.incident_number || '---'}
                      </td>
                      <td className="py-3.5 px-4 max-w-md">
                        <p className="font-semibold text-slate-200 text-sm truncate">{inc.title}</p>
                        {inc.description && (
                          <p className="text-slate-400 text-xs truncate mt-0.5">{inc.description}</p>
                        )}
                      </td>
                      <td className="py-3.5 px-4" onClick={(e) => e.stopPropagation()}>
                        <select
                          value={inc.severity}
                          onChange={(e) => handleSeverityChange(inc.id, e.target.value)}
                          className="bg-navy-900 border border-navy-600 rounded px-2 py-1 text-xs font-mono font-semibold uppercase text-slate-200 focus:outline-none focus:border-accent-blue"
                        >
                          <option value="low">Low</option>
                          <option value="medium">Medium</option>
                          <option value="high">High</option>
                          <option value="critical">Critical</option>
                        </select>
                      </td>
                      <td className="py-3.5 px-4" onClick={(e) => e.stopPropagation()}>
                        <select
                          value={inc.status}
                          onChange={(e) => handleStatusChange(inc.id, e.target.value)}
                          className={`rounded px-2.5 py-1 text-xs font-mono font-semibold uppercase border focus:outline-none ${
                            inc.status === 'resolved'
                              ? 'bg-emerald-950/60 text-emerald-300 border-emerald-600/60'
                              : inc.status === 'escalated'
                              ? 'bg-red-950/60 text-red-300 border-red-600/60'
                              : inc.status === 'under_investigation'
                              ? 'bg-amber-950/60 text-amber-300 border-amber-600/60'
                              : 'bg-navy-900 text-slate-300 border-navy-600'
                          }`}
                        >
                          <option value="new">New</option>
                          <option value="under_investigation">Investigating</option>
                          <option value="escalated">Escalated</option>
                          <option value="resolved">Resolved</option>
                          <option value="false_positive">False Positive</option>
                        </select>
                      </td>
                      <td className="py-3.5 px-4 text-slate-400 font-mono">
                        {formatDate(inc.created_at)}
                      </td>
                      <td className="py-3.5 px-4 text-right">
                        <button
                          type="button"
                          className="p-1 text-slate-400 hover:text-accent-cyan rounded transition-colors"
                          title="Open details"
                        >
                          <ChevronRight className="w-5 h-5" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <EmptyState
              icon={<AlertTriangle className="w-10 h-10 text-slate-500" />}
              title="No Security Incidents"
              description="No incidents match the active search criteria or status filter."
            />
          )}
        </CardContent>
      </Card>

      {/* Slide-Over Drawer for Incident Details & Investigation Notes */}
      {selectedIncidentId && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex justify-end">
          <div className="bg-navy-850 border-l border-navy-600 w-full max-w-2xl h-full shadow-2xl flex flex-col animate-in slide-in-from-right duration-200">
            {/* Drawer Header */}
            <div className="p-6 border-b border-navy-700 flex items-center justify-between bg-navy-900">
              <div className="flex items-center gap-3">
                <span className="font-mono font-bold text-accent-cyan text-lg">
                  #{incidentDetail?.incident_number || '...'}
                </span>
                <Badge
                  variant={
                    incidentDetail?.severity === 'critical'
                      ? 'critical'
                      : incidentDetail?.severity === 'high'
                      ? 'danger'
                      : incidentDetail?.severity === 'medium'
                      ? 'warning'
                      : 'default'
                  }
                >
                  {(incidentDetail?.severity || 'MEDIUM').toUpperCase()}
                </Badge>
                <Badge
                  variant={
                    incidentDetail?.status === 'resolved'
                      ? 'success'
                      : incidentDetail?.status === 'escalated'
                      ? 'critical'
                      : incidentDetail?.status === 'under_investigation'
                      ? 'info'
                      : 'default'
                  }
                >
                  {(incidentDetail?.status || 'NEW').replace('_', ' ').toUpperCase()}
                </Badge>
              </div>

              <button
                onClick={() => setSelectedIncidentId(null)}
                className="p-1.5 text-slate-400 hover:text-slate-100 rounded-lg hover:bg-navy-800 transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Drawer Body */}
            {isLoadingDetail ? (
              <div className="flex-1 flex items-center justify-center">
                <RefreshCw className="w-8 h-8 text-accent-blue animate-spin" />
              </div>
            ) : incidentDetail ? (
              <div className="flex-1 overflow-y-auto p-6 space-y-6">
                <div>
                  <h2 className="text-xl font-bold text-slate-100">{incidentDetail.title}</h2>
                  <p className="text-xs text-slate-400 mt-1 font-mono">
                    Opened: {formatDate(incidentDetail.created_at)}
                  </p>
                </div>

                {/* Description */}
                <div className="bg-navy-900 border border-navy-700 rounded-xl p-4">
                  <h4 className="text-xs font-mono uppercase tracking-wider text-slate-400 mb-2">
                    Incident Description & Context
                  </h4>
                  <p className="text-xs text-slate-200 leading-relaxed whitespace-pre-wrap">
                    {incidentDetail.description || 'No extended description provided.'}
                  </p>
                </div>

                {/* Quick Status / Severity Controls */}
                <div className="grid grid-cols-2 gap-4">
                  <div className="bg-navy-900 border border-navy-700 rounded-xl p-3">
                    <label className="block text-xs font-mono text-slate-400 mb-1">Status</label>
                    <select
                      value={incidentDetail.status}
                      onChange={(e) => handleStatusChange(incidentDetail.id, e.target.value)}
                      className="w-full bg-navy-800 border border-navy-600 rounded px-2.5 py-1.5 text-xs text-slate-200 font-mono focus:outline-none focus:border-accent-blue"
                    >
                      <option value="new">New</option>
                      <option value="under_investigation">Under Investigation</option>
                      <option value="escalated">Escalated</option>
                      <option value="resolved">Resolved</option>
                      <option value="false_positive">False Positive</option>
                    </select>
                  </div>

                  <div className="bg-navy-900 border border-navy-700 rounded-xl p-3">
                    <label className="block text-xs font-mono text-slate-400 mb-1">Severity</label>
                    <select
                      value={incidentDetail.severity}
                      onChange={(e) => handleSeverityChange(incidentDetail.id, e.target.value)}
                      className="w-full bg-navy-800 border border-navy-600 rounded px-2.5 py-1.5 text-xs text-slate-200 font-mono focus:outline-none focus:border-accent-blue"
                    >
                      <option value="low">Low</option>
                      <option value="medium">Medium</option>
                      <option value="high">High</option>
                      <option value="critical">Critical</option>
                    </select>
                  </div>
                </div>

                {/* Investigation Notes & Timeline */}
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <h3 className="text-sm font-bold text-slate-200 flex items-center gap-2">
                      <MessageSquare className="w-4 h-4 text-accent-blue" />
                      <span>Forensic Investigation Notes ({incidentDetail.notes?.length || 0})</span>
                    </h3>
                  </div>

                  <div className="space-y-2.5 max-h-72 overflow-y-auto pr-1">
                    {incidentDetail.notes && incidentDetail.notes.length > 0 ? (
                      incidentDetail.notes.map((note) => (
                        <div
                          key={note.id}
                          className="bg-navy-900 border border-navy-700 rounded-lg p-3 space-y-1.5"
                        >
                          <div className="flex items-center justify-between text-xs">
                            <span className="font-mono text-xs px-2 py-0.5 rounded bg-navy-800 border border-navy-600 text-accent-cyan uppercase">
                              {note.note_type}
                            </span>
                            <span className="text-slate-400 font-mono text-[11px]">
                              {formatDate(note.created_at)}
                            </span>
                          </div>
                          <p className="text-xs text-slate-200 leading-relaxed whitespace-pre-wrap">
                            {note.content}
                          </p>
                        </div>
                      ))
                    ) : (
                      <div className="bg-navy-900 border border-navy-750 rounded-lg p-4 text-center text-xs text-slate-500">
                        No investigation notes recorded yet. Add initial triage findings below.
                      </div>
                    )}
                  </div>

                  {/* Add Note Form */}
                  <form onSubmit={handleAddNote} className="space-y-2 pt-2">
                    <div className="flex gap-2">
                      <select
                        value={newNoteType}
                        onChange={(e) => setNewNoteType(e.target.value)}
                        className="bg-navy-900 border border-navy-600 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 font-mono focus:outline-none focus:border-accent-blue"
                      >
                        <option value="note">Note</option>
                        <option value="action">Remediation Action</option>
                        <option value="escalation">Escalation</option>
                        <option value="resolution">Resolution Note</option>
                      </select>
                      <input
                        type="text"
                        value={newNoteContent}
                        onChange={(e) => setNewNoteContent(e.target.value)}
                        placeholder="Log SOC observation, IOC block action, or triage result..."
                        className="flex-1 bg-navy-900 border border-navy-600 rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-accent-blue"
                      />
                      <Button size="sm" type="submit" isLoading={isSubmittingNote}>
                        <Send className="w-3.5 h-3.5" />
                      </Button>
                    </div>
                  </form>
                </div>
              </div>
            ) : null}
          </div>
        </div>
      )}

      {/* Create Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-navy-800 border border-navy-600 rounded-xl p-6 max-w-lg w-full space-y-4 shadow-2xl">
            <h3 className="text-lg font-bold text-slate-100 flex items-center gap-2">
              <Plus className="w-5 h-5 text-accent-blue" /> Create New Security Incident
            </h3>

            <form onSubmit={handleCreate} className="space-y-4">
              <div>
                <label className="block text-xs font-mono text-slate-400 mb-1">Incident Title</label>
                <input
                  type="text"
                  required
                  value={newTitle}
                  onChange={(e) => setNewTitle(e.target.value)}
                  placeholder="e.g. Credential Harvesting Campaign Targeting Finance"
                  className="w-full bg-navy-900 border border-navy-600 rounded-lg p-2.5 text-xs text-slate-200 focus:outline-none focus:border-accent-blue"
                />
              </div>

              <div>
                <label className="block text-xs font-mono text-slate-400 mb-1">Description / Notes</label>
                <textarea
                  rows={4}
                  value={newDesc}
                  onChange={(e) => setNewDesc(e.target.value)}
                  placeholder="Detailed context and impact of suspicious email activity..."
                  className="w-full bg-navy-900 border border-navy-600 rounded-lg p-2.5 text-xs text-slate-200 focus:outline-none focus:border-accent-blue"
                />
              </div>

              <div>
                <label className="block text-xs font-mono text-slate-400 mb-1">Severity</label>
                <select
                  value={newSeverity}
                  onChange={(e) => setNewSeverity(e.target.value)}
                  className="w-full bg-navy-900 border border-navy-600 rounded-lg p-2.5 text-xs text-slate-200 focus:outline-none focus:border-accent-blue"
                >
                  <option value="low">Low</option>
                  <option value="medium">Medium</option>
                  <option value="high">High</option>
                  <option value="critical">Critical</option>
                </select>
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <Button variant="ghost" type="button" onClick={() => setShowCreateModal(false)}>
                  Cancel
                </Button>
                <Button type="submit">Create Incident</Button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}
