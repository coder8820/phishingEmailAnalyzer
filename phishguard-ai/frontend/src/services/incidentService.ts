import { apiClient } from '@/lib/api'
import type { Incident, InvestigationNote } from '@/types'

export async function listIncidents(params?: { page?: number; page_size?: number; status?: string; severity?: string }): Promise<{
  items: Incident[]
  pagination: { total: number; page: number; page_size: number; total_pages: number }
}> {
  const { data } = await apiClient.get('/incidents', { params })
  return data.data
}

export async function getIncident(id: string): Promise<Incident & { notes: InvestigationNote[] }> {
  const { data } = await apiClient.get(`/incidents/${id}`)
  return data.data
}

export async function createIncident(data: {
  title: string
  description?: string
  severity: string
  tags?: string[]
  email_ids?: string[]
  ioc_ids?: string[]
}): Promise<{ id: string; incident_number: number; title: string }> {
  const res = await apiClient.post('/incidents', data)
  return res.data.data
}

export async function updateIncident(id: string, data: {
  title?: string
  description?: string
  severity?: string
  status?: string
  resolution_notes?: string
  tags?: string[]
}): Promise<void> {
  await apiClient.put(`/incidents/${id}`, data)
}

export async function addIncidentNote(id: string, data: { content: string; note_type?: string }): Promise<InvestigationNote> {
  const res = await apiClient.post(`/incidents/${id}/notes`, data)
  return res.data.data
}
