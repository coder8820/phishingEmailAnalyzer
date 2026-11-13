import { apiClient } from '@/lib/api'

export interface GmailStatus {
  is_connected: boolean
  email_address: string | null
  auto_analyze_enabled: boolean
  auth_type?: string
  total_messages: number
  analyzed_messages: number
  pending_messages: number
  critical_threats: number
  last_synced_at: string | null
}

export interface GmailMessageItem {
  id: string
  gmail_message_id: string
  subject: string
  sender: string
  snippet: string
  received_at: string | null
  is_analyzed: boolean
  analysis_status: string
  risk_score: number | null
  risk_classification: string | null
  email_id: string | null
}

export interface GmailMessagesResponse {
  messages: GmailMessageItem[]
  total: number
  integration_email?: string
  auto_analyze_enabled?: boolean
}

export async function getGmailStatus(): Promise<GmailStatus> {
  const { data } = await apiClient.get('/gmail/status')
  return data.data
}

export async function connectGmail(payload: {
  email_address: string
  app_password?: string
  auto_analyze?: boolean
  sync_demo_inbox?: boolean
}): Promise<any> {
  const { data } = await apiClient.post('/gmail/connect', payload)
  return data.data
}

export async function disconnectGmail(): Promise<any> {
  const { data } = await apiClient.post('/gmail/disconnect')
  return data.data
}

export async function toggleAutoAnalyze(enabled: boolean): Promise<any> {
  const { data } = await apiClient.post('/gmail/toggle-auto-analyze', { enabled })
  return data.data
}

export async function getGmailMessages(params?: {
  search?: string
  threat_level?: string
  status_filter?: string
  limit?: number
}): Promise<GmailMessagesResponse> {
  const query = new URLSearchParams()
  if (params?.search) query.append('search', params.search)
  if (params?.threat_level && params.threat_level !== 'all') query.append('threat_level', params.threat_level)
  if (params?.status_filter && params.status_filter !== 'all') query.append('status_filter', params.status_filter)
  if (params?.limit) query.append('limit', params.limit.toString())

  const qs = query.toString() ? `?${query.toString()}` : ''
  const { data } = await apiClient.get(`/gmail/messages${qs}`)
  return data.data
}

export async function analyzeGmailMessageManual(messageId: string): Promise<any> {
  const { data } = await apiClient.post(`/gmail/messages/${messageId}/analyze`)
  return data.data
}

export async function analyzeAllGmailPending(): Promise<any> {
  const { data } = await apiClient.post('/gmail/analyze-all')
  return data.data
}

export async function syncGmailInbox(): Promise<any> {
  const { data } = await apiClient.post('/gmail/sync')
  return data.data
}
