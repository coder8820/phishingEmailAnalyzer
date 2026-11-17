import { apiClient } from '@/lib/api'

export interface GmailStatus {
  is_connected: boolean
  connection_status?: string
  token_status?: string
  email_address: string | null
  granted_scopes?: string[]
  last_verified_at?: string | null
  last_error?: string | null
  watch_status?: 'active' | 'inactive' | 'expired' | 'error' | string
  watch_expiration?: string | null
  last_history_id?: string | null
  pubsub_topic?: string | null
  auto_analyze_enabled: boolean
  auto_quarantine_enabled?: boolean
  quarantine_consent_given_at?: string | null
  quarantine_threshold_score?: number
  quarantine_label_name?: string
  quarantine_label_id?: string | null
  has_modify_permission?: boolean
  auth_type?: string
  total_messages: number
  analyzed_messages: number
  pending_messages: number
  critical_threats: number
  quarantined_messages?: number
  restored_messages?: number
  failed_quarantines?: number
  last_synced_at: string | null
}

export interface GoogleOAuthInitiateResponse {
  authorization_url: string
  state: string
}

export interface ConnectedAccountItem {
  id: string
  email_address: string
  is_connected: boolean
  connection_status: string
  token_status: string
  granted_scopes: string[]
  connected_at: string | null
  last_verified_at: string | null
  last_synced_at: string | null
  last_error: string | null
  auto_analyze_enabled: boolean
}

export interface ConnectedAccountsResponse {
  accounts: ConnectedAccountItem[]
  total: number
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
  is_quarantined?: boolean
  quarantined_at?: string | null
  quarantine_reason?: string | null
  quarantine_action_status?: 'none' | 'quarantined' | 'restored' | 'failed' | string
  quarantine_error?: string | null
  restored_at?: string | null
}

export interface QuarantineSettings {
  is_connected: boolean
  auto_quarantine_enabled: boolean
  quarantine_consent_given_at: string | null
  quarantine_threshold_score: number
  quarantine_label_name: string
  quarantine_label_id: string | null
  has_modify_permission: boolean
  requires_reauthorization?: boolean
  permission_explanation: string
}

export interface QuarantineConsentPayload {
  consent_acknowledged: boolean
  threshold_score?: number
  quarantine_label_name?: string
}

export interface QuarantineRecordItem {
  id: string
  gmail_message_id: string
  subject: string
  sender: string
  received_at: string | null
  risk_score: number | null
  risk_classification: string | null
  is_quarantined: boolean
  quarantine_action_status: string
  quarantine_reason: string | null
  quarantine_error: string | null
  quarantined_at: string | null
  restored_at: string | null
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

export async function getGoogleOAuthUrl(redirectUri?: string): Promise<GoogleOAuthInitiateResponse> {
  const params = redirectUri ? `?redirect_uri=${encodeURIComponent(redirectUri)}` : ''
  const { data } = await apiClient.get(`/gmail/oauth/authorize${params}`)
  return data.data
}

export async function handleGoogleOAuthCallback(payload: {
  code?: string
  state?: string
  error?: string
}): Promise<any> {
  const { data } = await apiClient.post('/gmail/oauth/callback', payload)
  return data.data
}

export async function getConnectedGmailAccounts(): Promise<ConnectedAccountsResponse> {
  const { data } = await apiClient.get('/gmail/accounts')
  return data.data
}

export async function disconnectGmailAccountById(accountId: string): Promise<any> {
  const { data } = await apiClient.post(`/gmail/accounts/${accountId}/disconnect`)
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

export interface SyncInboxResult {
  synced_count: number
  skipped_count: number
  total_inbox_estimate: number
  message: string
}

export interface InitialScanPayload {
  consent_acknowledged: boolean
  max_messages?: number
}

export async function analyzeGmailMessageManual(messageId: string): Promise<any> {
  const { data } = await apiClient.post(`/gmail/messages/${messageId}/analyze`)
  return data.data
}

export async function analyzeAllGmailPending(): Promise<any> {
  const { data } = await apiClient.post('/gmail/analyze-all')
  return data.data
}

export async function syncGmailInbox(maxMessages: number = 20): Promise<SyncInboxResult> {
  const { data } = await apiClient.post(`/gmail/sync?max_messages=${maxMessages}`)
  return data.data
}

export async function runInitialInboxScan(payload: InitialScanPayload): Promise<SyncInboxResult> {
  const { data } = await apiClient.post('/gmail/initial-scan', payload)
  return data.data
}

export async function startGmailWatch(): Promise<any> {
  const { data } = await apiClient.post('/gmail/watch')
  return data.data
}

export async function stopGmailWatch(): Promise<any> {
  const { data } = await apiClient.post('/gmail/stop-watch')
  return data.data
}

export async function getQuarantineSettings(): Promise<QuarantineSettings> {
  const { data } = await apiClient.get('/gmail/quarantine/settings')
  return data.data
}

export async function enableQuarantineConsent(payload: QuarantineConsentPayload): Promise<any> {
  const { data } = await apiClient.post('/gmail/quarantine/consent', payload)
  return data.data
}

export async function disableQuarantine(): Promise<any> {
  const { data } = await apiClient.post('/gmail/quarantine/disable')
  return data.data
}

export async function quarantineGmailMessage(messageId: string, reason?: string): Promise<any> {
  const { data } = await apiClient.post(`/gmail/messages/${messageId}/quarantine`, { reason })
  return data.data
}

export async function restoreGmailMessage(messageId: string): Promise<any> {
  const { data } = await apiClient.post(`/gmail/messages/${messageId}/restore`)
  return data.data
}

export async function reportFalsePositive(messageId: string, feedback?: string): Promise<any> {
  const { data } = await apiClient.post(`/gmail/messages/${messageId}/report-false-positive`, { feedback })
  return data.data
}

export async function getQuarantineRecords(limit: number = 50): Promise<{ records: QuarantineRecordItem[]; total: number }> {
  const { data } = await apiClient.get(`/gmail/quarantine/records?limit=${limit}`)
  return data.data
}
