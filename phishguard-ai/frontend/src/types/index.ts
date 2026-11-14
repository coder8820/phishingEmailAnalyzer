export type RiskClassification = 'low' | 'suspicious' | 'medium' | 'high' | 'critical'
export type AnalysisStatus = 'pending' | 'queued' | 'processing' | 'complete' | 'failed'
export type IncidentStatus =
  | 'new'
  | 'under_investigation'
  | 'escalated'
  | 'resolved'
  | 'false_positive'
export type UserRole = 'viewer' | 'analyst' | 'security_admin' | 'super_admin'
export type IOCType = 'ip' | 'domain' | 'url' | 'email' | 'hash_sha256' | 'filename'

export interface User {
  id: string
  email: string
  username: string
  display_name?: string
  role: UserRole
  organization_id: string
  last_login_at?: string
  created_at: string
}

export interface Email {
  id: string
  subject?: string
  sender_email?: string
  sender_display_name?: string
  sender_raw?: string
  reply_to?: string
  return_path?: string
  message_id?: string
  analysis_status: AnalysisStatus
  file_hash_sha256?: string
  original_filename?: string
  created_at: string
  source_type: string
}

export interface ScoreSignal {
  name: string
  weight: number
  applied_score: number
  confidence: 'confirmed' | 'suspicious' | 'heuristic'
  reason: string
}

export interface DetectionFinding {
  id: string
  category: string
  name: string
  description?: string
  severity: string
  confidence: string
  score_impact: number
  evidence?: Record<string, unknown>
}

export interface EmailAnalysis {
  id: string
  email_id: string
  risk_score: number
  risk_classification: RiskClassification
  spf_result?: string
  dkim_result?: string
  dmarc_result?: string
  auth_alignment?: string
  display_name_spoofing: boolean
  sender_domain_mismatch: boolean
  reply_to_mismatch: boolean
  url_count: number
  malicious_url_count: number
  suspicious_url_count: number
  attachment_count: number
  malicious_attachment_count: number
  ioc_count: number
  ai_analysis_available: boolean
  ai_phishing_assessment?: string
  ai_confidence?: string
  ai_summary?: string
  ai_findings?: AIFinding[]
  ai_recommended_actions?: string[]
  score_breakdown: { signals: ScoreSignal[]; explanation?: string }
  missing_evidence?: string[]
  findings: DetectionFinding[]
  created_at: string
  analysis_duration_ms?: number
  ai_provider?: string
  ai_model?: string
}

export interface AIFinding {
  category: string
  description: string
  severity: string
  confidence: string
  evidence_quotes: string[]
}

export interface ExtractedURL {
  id: string
  url_raw: string
  url_normalized?: string
  domain?: string
  scheme?: string
  is_shortener: boolean
  is_ip_based: boolean
  is_punycode?: boolean
  has_suspicious_params?: boolean
  redirect_chain?: Array<Record<string, unknown>>
  is_malicious?: boolean
  malicious_confidence?: string
  detection_reasons?: string[]
  source_location?: string
}

export interface Attachment {
  id: string
  filename_sanitized?: string
  mime_type_declared?: string
  mime_type_detected?: string
  file_size_bytes?: number
  sha256_hash: string
  is_executable: boolean
  has_macro_indicator: boolean
  mime_type_mismatch: boolean
  risk_level: string
}

export interface IOC {
  id: string
  ioc_type: IOCType
  ioc_value: string
  source_location?: string
  risk_level?: string
  confidence?: string
  detection_reason?: string
  is_false_positive: boolean
  tags?: string[]
  created_at: string
}

export interface Incident {
  id: string
  title: string
  description?: string
  severity: string
  status: IncidentStatus
  incident_number?: number
  created_by: string
  created_at: string
  updated_at: string
  tags?: string[]
  assigned_to?: string
}

export interface InvestigationNote {
  id: string
  incident_id: string
  content: string
  note_type: string
  author_id: string
  created_at: string
  updated_at: string
}

export interface DashboardStats {
  total_emails: number
  phishing_count: number
  suspicious_count: number
  clean_count: number
  critical_count: number
  avg_risk_score: number
  emails_today: number
  emails_this_week: number
}

export interface TrendDataPoint {
  date: string
  phishing: number
  suspicious: number
  clean: number
  total: number
}

export interface APIResponse<T> {
  success: boolean
  data: T
  error?: { code: string; message: string }
}

export interface PaginatedResponse<T> {
  success: boolean
  data: T[]
  total: number
  page: number
  page_size: number
  total_pages: number
}

export interface AuditLog {
  id: string
  user_id: string
  user_email?: string
  action: string
  resource_type?: string
  resource_id?: string
  ip_address?: string
  severity: string
  created_at: string
  metadata?: Record<string, unknown>
}

export interface Integration {
  id: string
  provider: string
  display_name: string
  is_enabled: boolean
  last_used_at?: string
  request_count: number
  is_demo_mode: boolean
}

export interface ThreatLookupResult {
  provider: string
  is_malicious: boolean
  confidence: string
  detection_count?: number
  tags?: string[]
  is_demo: boolean
  details?: Record<string, unknown>
}
