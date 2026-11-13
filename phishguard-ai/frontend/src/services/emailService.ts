import { apiClient } from '@/lib/api'
import type { Email, EmailAnalysis, ExtractedURL, Attachment, IOC } from '@/types'

export async function uploadEmailFile(file: File): Promise<{ email_id: string; status: string }> {
  const formData = new FormData()
  formData.append('file', file)
  const { data } = await apiClient.post('/emails/upload', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  })
  return data.data
}

export async function submitRawEmail(content: string): Promise<{ email_id: string; status: string }> {
  const { data } = await apiClient.post('/emails/raw', { content })
  return data.data
}

export async function getEmail(id: string): Promise<Email> {
  const { data } = await apiClient.get(`/emails/${id}`)
  return data.data
}

export async function getEmailAnalysis(id: string): Promise<EmailAnalysis> {
  const { data } = await apiClient.get(`/emails/${id}/analysis`)
  return data.data
}

export async function getEmailURLs(id: string): Promise<ExtractedURL[]> {
  const { data } = await apiClient.get(`/emails/${id}/urls`)
  return data.data
}

export async function getEmailAttachments(id: string): Promise<Attachment[]> {
  const { data } = await apiClient.get(`/emails/${id}/attachments`)
  return data.data
}

export async function getEmailIOCs(id: string): Promise<IOC[]> {
  const { data } = await apiClient.get(`/emails/${id}/iocs`)
  return data.data
}

export async function listEmails(params?: { page?: number; page_size?: number; status?: string }): Promise<{
  items: Email[]
  pagination: { total: number; page: number; page_size: number; total_pages: number }
}> {
  const { data } = await apiClient.get('/emails', { params })
  return data.data
}

export async function deleteEmail(id: string): Promise<void> {
  await apiClient.delete(`/emails/${id}`)
}
