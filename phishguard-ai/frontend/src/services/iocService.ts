import { apiClient } from '@/lib/api'
import type { IOC } from '@/types'

export async function listIOCs(params?: {
  page?: number
  page_size?: number
  ioc_type?: string
  risk_level?: string
  search?: string
}): Promise<{
  items: IOC[]
  pagination: { total: number; page: number; page_size: number; total_pages: number }
}> {
  const { data } = await apiClient.get('/iocs', { params })
  return data.data
}

export async function updateIOC(id: string, data: { is_false_positive?: boolean; tags?: string[] }): Promise<void> {
  await apiClient.put(`/iocs/${id}`, data)
}

export async function exportIOCs(format: 'json' | 'csv'): Promise<Blob> {
  const response = await apiClient.get(`/iocs/export?format=${format}`, {
    responseType: 'blob',
  })
  return response.data
}
