import { apiClient } from '@/lib/api'
import type { DashboardStats, TrendDataPoint, EmailAnalysis } from '@/types'

export async function getDashboardStats(): Promise<DashboardStats> {
  const { data } = await apiClient.get('/dashboard/stats')
  return data.data
}

export async function getTrends(days: number = 30): Promise<TrendDataPoint[]> {
  const { data } = await apiClient.get(`/dashboard/trends?days=${days}`)
  return data.data
}

export async function getTopDomains(): Promise<{ domain: string; count: number; risk: string }[]> {
  const { data } = await apiClient.get('/dashboard/top-domains')
  return data.data
}

export async function getRecentAnalyses(): Promise<EmailAnalysis[]> {
  const { data } = await apiClient.get('/dashboard/recent-analyses')
  return data.data
}

export async function getIndicatorDistribution(): Promise<{ category: string; count: number }[]> {
  const { data } = await apiClient.get('/dashboard/indicator-distribution')
  return data.data
}
