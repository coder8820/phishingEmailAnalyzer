'use client'

import React, { useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import {
  Shield,
  AlertTriangle,
  CheckCircle,
  Mail,
  RefreshCw,
  TrendingUp,
  Plus,
  ArrowUpRight,
  ExternalLink,
  Zap,
  Globe,
  SlidersHorizontal,
  FileDown,
} from 'lucide-react'
import { toast } from 'sonner'
import {
  getDashboardStats,
  getTrends,
  getTopDomains,
  getRecentAnalyses,
  getIndicatorDistribution,
} from '@/services/dashboardService'
import { ThreatTrendChart } from '@/components/charts/ThreatTrendChart'
import { CategoryDistributionChart } from '@/components/charts/CategoryDistributionChart'
import { GmailDefenseHub } from '@/components/dashboard/GmailDefenseHub'
import { Badge } from '@/components/ui/Badge'
import { EmptyState } from '@/components/ui/EmptyState'
import { LoadingSkeleton } from '@/components/ui/LoadingSkeleton'
import { formatDate, cn } from '@/lib/utils'
import type { DashboardStats, TrendDataPoint, EmailAnalysis } from '@/types'

interface StatCardProps {
  title: string
  value: number | string
  icon: React.ReactNode
  iconBg: string
  trend?: { value: number; direction: 'up' | 'down' }
  subtitle?: string
  accentColor?: string
}

function StatCard({ title, value, icon, iconBg, trend, subtitle, accentColor }: StatCardProps) {
  return (
    <div
      className={cn(
        'bg-navy-800/90 border border-navy-700/80 rounded-xl p-5 flex flex-col justify-between hover:border-accent-blue/40 hover:bg-navy-800 transition-all duration-200 shadow-lg relative overflow-hidden group',
        accentColor
      )}
    >
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs font-semibold uppercase tracking-wider text-slate-400 font-mono">
            {title}
          </p>
          <p className="text-3xl font-extrabold text-slate-100 mt-2 font-mono tracking-tight">
            {value}
          </p>
        </div>
        <div className={cn('p-2.5 rounded-xl border border-white/5 shadow-inner', iconBg)}>
          {icon}
        </div>
      </div>
      <div className="mt-4 flex items-center justify-between text-xs pt-2 border-t border-navy-700/50">
        {subtitle && <span className="text-slate-400 font-mono">{subtitle}</span>}
        {trend && (
          <span
            className={cn(
              'flex items-center font-mono font-medium',
              trend.direction === 'up' ? 'text-red-400' : 'text-green-400'
            )}
          >
            {trend.direction === 'up' ? '↑' : '↓'} {trend.value}% vs last week
          </span>
        )}
      </div>
    </div>
  )
}

export default function DashboardPage() {
  const router = useRouter()
  const [stats, setStats] = useState<DashboardStats | null>(null)
  const [trends, setTrends] = useState<TrendDataPoint[]>([])
  const [topDomains, setTopDomains] = useState<{ domain: string; count: number; risk: string }[]>([])
  const [recentAnalyses, setRecentAnalyses] = useState<any[]>([])
  const [indicators, setIndicators] = useState<{ category: string; count: number }[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [isRefreshing, setIsRefreshing] = useState(false)

  const fetchData = async (refresh = false) => {
    if (refresh) setIsRefreshing(true)
    else setIsLoading(true)
    try {
      const results = await Promise.allSettled([
        getDashboardStats(),
        getTrends(30),
        getTopDomains(),
        getRecentAnalyses(),
        getIndicatorDistribution(),
      ])

      const [statsRes, trendsRes, domainsRes, analysesRes, indicatorsRes] = results

      if (statsRes.status === 'fulfilled') setStats(statsRes.value)
      if (trendsRes.status === 'fulfilled') setTrends(trendsRes.value)
      if (domainsRes.status === 'fulfilled') setTopDomains(domainsRes.value)
      if (analysesRes.status === 'fulfilled') setRecentAnalyses(analysesRes.value)
      if (indicatorsRes.status === 'fulfilled') setIndicators(indicatorsRes.value)

      const hasAnySuccess = results.some((r) => r.status === 'fulfilled')
      if (!hasAnySuccess) {
        toast.error('Failed to load dashboard data')
      }
    } catch {
      toast.error('Failed to load dashboard data')
    } finally {
      setIsLoading(false)
      setIsRefreshing(false)
    }
  }

  useEffect(() => {
    fetchData()
  }, [])

  if (isLoading) {
    return (
      <div className="space-y-6">
        <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
          {Array.from({ length: 5 }).map((_, i) => (
            <LoadingSkeleton key={i} variant="stat-card" />
          ))}
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <LoadingSkeleton variant="chart" />
          <LoadingSkeleton variant="chart" />
        </div>
        <LoadingSkeleton variant="table" />
      </div>
    )
  }

  return (
    <div className="space-y-6 animate-fade-in max-w-7xl mx-auto">
      {/* Enterprise SOC Perimeter Header */}
      <div className="bg-gradient-to-r from-navy-850 via-navy-800 to-navy-850 border border-navy-700/80 rounded-2xl p-6 shadow-xl">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-3">
              <h1 className="text-2xl font-black text-slate-100 tracking-tight">
                SOC Threat Defense Center
              </h1>
              <span className="px-2.5 py-0.5 text-[10px] font-mono font-bold bg-accent-blue/15 text-accent-cyan border border-accent-blue/30 rounded-full uppercase tracking-wider">
                Enterprise Edition
              </span>
            </div>
            <p className="text-slate-400 text-xs mt-1.5 flex items-center gap-3 font-mono">
              <span>ACTIVE PERIMETER PROTECTION</span>
              <span className="text-slate-600">•</span>
              <span className="text-green-400 flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse" />
                M365 & MTA WEBHOOKS CONNECTED
              </span>
            </p>
          </div>

          {/* Quick Action Toolbar */}
          <div className="flex flex-wrap items-center gap-2.5">
            <button
              onClick={() => router.push('/email-analyzer')}
              className="flex items-center gap-1.5 px-3.5 py-2 bg-accent-blue hover:bg-blue-600 text-white rounded-lg text-xs font-semibold shadow-lg shadow-accent-blue/20 transition-all"
            >
              <Plus className="w-4 h-4" />
              <span>Scan Email</span>
            </button>

            <button
              onClick={() => router.push('/incidents')}
              className="flex items-center gap-1.5 px-3.5 py-2 bg-navy-800 hover:bg-navy-700 text-slate-200 border border-navy-600 hover:border-navy-500 rounded-lg text-xs font-semibold transition-all"
            >
              <AlertTriangle className="w-3.5 h-3.5 text-yellow-400" />
              <span>Incidents Queue</span>
            </button>

            <button
              onClick={() => router.push('/reports')}
              className="flex items-center gap-1.5 px-3.5 py-2 bg-navy-800 hover:bg-navy-700 text-slate-200 border border-navy-600 hover:border-navy-500 rounded-lg text-xs font-semibold transition-all"
            >
              <FileDown className="w-3.5 h-3.5 text-accent-cyan" />
              <span>Reports</span>
            </button>

            <button
              onClick={() => fetchData(true)}
              disabled={isRefreshing}
              className="p-2 bg-navy-800 hover:bg-navy-700 border border-navy-600 text-slate-400 hover:text-slate-200 rounded-lg transition-all disabled:opacity-50"
              title="Refresh telemetry"
            >
              <RefreshCw className={cn('w-4 h-4', isRefreshing && 'animate-spin text-accent-cyan')} />
            </button>
          </div>
        </div>
      </div>

      {/* Primary Telemetry Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        <StatCard
          title="Total Ingested"
          value={stats?.total_emails ?? 0}
          icon={<Mail className="w-5 h-5 text-blue-400" />}
          iconBg="bg-blue-500/10"
          subtitle={`${stats?.emails_today ?? 0} in last 24h`}
        />
        <StatCard
          title="Phishing Confirmed"
          value={stats?.phishing_count ?? 0}
          icon={<AlertTriangle className="w-5 h-5 text-red-400" />}
          iconBg="bg-red-500/10"
          trend={{ value: 14, direction: 'up' }}
          accentColor="hover:border-red-500/40"
        />
        <StatCard
          title="Suspicious Neutral"
          value={stats?.suspicious_count ?? 0}
          icon={<Shield className="w-5 h-5 text-yellow-400" />}
          iconBg="bg-yellow-500/10"
          subtitle="Heuristic triggers"
        />
        <StatCard
          title="Clean Passed"
          value={stats?.clean_count ?? 0}
          icon={<CheckCircle className="w-5 h-5 text-green-400" />}
          iconBg="bg-green-500/10"
          subtitle="Authorized origins"
        />
        <StatCard
          title="Critical Attacks"
          value={stats?.critical_count ?? 0}
          icon={<AlertTriangle className="w-5 h-5 text-rose-400" />}
          iconBg="bg-rose-500/15"
          subtitle={`Avg Risk: ${stats?.avg_risk_score?.toFixed(1) ?? '0.0'}/100`}
          accentColor="hover:border-rose-500/50"
        />
      </div>

      {/* Connected Gmail Defense & Auto-Analyze Hub */}
      <GmailDefenseHub />

      {/* Visual Analytics Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* 30-Day Threat Trend Chart */}
        <div className="bg-navy-800/90 border border-navy-700/80 rounded-2xl p-6 shadow-xl">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
                <TrendingUp className="w-4 h-4 text-accent-blue" />
                <span>30-Day Threat Volume Trend</span>
              </h2>
              <p className="text-xs text-slate-400">Timeline of analyzed email classifications</p>
            </div>
            <Badge variant="outline">Rolling 30 Days</Badge>
          </div>
          {trends.length > 0 ? (
            <ThreatTrendChart data={trends} />
          ) : (
            <EmptyState
              icon={<TrendingUp className="w-8 h-8" />}
              title="No trend timeline"
              description="Telemetry will populate as inbound mail is processed"
            />
          )}
        </div>

        {/* Detection Indicators Distribution */}
        <div className="bg-navy-800/90 border border-navy-700/80 rounded-2xl p-6 shadow-xl">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
                <Zap className="w-4 h-4 text-accent-cyan" />
                <span>Threat Category Distribution</span>
              </h2>
              <p className="text-xs text-slate-400">Breakdown of active detection rule matches</p>
            </div>
            <Badge variant="outline">Engine Triggers</Badge>
          </div>
          {indicators.length > 0 ? (
            <CategoryDistributionChart data={indicators} />
          ) : (
            <EmptyState
              icon={<Shield className="w-8 h-8" />}
              title="No active findings"
              description="Triggered threat categories will visualize here"
            />
          )}
        </div>
      </div>

      {/* Investigation Queue & Top Threat Domains */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Recent Analyzed Emails Queue */}
        <div className="lg:col-span-2 bg-navy-800/90 border border-navy-700/80 rounded-2xl p-6 shadow-xl">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
                <Mail className="w-4 h-4 text-accent-blue" />
                <span>Recent Threat Analyses</span>
              </h2>
              <p className="text-xs text-slate-400">Latest inspected emails with security verdicts</p>
            </div>
            <button
              onClick={() => router.push('/investigation-history')}
              className="text-xs font-semibold text-accent-cyan hover:text-cyan-300 flex items-center gap-1 transition-colors"
            >
              <span>Full Investigation Archive</span>
              <ArrowUpRight className="w-3.5 h-3.5" />
            </button>
          </div>

          {recentAnalyses.length === 0 ? (
            <EmptyState
              icon={<Mail className="w-8 h-8" />}
              title="No analyzed emails yet"
              description="Upload a .eml file or use inbound webhooks to run analysis"
            />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-navy-700 text-slate-400 font-mono uppercase tracking-wider">
                    <th className="pb-3 font-semibold">Risk Score</th>
                    <th className="pb-3 font-semibold">Subject & Sender</th>
                    <th className="pb-3 font-semibold">Authentication</th>
                    <th className="pb-3 font-semibold">Scanned</th>
                    <th className="pb-3 text-right font-semibold">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-navy-700/60">
                  {recentAnalyses.map((item) => (
                    <tr
                      key={item.id}
                      onClick={() => router.push(`/email-analyzer?id=${item.email_id}`)}
                      className="hover:bg-navy-750/70 transition-colors cursor-pointer group"
                    >
                      {/* Risk Score */}
                      <td className="py-3 pr-4">
                        <div className="flex items-center gap-2">
                          <span
                            className={cn(
                              'text-base font-black font-mono',
                              getRiskColor(item.risk_score)
                            )}
                          >
                            {item.risk_score}
                          </span>
                          <span
                            className={cn(
                              'text-[9px] font-mono uppercase px-1.5 py-0.5 rounded border',
                              getRiskBadgeClasses(item.risk_classification)
                            )}
                          >
                            {item.risk_classification}
                          </span>
                        </div>
                      </td>

                      {/* Subject & Sender */}
                      <td className="py-3 pr-4 max-w-xs">
                        <p className="font-semibold text-slate-100 truncate group-hover:text-accent-cyan transition-colors">
                          {item.subject || 'Untitled Email'}
                        </p>
                        <p className="text-[11px] text-slate-400 font-mono truncate mt-0.5">
                          {item.sender || 'Unknown Sender'}
                        </p>
                      </td>

                      {/* Authentication Status */}
                      <td className="py-3 pr-4 font-mono">
                        <span
                          className={cn(
                            'text-[10px] px-2 py-0.5 rounded border',
                            item.spf_result === 'pass'
                              ? 'bg-green-500/10 text-green-400 border-green-500/20'
                              : 'bg-red-500/10 text-red-400 border-red-500/20'
                          )}
                        >
                          SPF: {item.spf_result ? item.spf_result.toUpperCase() : 'NONE'}
                        </span>
                      </td>

                      {/* Timestamp */}
                      <td className="py-3 pr-4 text-slate-400 font-mono text-[11px] whitespace-nowrap">
                        {item.created_at ? formatDate(item.created_at) : 'Just now'}
                      </td>

                      {/* Action */}
                      <td className="py-3 text-right">
                        <span className="text-accent-blue group-hover:text-cyan-300 font-semibold inline-flex items-center gap-1">
                          View <ArrowUpRight className="w-3 h-3" />
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Top Suspicious Domains Panel */}
        <div className="bg-navy-800/90 border border-navy-700/80 rounded-2xl p-6 shadow-xl flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <div>
                <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
                  <Globe className="w-4 h-4 text-accent-cyan" />
                  <span>Top Threat Domains</span>
                </h2>
                <p className="text-xs text-slate-400">Recurring malicious sender infrastructure</p>
              </div>
              <button
                onClick={() => router.push('/ioc-explorer')}
                className="text-slate-400 hover:text-slate-200"
                title="Search IOCs"
              >
                <ExternalLink className="w-4 h-4" />
              </button>
            </div>

            {topDomains.length === 0 ? (
              <EmptyState
                icon={<Globe className="w-6 h-6" />}
                title="No hostile domains"
                description="Domains involved in high risk attacks will be ranked here"
              />
            ) : (
              <div className="space-y-2.5">
                {topDomains.map((d, i) => (
                  <div
                    key={i}
                    onClick={() => router.push(`/threat-intelligence`)}
                    className="flex items-center justify-between p-2.5 rounded-xl bg-navy-850/80 border border-navy-700/70 hover:border-accent-blue/40 cursor-pointer transition-colors"
                  >
                    <div className="flex items-center gap-2.5 min-w-0 pr-2">
                      <span className="text-xs font-mono font-bold text-slate-500 w-5">
                        #{i + 1}
                      </span>
                      <span className="text-xs text-slate-200 font-mono truncate font-medium">
                        {d.domain}
                      </span>
                    </div>
                    <div className="flex items-center gap-2 flex-shrink-0">
                      <span className="px-1.5 py-0.5 text-[9px] font-mono uppercase bg-red-500/10 text-red-400 border border-red-500/20 rounded">
                        {d.risk}
                      </span>
                      <span className="text-[11px] font-mono text-slate-400 bg-navy-800 px-2 py-0.5 rounded border border-navy-700">
                        {d.count} attacks
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Quick Deep Link */}
          <div className="mt-6 pt-4 border-t border-navy-700/60">
            <button
              onClick={() => router.push('/threat-intelligence')}
              className="w-full py-2 bg-navy-850 hover:bg-navy-750 text-slate-300 hover:text-white border border-navy-700 rounded-lg text-xs font-mono flex items-center justify-center gap-1.5 transition-colors"
            >
              <span>Perform Threat Intel Domain Lookup</span>
              <ArrowUpRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

function getRiskColor(score: number): string {
  if (score < 25) return 'text-green-400'
  if (score < 50) return 'text-yellow-400'
  if (score < 75) return 'text-orange-400'
  return 'text-red-400'
}

function getRiskBadgeClasses(classification: string): string {
  switch (classification?.toLowerCase()) {
    case 'critical':
      return 'bg-red-500/15 text-red-400 border-red-500/30'
    case 'high':
      return 'bg-orange-500/15 text-orange-400 border-orange-500/30'
    case 'medium':
    case 'suspicious':
      return 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30'
    case 'low':
      return 'bg-green-500/15 text-green-400 border-green-500/30'
    default:
      return 'bg-slate-500/15 text-slate-400 border-slate-500/30'
  }
}
