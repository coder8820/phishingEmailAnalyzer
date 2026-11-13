'use client'

import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
} from 'recharts'
import type { TrendDataPoint } from '@/types'

export function ThreatTrendChart({ data }: { data: TrendDataPoint[] }) {
  if (!data || data.length === 0) {
    return (
      <div className="h-64 flex items-center justify-center text-slate-500 text-sm">
        No trend telemetry available for the current period
      </div>
    )
  }

  return (
    <div className="h-64 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={data} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
          <defs>
            <linearGradient id="phishGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#ef4444" stopOpacity={0.4} />
              <stop offset="95%" stopColor="#ef4444" stopOpacity={0.0} />
            </linearGradient>
            <linearGradient id="suspGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#eab308" stopOpacity={0.3} />
              <stop offset="95%" stopColor="#eab308" stopOpacity={0.0} />
            </linearGradient>
            <linearGradient id="cleanGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#22c55e" stopOpacity={0.3} />
              <stop offset="95%" stopColor="#22c55e" stopOpacity={0.0} />
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke="#1e2d4a" vertical={false} />
          <XAxis dataKey="date" stroke="#64748b" fontSize={11} tickLine={false} />
          <YAxis stroke="#64748b" fontSize={11} tickLine={false} allowDecimals={false} />
          <Tooltip
            contentStyle={{
              backgroundColor: '#0d1526',
              borderColor: '#1e2d4a',
              borderRadius: '8px',
              fontSize: '12px',
              color: '#f8fafc',
            }}
          />
          <Area
            type="monotone"
            dataKey="phishing"
            name="Phishing Threats"
            stroke="#ef4444"
            fillOpacity={1}
            fill="url(#phishGrad)"
          />
          <Area
            type="monotone"
            dataKey="suspicious"
            name="Suspicious"
            stroke="#eab308"
            fillOpacity={1}
            fill="url(#suspGrad)"
          />
          <Area
            type="monotone"
            dataKey="clean"
            name="Clean Emails"
            stroke="#22c55e"
            fillOpacity={1}
            fill="url(#cleanGrad)"
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  )
}
