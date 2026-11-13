import React from 'react'
import { cn, getRiskColor } from '@/lib/utils'

interface RiskScoreProps {
  score: number
  classification?: string
  size?: 'sm' | 'md' | 'lg'
}

export function RiskScore({ score, classification, size = 'md' }: RiskScoreProps) {
  const strokeColor =
    score < 20
      ? '#22c55e'
      : score < 40
      ? '#eab308'
      : score < 70
      ? '#f97316'
      : '#ef4444'

  const sizeClasses = {
    sm: { box: 'w-16 h-16', text: 'text-lg', label: 'text-[10px]', stroke: 4 },
    md: { box: 'w-24 h-24', text: 'text-2xl', label: 'text-xs', stroke: 6 },
    lg: { box: 'w-36 h-36', text: 'text-4xl', label: 'text-sm', stroke: 8 },
  }

  const { box, text, label, stroke } = sizeClasses[size]
  const radius = 40
  const circumference = 2 * Math.PI * radius
  const progress = Math.min(Math.max(score, 0), 100)
  const offset = circumference - (progress / 100) * circumference

  return (
    <div className="flex flex-col items-center">
      <div className={cn('relative flex items-center justify-center', box)}>
        <svg className="w-full h-full -rotate-90 transform" viewBox="0 0 100 100">
          <circle
            cx="50"
            cy="50"
            r={radius}
            fill="transparent"
            stroke="#1e2d4a"
            strokeWidth={stroke}
          />
          <circle
            cx="50"
            cy="50"
            r={radius}
            fill="transparent"
            stroke={strokeColor}
            strokeWidth={stroke}
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            strokeLinecap="round"
            className="transition-all duration-1000 ease-out"
          />
        </svg>
        <div className="absolute flex flex-col items-center justify-center">
          <span className={cn('font-bold tracking-tight', text, getRiskColor(score))}>
            {score}
          </span>
          <span className="text-[10px] text-slate-500 uppercase font-mono">/100</span>
        </div>
      </div>
      {classification && (
        <span className={cn('mt-2 font-semibold uppercase tracking-wider', label, getRiskColor(score))}>
          {classification}
        </span>
      )}
    </div>
  )
}
