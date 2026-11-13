'use client'

import React from 'react'
import { ExternalLink, ShieldCheck, Globe, Database, Terminal, FileCode } from 'lucide-react'
import { CyberResource } from '@/services/chatService'

interface ResourceCardProps {
  resource: CyberResource
  compact?: boolean
}

export function ResourceCard({ resource, compact = false }: ResourceCardProps) {
  const getCategoryIcon = (cat: string) => {
    const l = cat.toLowerCase()
    if (l.includes('threat') || l.includes('malware') || l.includes('intel')) return ShieldCheck
    if (l.includes('url') || l.includes('domain') || l.includes('web')) return Globe
    if (l.includes('database') || l.includes('feed') || l.includes('reputation')) return Database
    if (l.includes('sandbox') || l.includes('interactive')) return Terminal
    return FileCode
  }

  const Icon = getCategoryIcon(resource.category)

  if (compact) {
    return (
      <a
        href={resource.url}
        target="_blank"
        rel="noopener noreferrer"
        className="group flex items-center justify-between p-2.5 rounded-lg bg-navy-900/90 border border-navy-700/80 hover:border-accent-cyan/60 hover:bg-navy-800/90 transition-all shadow-sm"
      >
        <div className="flex items-center gap-2.5 min-w-0">
          <div className="w-7 h-7 rounded-md bg-accent-blue/15 border border-accent-blue/30 flex items-center justify-center shrink-0">
            <Icon className="w-3.5 h-3.5 text-accent-cyan" />
          </div>
          <div className="min-w-0">
            <p className="text-xs font-semibold text-slate-100 group-hover:text-accent-cyan truncate transition-colors">
              {resource.title}
            </p>
            <p className="text-[10px] text-slate-400 truncate">{resource.category}</p>
          </div>
        </div>
        <ExternalLink className="w-3.5 h-3.5 text-slate-400 group-hover:text-accent-cyan shrink-0 transition-colors" />
      </a>
    )
  }

  return (
    <div className="group relative flex flex-col justify-between p-4 rounded-xl bg-navy-900 border border-navy-700/80 hover:border-accent-cyan/60 hover:shadow-lg hover:shadow-accent-cyan/5 transition-all">
      <div>
        <div className="flex items-start justify-between gap-3 mb-2">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-accent-blue/15 border border-accent-blue/30 flex items-center justify-center shrink-0">
              <Icon className="w-4 h-4 text-accent-cyan" />
            </div>
            <div>
              <h4 className="text-sm font-bold text-white group-hover:text-accent-cyan transition-colors">
                {resource.title}
              </h4>
              <span className="inline-block text-[10px] font-mono font-medium px-2 py-0.5 rounded bg-navy-950 border border-navy-700 text-slate-400">
                {resource.badge}
              </span>
            </div>
          </div>
          <a
            href={resource.url}
            target="_blank"
            rel="noopener noreferrer"
            title={`Open ${resource.title}`}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-navy-800 transition-colors"
          >
            <ExternalLink className="w-4 h-4" />
          </a>
        </div>
        <p className="text-xs text-slate-300 leading-relaxed mb-3">{resource.description}</p>
      </div>

      <div className="pt-2 border-t border-navy-800/80 flex items-center justify-between">
        <span className="text-[11px] text-slate-400 font-medium">{resource.category}</span>
        <a
          href={resource.url}
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center gap-1.5 text-xs font-semibold text-accent-cyan hover:text-cyan-300 transition-colors"
        >
          <span>Launch Tool</span>
          <ExternalLink className="w-3 h-3" />
        </a>
      </div>
    </div>
  )
}
