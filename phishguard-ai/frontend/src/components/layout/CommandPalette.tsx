'use client'

import React, { useEffect, useState, useRef } from 'react'
import { useRouter } from 'next/navigation'
import {
  Search,
  Mail,
  Shield,
  AlertTriangle,
  FileText,
  Settings,
  History,
  Zap,
  ArrowRight,
  X,
} from 'lucide-react'

interface CommandItem {
  id: string
  title: string
  subtitle?: string
  icon: React.ComponentType<{ className?: string }>
  category: 'Actions' | 'Navigation' | 'Threats'
  href: string
}

const COMMAND_ITEMS: CommandItem[] = [
  {
    id: 'cmd-analyze',
    title: 'Analyze New Email',
    subtitle: 'Upload .eml or paste raw RFC-822 email content for scanning',
    icon: Mail,
    category: 'Actions',
    href: '/email-analyzer',
  },
  {
    id: 'cmd-incidents',
    title: 'Open Incident Queue',
    subtitle: 'View and investigate active SOC incidents',
    icon: AlertTriangle,
    category: 'Actions',
    href: '/incidents',
  },
  {
    id: 'cmd-dashboard',
    title: 'Security Overview Dashboard',
    subtitle: 'Executive metrics, trends, and risk distributions',
    icon: Shield,
    category: 'Navigation',
    href: '/dashboard',
  },
  {
    id: 'cmd-history',
    title: 'Investigation History',
    subtitle: 'Past email analysis reports and threat breakdowns',
    icon: History,
    category: 'Navigation',
    href: '/investigation-history',
  },
  {
    id: 'cmd-intel',
    title: 'Threat Intelligence Provider Center',
    subtitle: 'VirusTotal, URLhaus, and AbuseIPDB live lookups',
    icon: Zap,
    category: 'Navigation',
    href: '/threat-intelligence',
  },
  {
    id: 'cmd-iocs',
    title: 'IOC Explorer',
    subtitle: 'Search extracted malicious IPs, domains, and SHA-256 hashes',
    icon: Search,
    category: 'Threats',
    href: '/ioc-explorer',
  },
  {
    id: 'cmd-reports',
    title: 'Generate SOC Reports',
    subtitle: 'Export executive PDF, JSON, or CSV compliance reports',
    icon: FileText,
    category: 'Actions',
    href: '/reports',
  },
  {
    id: 'cmd-settings',
    title: 'System & Security Settings',
    subtitle: 'Automated quarantine policies, API integrations, and credentials',
    icon: Settings,
    category: 'Navigation',
    href: '/settings',
  },
]

interface CommandPaletteProps {
  isOpen: boolean
  onClose: () => void
}

export function CommandPalette({ isOpen, onClose }: CommandPaletteProps) {
  const router = useRouter()
  const [query, setQuery] = useState('')
  const [selectedIndex, setSelectedIndex] = useState(0)
  const inputRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    if (isOpen) {
      setQuery('')
      setSelectedIndex(0)
      setTimeout(() => inputRef.current?.focus(), 50)
    }
  }, [isOpen])

  const filtered = COMMAND_ITEMS.filter((item) => {
    if (!query.trim()) return true
    const q = query.toLowerCase()
    return (
      item.title.toLowerCase().includes(q) ||
      (item.subtitle && item.subtitle.toLowerCase().includes(q)) ||
      item.category.toLowerCase().includes(q)
    )
  })

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (!isOpen) return

      if (e.key === 'ArrowDown') {
        e.preventDefault()
        setSelectedIndex((prev) => (prev + 1) % (filtered.length || 1))
      } else if (e.key === 'ArrowUp') {
        e.preventDefault()
        setSelectedIndex((prev) => (prev - 1 + (filtered.length || 1)) % (filtered.length || 1))
      } else if (e.key === 'Enter') {
        e.preventDefault()
        if (filtered[selectedIndex]) {
          onClose()
          router.push(filtered[selectedIndex].href)
        }
      } else if (e.key === 'Escape') {
        e.preventDefault()
        onClose()
      }
    }

    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [isOpen, filtered, selectedIndex, router, onClose])

  if (!isOpen) return null

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto p-4 sm:p-6 md:p-20">
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-navy-950/80 backdrop-blur-sm transition-opacity"
        onClick={onClose}
      />

      <div className="relative mx-auto max-w-xl bg-navy-900 border border-navy-700 rounded-xl shadow-2xl overflow-hidden divide-y divide-navy-700">
        {/* Search Input */}
        <div className="relative flex items-center px-4 py-3 bg-navy-850">
          <Search className="w-5 h-5 text-accent-cyan mr-3 flex-shrink-0" />
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={(e) => {
              setQuery(e.target.value)
              setSelectedIndex(0)
            }}
            placeholder="Type a command or search platform (e.g. analyze, incidents, ioc)..."
            className="w-full bg-transparent text-sm text-slate-100 placeholder-slate-400 focus:outline-none font-sans"
          />
          <button
            onClick={onClose}
            className="p-1 text-slate-400 hover:text-slate-200 rounded transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Results List */}
        <div className="max-h-80 overflow-y-auto p-2 space-y-1">
          {filtered.length === 0 ? (
            <div className="py-8 text-center text-slate-400 text-xs">
              No matching commands or destinations found for &quot;{query}&quot;
            </div>
          ) : (
            filtered.map((item, index) => {
              const Icon = item.icon
              const isSelected = index === selectedIndex
              return (
                <div
                  key={item.id}
                  onClick={() => {
                    onClose()
                    router.push(item.href)
                  }}
                  onMouseEnter={() => setSelectedIndex(index)}
                  className={`flex items-center justify-between p-2.5 rounded-lg text-xs cursor-pointer transition-colors ${
                    isSelected
                      ? 'bg-accent-blue/20 text-white border border-accent-blue/40'
                      : 'text-slate-300 hover:bg-navy-800'
                  }`}
                >
                  <div className="flex items-center gap-3 min-w-0 pr-2">
                    <div
                      className={`p-1.5 rounded-md ${
                        isSelected
                          ? 'bg-accent-blue text-white'
                          : 'bg-navy-800 text-slate-400 border border-navy-700'
                      }`}
                    >
                      <Icon className="w-4 h-4" />
                    </div>
                    <div className="min-w-0">
                      <div className="font-semibold text-slate-100 flex items-center gap-2">
                        <span>{item.title}</span>
                        <span className="text-[10px] font-mono text-slate-500 uppercase px-1.5 py-0.2 bg-navy-800 rounded">
                          {item.category}
                        </span>
                      </div>
                      {item.subtitle && (
                        <p className="text-[11px] text-slate-400 truncate mt-0.5">
                          {item.subtitle}
                        </p>
                      )}
                    </div>
                  </div>
                  <ArrowRight
                    className={`w-3.5 h-3.5 flex-shrink-0 transition-transform ${
                      isSelected ? 'text-accent-cyan translate-x-0.5' : 'text-slate-600'
                    }`}
                  />
                </div>
              )
            })
          )}
        </div>

        {/* Footer */}
        <div className="px-4 py-2 bg-navy-850 flex items-center justify-between text-[11px] text-slate-500 font-mono">
          <span>Navigate with ↑ ↓ and Press Enter</span>
          <span>Esc to exit</span>
        </div>
      </div>
    </div>
  )
}
