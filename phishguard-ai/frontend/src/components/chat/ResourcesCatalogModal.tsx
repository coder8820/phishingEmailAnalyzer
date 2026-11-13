'use client'

import React, { useState } from 'react'
import { X, Search, Globe, Shield, ExternalLink, Filter } from 'lucide-react'
import { CyberResource } from '@/services/chatService'
import { ResourceCard } from './ResourceCard'

interface ResourcesCatalogModalProps {
  isOpen: boolean
  onClose: () => void
  resources: CyberResource[]
}

export function ResourcesCatalogModal({ isOpen, onClose, resources }: ResourcesCatalogModalProps) {
  const [searchQuery, setSearchQuery] = useState('')
  const [selectedCategory, setSelectedCategory] = useState<string>('all')

  if (!isOpen) return null

  const categories = [
    { id: 'all', label: 'All Resources' },
    { id: 'intel', label: 'Threat Intelligence' },
    { id: 'email', label: 'Email & Headers' },
    { id: 'phish', label: 'Phishing Feeds' },
    { id: 'sandbox', label: 'Sandboxes' },
    { id: 'standard', label: 'RFC Standards & Frameworks' },
  ]

  const filtered = resources.filter((item) => {
    const matchesSearch =
      item.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.tags.some((t) => t.toLowerCase().includes(searchQuery.toLowerCase()))

    if (!matchesSearch) return false

    if (selectedCategory === 'all') return true
    const cat = item.category.toLowerCase()
    if (selectedCategory === 'intel') return cat.includes('threat') || cat.includes('reputation') || cat.includes('ip')
    if (selectedCategory === 'email') return cat.includes('email') || cat.includes('header') || cat.includes('dmarc')
    if (selectedCategory === 'phish') return cat.includes('phishing')
    if (selectedCategory === 'sandbox') return cat.includes('sandbox')
    if (selectedCategory === 'standard') return cat.includes('rfc') || cat.includes('framework') || cat.includes('standard')
    return true
  })

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-navy-950/80 backdrop-blur-sm animate-fade-in">
      <div className="relative w-full max-w-4xl max-h-[85vh] flex flex-col rounded-2xl bg-navy-800 border border-navy-600 shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-navy-700 bg-navy-850">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-accent-blue/15 border border-accent-blue/30 flex items-center justify-center">
              <Globe className="w-5 h-5 text-accent-cyan" />
            </div>
            <div>
              <h3 className="text-base font-bold text-white">Verified External Security Platforms</h3>
              <p className="text-xs text-slate-400">
                Industry-standard threat feeds, email diagnostic tools, and sandboxes for SOC investigations.
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 text-slate-400 hover:text-white hover:bg-navy-700 rounded-lg transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Filter & Search Bar */}
        <div className="p-4 border-b border-navy-700/80 bg-navy-900/60 flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search tools, tags, protocols (e.g. VirusTotal, SPF, ANY.RUN)..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-9 pr-4 py-2 rounded-xl bg-navy-950 border border-navy-700 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-accent-cyan transition-colors"
            />
          </div>

          <div className="flex items-center gap-1.5 overflow-x-auto pb-1 sm:pb-0 scrollbar-none">
            {categories.map((c) => (
              <button
                key={c.id}
                onClick={() => setSelectedCategory(c.id)}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium whitespace-nowrap transition-colors ${
                  selectedCategory === c.id
                    ? 'bg-accent-blue/20 text-accent-cyan border border-accent-blue/40 font-semibold'
                    : 'bg-navy-950/60 text-slate-400 hover:text-slate-200 border border-navy-800'
                }`}
              >
                {c.label}
              </button>
            ))}
          </div>
        </div>

        {/* Grid List */}
        <div className="flex-1 overflow-y-auto p-6 grid grid-cols-1 md:grid-cols-2 gap-4">
          {filtered.length === 0 ? (
            <div className="col-span-full py-12 text-center text-slate-400 text-sm">
              No cybersecurity tools found matching &quot;{searchQuery}&quot;.
            </div>
          ) : (
            filtered.map((item) => <ResourceCard key={item.id} resource={item} />)
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-3 border-t border-navy-700 bg-navy-850/80 flex items-center justify-between text-xs text-slate-400">
          <span>Showing {filtered.length} curated resources</span>
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg bg-navy-700 text-slate-200 hover:bg-navy-600 transition-colors font-medium"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  )
}
