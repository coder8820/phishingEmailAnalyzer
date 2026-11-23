'use client'

import React from 'react'
import Link from 'next/link'
import { Shield, Lock, Terminal, Radio } from 'lucide-react'
import { Cyber3DBackground } from '@/components/3d/Cyber3DBackground'
import { AuthCard3D } from '@/components/auth/AuthCard3D'

interface AuthLayoutViewProps {
  initialMode: 'login' | 'register'
}

export function AuthLayoutView({ initialMode }: AuthLayoutViewProps) {
  return (
    <main className="h-[100dvh] w-full overflow-hidden flex flex-col justify-between items-center relative p-3 sm:p-4 bg-navy-950 text-slate-100">
      {/* Interactive 3D Three.js Background */}
      <Cyber3DBackground />

      {/* Cyber Vignette & Radial Depth Overlays */}
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_center,_transparent_0%,_rgba(5,10,20,0.4)_50%,_rgba(5,10,20,0.85)_100%)] z-[1]" />
      <div className="pointer-events-none absolute inset-0 bg-gradient-to-b from-navy-950/60 via-transparent to-navy-950/90 z-[1]" />

      {/* Top Header Bar */}
      <header className="relative z-10 w-full max-w-5xl flex items-center justify-between py-1">
        <Link
          href="/"
          className="flex items-center gap-2.5 text-xs text-slate-400 hover:text-slate-200 transition-colors group"
        >
          <div className="w-6 h-6 rounded-lg bg-navy-800 border border-navy-700 flex items-center justify-center text-accent-cyan group-hover:border-accent-cyan/40 transition-colors">
            <Shield className="w-3.5 h-3.5" />
          </div>
          <span className="font-mono text-[11px] tracking-wide text-slate-300">
            ← Home
          </span>
        </Link>

        {/* Live SOC Security Status Badge */}
        <div className="hidden sm:inline-flex items-center gap-2 px-3 py-1 rounded-full bg-navy-900/80 border border-navy-700/80 backdrop-blur-md text-[11px] font-mono text-slate-300">
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
            <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500" />
          </span>
          <span className="text-slate-400">SOC Node:</span>
          <span className="text-accent-cyan">Active Defense</span>
          <span className="text-slate-600">|</span>
          <span className="text-slate-400">TLS 1.3 / E2E</span>
        </div>
      </header>

      {/* Center 3D Interactive Card Viewport (No Scroll) */}
      <div className="relative z-10 w-full flex items-center justify-center my-auto">
        <AuthCard3D initialMode={initialMode} />
      </div>

      {/* Bottom Footer Information */}
      <footer className="relative z-10 w-full max-w-5xl flex flex-col sm:flex-row items-center justify-between text-[11px] font-mono text-slate-500 py-1 gap-1">
        <div className="flex items-center gap-2 text-slate-400">
          <Lock className="w-3 h-3 text-accent-cyan/80" />
          <span>Zero-Knowledge SOC Sandbox Architecture</span>
        </div>

        <div className="flex items-center gap-3">
          <span>Phishing EML Analyzer v1.0</span>
          <span>·</span>
          <span>Enterprise Threat Intelligence</span>
        </div>
      </footer>
    </main>
  )
}
