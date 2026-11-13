'use client'

import React, { useState, useEffect } from 'react'
import Link from 'next/link'
import {
  ShieldAlert,
  LayoutDashboard,
  ArrowRight,
  LogOut,
  User as UserIcon,
  Menu,
  X,
  ChevronRight,
  Sparkles,
  ShieldCheck,
} from 'lucide-react'
import { useAuthStore } from '@/store/authStore'
import { cn } from '@/lib/utils'

interface LandingNavProps {
  onOpenDemo?: () => void
  isAppView?: boolean
}

const LANDING_NAV_LINKS = [
  { href: '/#services', label: 'Services' },
  { href: '/#pipeline', label: 'Forensic Engine' },
  { href: '/#guidance', label: 'SOC Guidance' },
  { href: '/#about', label: 'About Us' },
  { href: '/#team', label: 'Research Team' },
  { href: '/#pricing', label: 'Subscription' },
  { href: '/#faq', label: 'FAQ' },
]

export function LandingNav({ onOpenDemo, isAppView = false }: LandingNavProps) {
  const { user, isAuthenticated, logout } = useAuthStore()
  const [mounted, setMounted] = useState(false)
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)
  const [scrolled, setScrolled] = useState(false)
  const [activeSection, setActiveSection] = useState('')

  // Prevent SSR hydration mismatch when reading localStorage auth
  useEffect(() => {
    setMounted(true)
  }, [])

  // Detect scroll state and active section
  useEffect(() => {
    const handleScroll = () => {
      setScrolled(window.scrollY > 20)

      const sections = ['services', 'pipeline', 'guidance', 'about', 'team', 'pricing', 'faq']
      const current = sections.find((section) => {
        const el = document.getElementById(section)
        if (el) {
          const rect = el.getBoundingClientRect()
          return rect.top <= 200 && rect.bottom >= 200
        }
        return false
      })
      if (current) {
        setActiveSection(current)
      } else if (window.scrollY < 200) {
        setActiveSection('')
      }
    }

    window.addEventListener('scroll', handleScroll, { passive: true })
    return () => window.removeEventListener('scroll', handleScroll)
  }, [])

  const handleLogout = async () => {
    try {
      await logout()
    } catch {
      // ignore
    }
  }

  // Format user role label for badge display
  const isSuperOrSecAdmin =
    user?.role === 'super_admin' || user?.role === 'security_admin'
  const roleBadgeLabel = isSuperOrSecAdmin
    ? 'Admin'
    : user?.role === 'analyst'
    ? 'Analyst'
    : 'User'

  const isLoggedIn = mounted && isAuthenticated

  return (
    <header
      className={cn(
        'w-full transition-all duration-300',
        scrolled
          ? 'bg-navy-950/90 backdrop-blur-xl border-b border-navy-700/80 shadow-xl shadow-black/50 py-2.5'
          : 'bg-navy-900/85 backdrop-blur-md border-b border-navy-800/60 py-3.5'
      )}
    >
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="relative flex items-center justify-between min-h-[44px]">
          {/* ─────────────────────────────────────────────────────────────
              1. LOGO: ONLY LOGO ICON / EMBLEM (NO TEXT)
          ───────────────────────────────────────────────────────────── */}
          <div className="flex-shrink-0 z-10 flex items-center">
            <Link
              href="/"
              className="group relative flex items-center justify-center focus:outline-none"
              title="PhishGuard AI"
              aria-label="PhishGuard AI Home"
            >
              {/* Outer cyber glow aura */}
              <div className="absolute -inset-1.5 bg-gradient-to-r from-accent-blue/40 via-accent-cyan/30 to-blue-500/40 rounded-2xl blur-md opacity-50 group-hover:opacity-100 group-hover:scale-110 transition-all duration-500" />

              {/* Logo Emblem Container */}
              <div className="relative w-11 h-11 rounded-xl bg-gradient-to-br from-navy-800 via-navy-900 to-navy-950 border border-accent-blue/40 group-hover:border-accent-cyan flex items-center justify-center transition-all duration-300 shadow-lg shadow-accent-blue/20 group-hover:shadow-accent-cyan/30 group-hover:scale-105 active:scale-95">
                <ShieldAlert className="w-6 h-6 text-accent-cyan group-hover:text-accent-blue transition-colors duration-300" />

                {/* Radar defense status indicator */}
                <span className="absolute -top-1 -right-1 flex h-2.5 w-2.5">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
                  <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500 ring-2 ring-navy-900" />
                </span>
              </div>
            </Link>
          </div>

          {/* ─────────────────────────────────────────────────────────────
              2. CENTERED SINGLE-LINE NAVIGATION MENU
                 (Centered across the entire bar, reduced font size & smooth animations)
          ───────────────────────────────────────────────────────────── */}
          <nav className="hidden lg:flex items-center justify-center absolute inset-x-0 mx-auto pointer-events-none">
            <div className="pointer-events-auto flex items-center gap-1 xl:gap-1.5 px-3 py-1.5 rounded-full bg-navy-950/70 border border-navy-700/60 backdrop-blur-md shadow-inner shadow-black/40">
              {LANDING_NAV_LINKS.map((link) => {
                const sectionName = link.href.split('#')[1]
                const isActive = activeSection === sectionName
                return (
                  <Link
                    key={link.href}
                    href={link.href}
                    className={cn(
                      'relative px-3 py-1 rounded-full text-xs font-medium tracking-wide whitespace-nowrap transition-all duration-200 group flex items-center',
                      isActive
                        ? 'text-white font-semibold'
                        : 'text-slate-300 hover:text-white'
                    )}
                  >
                    {/* Hover & Active Glowing Capsule */}
                    <span
                      className={cn(
                        'absolute inset-0 rounded-full transition-all duration-300 -z-10',
                        isActive
                          ? 'bg-gradient-to-r from-accent-blue/25 to-accent-cyan/25 border border-accent-cyan/40 shadow-sm shadow-accent-cyan/20'
                          : 'bg-white/0 group-hover:bg-navy-800/80 group-hover:border group-hover:border-navy-600/60'
                      )}
                    />

                    <span>{link.label}</span>

                    {/* Animated Indicator Bar */}
                    <span
                      className={cn(
                        'absolute bottom-0 left-1/2 -translate-x-1/2 h-[2px] rounded-full bg-gradient-to-r from-accent-blue to-accent-cyan transition-all duration-300',
                        isActive
                          ? 'w-3/5 opacity-100'
                          : 'w-0 opacity-0 group-hover:w-3/5 group-hover:opacity-100'
                      )}
                    />
                  </Link>
                )
              })}
            </div>
          </nav>

          {/* ─────────────────────────────────────────────────────────────
              3. RIGHT SIDE AUTH ACTIONS (LOGIN / REGISTER OR DASHBOARD)
          ───────────────────────────────────────────────────────────── */}
          <div className="hidden sm:flex items-center gap-2.5 flex-shrink-0 z-10 ml-auto">
            {!mounted ? (
              // Hydration skeleton placeholder to eliminate layout flicker
              <div className="h-9 w-36 bg-navy-800/50 animate-pulse rounded-full" />
            ) : isLoggedIn ? (
              // User IS Logged In (Admin or Normal User who has not logged out)
              <div className="flex items-center gap-2 bg-navy-950/80 border border-navy-700/70 rounded-full p-1 pl-3 backdrop-blur-md shadow-lg shadow-black/40">
                {/* User Role & Name */}
                <div className="flex items-center gap-2 pr-1">
                  <div className="w-5 h-5 rounded-full bg-gradient-to-br from-accent-blue/20 to-accent-cyan/20 border border-accent-blue/40 flex items-center justify-center text-accent-cyan">
                    <UserIcon className="w-3 h-3" />
                  </div>
                  <div className="flex flex-col text-left">
                    <div className="flex items-center gap-1.5">
                      <span
                        className={cn(
                          'text-[9px] font-mono font-bold px-1.5 py-0.2 rounded leading-tight uppercase',
                          isSuperOrSecAdmin
                            ? 'bg-purple-500/20 text-purple-300 border border-purple-500/30'
                            : 'bg-accent-blue/20 text-accent-cyan border border-accent-blue/30'
                        )}
                      >
                        {roleBadgeLabel}
                      </span>
                    </div>
                    <span className="text-[11px] font-medium text-slate-200 leading-tight max-w-[80px] sm:max-w-[100px] truncate">
                      {user?.display_name || user?.username || 'Analyst'}
                    </span>
                  </div>
                </div>

                {/* Dashboard Button */}
                <Link
                  href="/dashboard"
                  className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-full bg-gradient-to-r from-accent-blue to-blue-600 hover:from-blue-600 hover:to-accent-blue text-white text-xs font-semibold shadow-md shadow-accent-blue/25 hover:shadow-accent-blue/45 transition-all duration-200 hover:scale-[1.03] active:scale-[0.98]"
                >
                  <LayoutDashboard className="w-3.5 h-3.5 text-accent-cyan" />
                  <span>Dashboard</span>
                  <ArrowRight className="w-3 h-3" />
                </Link>

                {/* Quick Log Out Action */}
                <button
                  onClick={handleLogout}
                  className="p-1.5 rounded-full text-slate-400 hover:text-red-400 hover:bg-red-500/10 transition-colors"
                  title="Sign out of account"
                  aria-label="Logout"
                >
                  <LogOut className="w-3.5 h-3.5" />
                </button>
              </div>
            ) : (
              // User IS NOT Logged In (Show Login & Register)
              <div className="flex items-center gap-2">
                <Link
                  href="/login"
                  className="px-3.5 py-1.5 text-xs font-medium text-slate-300 hover:text-white hover:bg-navy-800/80 rounded-full border border-navy-700/60 hover:border-slate-500 transition-all duration-200"
                >
                  Sign In
                </Link>

                <Link
                  href="/register"
                  className="inline-flex items-center gap-1.5 px-4 py-1.5 rounded-full bg-gradient-to-r from-accent-blue to-blue-600 hover:from-blue-600 hover:to-accent-blue text-white text-xs font-semibold shadow-md shadow-accent-blue/20 hover:shadow-accent-blue/40 transition-all duration-200 hover:scale-[1.03] active:scale-[0.98]"
                >
                  <span>Register</span>
                  <ArrowRight className="w-3 h-3" />
                </Link>
              </div>
            )}
          </div>

          {/* ─────────────────────────────────────────────────────────────
              4. MOBILE MENU HAMBURGER BUTTON
          ───────────────────────────────────────────────────────────── */}
          <button
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            className="lg:hidden p-2 rounded-xl bg-navy-800/90 border border-navy-700 text-slate-300 hover:text-white hover:bg-navy-700 transition-colors z-10"
            aria-label="Toggle Mobile Navigation"
          >
            {mobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
          </button>
        </div>

        {/* ─────────────────────────────────────────────────────────────
            5. MOBILE NAVIGATION DRAWER
        ───────────────────────────────────────────────────────────── */}
        {mobileMenuOpen && (
          <div className="lg:hidden mt-3 pt-3 border-t border-navy-800/80 bg-navy-950/95 backdrop-blur-xl rounded-2xl p-5 space-y-4 animate-in fade-in slide-in-from-top-3 shadow-2xl border border-navy-700/70">
            {/* Links */}
            <div className="flex flex-col space-y-1">
              {LANDING_NAV_LINKS.map((link) => (
                <Link
                  key={link.href}
                  href={link.href}
                  onClick={() => setMobileMenuOpen(false)}
                  className="px-3 py-2 rounded-lg text-sm font-medium text-slate-300 hover:text-accent-cyan hover:bg-navy-800/60 transition-colors flex items-center justify-between"
                >
                  <span>{link.label}</span>
                  <ChevronRight className="w-3.5 h-3.5 text-slate-500" />
                </Link>
              ))}
            </div>

            {/* Mobile Auth Actions */}
            <div className="pt-3 border-t border-navy-800 flex flex-col gap-2.5">
              {!mounted ? (
                <div className="h-10 bg-navy-800/60 rounded-xl animate-pulse" />
              ) : isLoggedIn ? (
                <>
                  <div className="flex items-center justify-between px-3 py-2 bg-navy-900/90 rounded-xl border border-navy-700/60">
                    <div className="flex items-center gap-2">
                      <div className="w-7 h-7 rounded-full bg-accent-blue/20 border border-accent-blue/30 flex items-center justify-center text-accent-cyan">
                        <UserIcon className="w-3.5 h-3.5" />
                      </div>
                      <div>
                        <div className="text-xs font-semibold text-white">
                          {user?.display_name || user?.username || 'Active Account'}
                        </div>
                        <div className="text-[10px] font-mono text-accent-cyan uppercase">
                          Role: {roleBadgeLabel}
                        </div>
                      </div>
                    </div>
                    <button
                      onClick={() => {
                        setMobileMenuOpen(false)
                        handleLogout()
                      }}
                      className="text-xs text-red-400 hover:text-red-300 flex items-center gap-1 font-medium px-2 py-1 rounded bg-red-500/10 border border-red-500/20"
                    >
                      <LogOut className="w-3 h-3" />
                      <span>Logout</span>
                    </button>
                  </div>

                  <Link
                    href="/dashboard"
                    onClick={() => setMobileMenuOpen(false)}
                    className="w-full inline-flex items-center justify-center gap-2 py-2.5 rounded-xl bg-gradient-to-r from-accent-blue to-blue-600 text-white font-semibold text-sm shadow-md shadow-accent-blue/25"
                  >
                    <LayoutDashboard className="w-4 h-4 text-accent-cyan" />
                    <span>Open SOC Dashboard</span>
                    <ArrowRight className="w-4 h-4" />
                  </Link>
                </>
              ) : (
                <>
                  <Link
                    href="/login"
                    onClick={() => setMobileMenuOpen(false)}
                    className="w-full text-center py-2.5 rounded-xl bg-navy-900 border border-navy-700 text-slate-200 font-medium text-sm hover:bg-navy-800"
                  >
                    Sign In to Console
                  </Link>
                  <Link
                    href="/register"
                    onClick={() => setMobileMenuOpen(false)}
                    className="w-full inline-flex items-center justify-center gap-1.5 py-2.5 rounded-xl bg-gradient-to-r from-accent-blue to-blue-600 text-white font-semibold text-sm shadow-md shadow-accent-blue/25"
                  >
                    <span>Register Free Account</span>
                    <ArrowRight className="w-4 h-4" />
                  </Link>
                </>
              )}
            </div>
          </div>
        )}
      </div>
    </header>
  )
}
