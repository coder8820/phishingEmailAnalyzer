'use client'

import React, { useState, useEffect, useRef } from 'react'
import Link from 'next/link'
import { useRouter } from 'next/navigation'
import {
  Bell,
  Search,
  ShieldCheck,
  User,
  Settings,
  LogOut,
  ChevronDown,
  FileText,
  AlertTriangle,
} from 'lucide-react'
import { useAuthStore } from '@/store/authStore'
import { useNotificationStore } from '@/store/notificationStore'
import { NotificationDrawer } from '@/components/notifications/NotificationDrawer'
import { CommandPalette } from '@/components/layout/CommandPalette'

export function TopNav() {
  const router = useRouter()
  const { user, logout } = useAuthStore()
  const { unreadCount } = useNotificationStore()

  const [isNotificationsOpen, setIsNotificationsOpen] = useState(false)
  const [isCommandPaletteOpen, setIsCommandPaletteOpen] = useState(false)
  const [isUserMenuOpen, setIsUserMenuOpen] = useState(false)
  const userMenuRef = useRef<HTMLDivElement>(null)

  // Global Ctrl+K / Cmd+K listener
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        setIsCommandPaletteOpen((prev) => !prev)
      }
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [])

  // Close user menu on outside click
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (userMenuRef.current && !userMenuRef.current.contains(e.target as Node)) {
        setIsUserMenuOpen(false)
      }
    }
    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  const count = unreadCount()

  return (
    <>
      <header className="sticky top-0 z-30 h-16 bg-navy-800/95 backdrop-blur-md border-b border-navy-600/70 px-6 flex items-center justify-between shadow-md shadow-black/20">
        {/* Global Search Bar (Opens Command Palette) */}
        <div
          onClick={() => setIsCommandPaletteOpen(true)}
          className="relative w-80 cursor-pointer group"
        >
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2 group-hover:text-accent-cyan transition-colors" />
          <input
            type="text"
            readOnly
            placeholder="Search emails, IOCs, domains... (Ctrl+K)"
            className="w-full bg-navy-900 border border-navy-600 rounded-lg pl-9 pr-14 py-1.5 text-xs text-slate-200 placeholder-slate-400 cursor-pointer focus:outline-none group-hover:border-accent-blue/50 transition-colors"
          />
          <kbd className="absolute right-2.5 top-1/2 -translate-y-1/2 px-1.5 py-0.5 text-[10px] font-mono text-slate-400 bg-navy-800 border border-navy-700 rounded shadow-sm">
            ⌘K
          </kbd>
        </div>

        {/* Right Controls */}
        <div className="flex items-center gap-4">
          {/* Defense status indicator */}
          <div className="hidden sm:flex items-center gap-2 px-3 py-1 bg-green-500/10 border border-green-500/20 rounded-full">
            <span className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
            <span className="text-xs font-mono text-green-400 font-semibold tracking-wide">
              DEFENSE ACTIVE
            </span>
          </div>

          {/* Notification Bell */}
          <button
            onClick={() => setIsNotificationsOpen(true)}
            className="relative p-2 text-slate-300 hover:text-white hover:bg-navy-700/80 rounded-lg transition-colors border border-transparent hover:border-navy-600"
            title="SOC Notifications"
          >
            <Bell className="w-4 h-4" />
            {count > 0 && (
              <span className="absolute -top-1 -right-1 min-w-[18px] h-[18px] px-1 bg-red-500 text-white text-[10px] font-bold font-mono rounded-full flex items-center justify-center animate-bounce shadow-md shadow-red-500/30">
                {count > 9 ? '9+' : count}
              </span>
            )}
          </button>

          {/* User Profile Dropdown Menu */}
          <div className="relative border-l border-navy-600/70 pl-4" ref={userMenuRef}>
            <button
              onClick={() => setIsUserMenuOpen((prev) => !prev)}
              className="flex items-center gap-3 p-1.5 rounded-lg hover:bg-navy-700/60 transition-colors text-left"
            >
              <div className="w-8 h-8 rounded-lg bg-accent-blue/20 border border-accent-blue/40 flex items-center justify-center text-accent-cyan font-bold text-xs">
                {(user?.display_name || user?.username || 'A').slice(0, 2).toUpperCase()}
              </div>
              <div className="hidden md:block">
                <div className="text-xs font-semibold text-slate-100 flex items-center gap-1">
                  <span>{user?.display_name || user?.username || 'SOC Analyst'}</span>
                  <ChevronDown className="w-3 h-3 text-slate-400" />
                </div>
                <div className="text-[10px] text-slate-400 font-mono uppercase tracking-wider">
                  {user?.role || 'security_admin'}
                </div>
              </div>
            </button>

            {/* Dropdown Card */}
            {isUserMenuOpen && (
              <div className="absolute right-0 mt-2 w-64 bg-navy-900 border border-navy-700 rounded-xl shadow-2xl py-2 z-50 divide-y divide-navy-800">
                <div className="px-4 py-2.5">
                  <p className="text-xs font-bold text-slate-100 truncate">
                    {user?.display_name || user?.username || 'SOC Analyst'}
                  </p>
                  <p className="text-[11px] text-slate-400 truncate">{user?.email}</p>
                  <div className="mt-2 flex items-center gap-1.5">
                    <span className="px-1.5 py-0.5 bg-accent-blue/20 border border-accent-blue/30 text-accent-cyan text-[10px] font-mono rounded uppercase">
                      {user?.role || 'Analyst'}
                    </span>
                    <span className="text-[10px] text-slate-500 font-mono">
                      Tenant: {user?.organization_id?.slice(0, 8) || 'Primary'}
                    </span>
                  </div>
                </div>

                <div className="py-1 text-xs">
                  <Link
                    href="/settings"
                    onClick={() => setIsUserMenuOpen(false)}
                    className="flex items-center gap-2.5 px-4 py-2 text-slate-300 hover:text-white hover:bg-navy-800 transition-colors"
                  >
                    <Settings className="w-4 h-4 text-slate-400" />
                    <span>Profile & System Settings</span>
                  </Link>

                  <Link
                    href="/incidents"
                    onClick={() => setIsUserMenuOpen(false)}
                    className="flex items-center gap-2.5 px-4 py-2 text-slate-300 hover:text-white hover:bg-navy-800 transition-colors"
                  >
                    <AlertTriangle className="w-4 h-4 text-slate-400" />
                    <span>My Assigned Incidents</span>
                  </Link>

                  <Link
                    href="/reports"
                    onClick={() => setIsUserMenuOpen(false)}
                    className="flex items-center gap-2.5 px-4 py-2 text-slate-300 hover:text-white hover:bg-navy-800 transition-colors"
                  >
                    <FileText className="w-4 h-4 text-slate-400" />
                    <span>Compliance & Reports</span>
                  </Link>
                </div>

                <div className="py-1 text-xs">
                  <button
                    onClick={() => {
                      setIsUserMenuOpen(false)
                      logout()
                    }}
                    className="w-full flex items-center gap-2.5 px-4 py-2 text-red-400 hover:text-red-300 hover:bg-red-500/10 transition-colors text-left"
                  >
                    <LogOut className="w-4 h-4" />
                    <span>Sign Out of Console</span>
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      </header>

      {/* Notification Drawer Modal */}
      <NotificationDrawer
        isOpen={isNotificationsOpen}
        onClose={() => setIsNotificationsOpen(false)}
      />

      {/* Ctrl+K Command Palette Modal */}
      <CommandPalette
        isOpen={isCommandPaletteOpen}
        onClose={() => setIsCommandPaletteOpen(false)}
      />
    </>
  )
}
