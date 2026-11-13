'use client'

import React, { useState } from 'react'
import { useRouter } from 'next/navigation'
import {
  Bell,
  X,
  CheckCheck,
  Trash2,
  AlertTriangle,
  ShieldAlert,
  Info,
  ExternalLink,
} from 'lucide-react'
import { useNotificationStore, type SOCNotification } from '@/store/notificationStore'
import { cn, formatDate } from '@/lib/utils'

interface NotificationDrawerProps {
  isOpen: boolean
  onClose: () => void
}

export function NotificationDrawer({ isOpen, onClose }: NotificationDrawerProps) {
  const router = useRouter()
  const {
    notifications,
    unreadCount,
    markAsRead,
    markAllAsRead,
    removeNotification,
    clearAll,
  } = useNotificationStore()

  const [filter, setFilter] = useState<'all' | 'unread' | 'critical'>('all')

  if (!isOpen) return null

  const filtered = notifications.filter((n) => {
    if (filter === 'unread') return !n.read
    if (filter === 'critical') return n.severity === 'critical'
    return true
  })

  const getSeverityIcon = (sev: SOCNotification['severity']) => {
    switch (sev) {
      case 'critical':
        return <ShieldAlert className="w-4 h-4 text-red-400" />
      case 'high':
        return <AlertTriangle className="w-4 h-4 text-orange-400" />
      case 'medium':
        return <AlertTriangle className="w-4 h-4 text-yellow-400" />
      default:
        return <Info className="w-4 h-4 text-blue-400" />
    }
  }

  const getSeverityBadge = (sev: SOCNotification['severity']) => {
    switch (sev) {
      case 'critical':
        return 'bg-red-500/10 text-red-400 border-red-500/20'
      case 'high':
        return 'bg-orange-500/10 text-orange-400 border-orange-500/20'
      case 'medium':
        return 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20'
      default:
        return 'bg-blue-500/10 text-blue-400 border-blue-500/20'
    }
  }

  const handleItemClick = (n: SOCNotification) => {
    markAsRead(n.id)
    if (n.link) {
      onClose()
      router.push(n.link)
    }
  }

  return (
    <div className="fixed inset-0 z-50 overflow-hidden">
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-navy-950/70 backdrop-blur-sm transition-opacity"
        onClick={onClose}
      />

      <div className="fixed inset-y-0 right-0 max-w-full flex pl-10">
        <div className="w-screen max-w-md bg-navy-900 border-l border-navy-700 shadow-2xl flex flex-col">
          {/* Header */}
          <div className="p-4 border-b border-navy-700/80 bg-navy-850 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <div className="p-2 bg-navy-800 rounded-lg border border-navy-700">
                <Bell className="w-4 h-4 text-accent-cyan" />
              </div>
              <div>
                <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                  SOC Threat Notifications
                  {unreadCount() > 0 && (
                    <span className="px-1.5 py-0.5 text-[10px] bg-red-500 text-white font-mono rounded-full">
                      {unreadCount()}
                    </span>
                  )}
                </h2>
                <p className="text-[11px] text-slate-400">Real-time alerts & ingestion events</p>
              </div>
            </div>
            <button
              onClick={onClose}
              className="p-1.5 text-slate-400 hover:text-slate-100 hover:bg-navy-800 rounded-lg transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          {/* Action Toolbar */}
          <div className="px-4 py-2.5 bg-navy-850/60 border-b border-navy-700/60 flex items-center justify-between text-xs">
            {/* Filter Pills */}
            <div className="flex items-center gap-1">
              <button
                onClick={() => setFilter('all')}
                className={cn(
                  'px-2.5 py-1 rounded text-[11px] font-medium transition-colors',
                  filter === 'all'
                    ? 'bg-accent-blue text-white'
                    : 'text-slate-400 hover:bg-navy-800 hover:text-slate-200'
                )}
              >
                All ({notifications.length})
              </button>
              <button
                onClick={() => setFilter('unread')}
                className={cn(
                  'px-2.5 py-1 rounded text-[11px] font-medium transition-colors',
                  filter === 'unread'
                    ? 'bg-accent-blue text-white'
                    : 'text-slate-400 hover:bg-navy-800 hover:text-slate-200'
                )}
              >
                Unread ({unreadCount()})
              </button>
              <button
                onClick={() => setFilter('critical')}
                className={cn(
                  'px-2.5 py-1 rounded text-[11px] font-medium transition-colors',
                  filter === 'critical'
                    ? 'bg-accent-blue text-white'
                    : 'text-slate-400 hover:bg-navy-800 hover:text-slate-200'
                )}
              >
                Critical
              </button>
            </div>

            {/* Quick Actions */}
            <div className="flex items-center gap-2">
              <button
                onClick={() => markAllAsRead()}
                className="text-slate-400 hover:text-accent-cyan flex items-center gap-1 text-[11px] transition-colors"
                title="Mark all as read"
              >
                <CheckCheck className="w-3.5 h-3.5" />
                <span>Read all</span>
              </button>
              <button
                onClick={() => clearAll()}
                className="text-slate-400 hover:text-red-400 flex items-center gap-1 text-[11px] transition-colors"
                title="Clear all notifications"
              >
                <Trash2 className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>

          {/* Notification List */}
          <div className="flex-1 overflow-y-auto divide-y divide-navy-800 p-2 space-y-1">
            {filtered.length === 0 ? (
              <div className="h-64 flex flex-col items-center justify-center text-center p-6 text-slate-500">
                <Bell className="w-8 h-8 mb-2 opacity-30" />
                <p className="text-xs font-medium text-slate-400">No notifications in this view</p>
                <p className="text-[11px] text-slate-500 mt-1">All clear across defense perimeter</p>
              </div>
            ) : (
              filtered.map((n) => (
                <div
                  key={n.id}
                  onClick={() => handleItemClick(n)}
                  className={cn(
                    'p-3 rounded-lg border transition-all cursor-pointer relative group',
                    n.read
                      ? 'bg-navy-850/40 border-navy-800 hover:bg-navy-800/80 hover:border-navy-700'
                      : 'bg-navy-800/90 border-navy-700/80 hover:bg-navy-750 hover:border-accent-blue/40 shadow-sm'
                  )}
                >
                  <div className="flex items-start gap-3">
                    <div className="p-1.5 rounded-md bg-navy-900 border border-navy-700/80 flex-shrink-0 mt-0.5">
                      {getSeverityIcon(n.severity)}
                    </div>
                    <div className="flex-1 min-w-0 pr-4">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-semibold text-slate-200 truncate">
                          {n.title}
                        </span>
                        {!n.read && (
                          <span className="w-2 h-2 rounded-full bg-accent-blue flex-shrink-0" />
                        )}
                      </div>
                      <p className="text-[11px] text-slate-400 mt-1 line-clamp-2 leading-relaxed">
                        {n.message}
                      </p>
                      <div className="flex items-center gap-2 mt-2">
                        <span
                          className={cn(
                            'text-[9px] font-mono uppercase px-1.5 py-0.5 rounded border',
                            getSeverityBadge(n.severity)
                          )}
                        >
                          {n.severity}
                        </span>
                        {n.source && (
                          <span className="text-[10px] text-slate-500 font-mono">
                            [{n.source}]
                          </span>
                        )}
                        <span className="text-[10px] text-slate-500 ml-auto">
                          {formatDate(n.timestamp)}
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Dismiss Single */}
                  <button
                    onClick={(e) => {
                      e.stopPropagation()
                      removeNotification(n.id)
                    }}
                    className="absolute right-2 top-2 p-1 text-slate-600 hover:text-slate-300 opacity-0 group-hover:opacity-100 transition-opacity"
                    title="Dismiss notification"
                  >
                    <X className="w-3 h-3" />
                  </button>
                </div>
              ))
            )}
          </div>

          {/* Footer */}
          <div className="p-3 border-t border-navy-800 bg-navy-850 text-center">
            <span className="text-[10px] text-slate-500 font-mono tracking-wider">
              PHISHGUARD AI DEFENSE LOG • ENTERPRISE SOC
            </span>
          </div>
        </div>
      </div>
    </div>
  )
}
