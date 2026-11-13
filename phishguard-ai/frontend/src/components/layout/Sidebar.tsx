'use client'

import Link from 'next/link'
import {
  LayoutDashboard,
  Mail,
  History,
  Shield,
  Search,
  AlertTriangle,
  FileText,
  Zap,
  Plug,
  ScrollText,
  Settings,
  LogOut,
  ShieldAlert,
  Lock,
  Bot,
  Sparkles,
} from 'lucide-react'
import { useAuthStore } from '@/store/authStore'
import { cn } from '@/lib/utils'

interface NavItem {
  label: string
  href: string
  icon: any
  adminOnly?: boolean
  badge?: string
}

const navItems: NavItem[] = [
  { label: 'Dashboard', href: '/dashboard', icon: LayoutDashboard },
  { label: 'AI Assistant', href: '/ai-assistant', icon: Bot, badge: 'AI' },
  { label: 'Email Analyzer', href: '/email-analyzer', icon: Mail },
  { label: 'Investigation History', href: '/investigation-history', icon: History },
  { label: 'Threat Intelligence', href: '/threat-intelligence', icon: Shield },
  { label: 'IOC Explorer', href: '/ioc-explorer', icon: Search },
  { label: 'Incident Management', href: '/incidents', icon: AlertTriangle },
  { label: 'Reports', href: '/reports', icon: FileText },
  { label: 'Detection Rules', href: '/detection-rules', icon: Zap },
  { label: 'Integrations', href: '/integrations', icon: Plug, adminOnly: true },
  { label: 'Audit Logs', href: '/audit-logs', icon: ScrollText, adminOnly: true },
  { label: 'Settings', href: '/settings', icon: Settings },
]


export function Sidebar({ currentPath }: { currentPath: string }) {
  const { user, logout } = useAuthStore()
  const isAdmin = user?.role === 'super_admin' || user?.role === 'security_admin'

  return (
    <aside className="w-64 bg-navy-800 border-r border-navy-600 flex flex-col h-full select-none">
      {/* Brand Header */}
      <div className="h-16 flex items-center px-6 gap-3 border-b border-navy-600/70">
        <div className="w-9 h-9 rounded-xl bg-accent-blue/15 border border-accent-blue/30 flex items-center justify-center shadow-lg shadow-accent-blue/5">
          <ShieldAlert className="w-5 h-5 text-accent-blue" />
        </div>
        <div>
          <span className="font-bold text-base tracking-wide text-white">
            PhishGuard <span className="text-accent-cyan font-mono text-sm">AI</span>
          </span>
          <span className="block text-[10px] text-slate-400 font-mono tracking-widest uppercase">
            SOC Defense Suite
          </span>
        </div>
      </div>

      {/* Nav List */}
      <div className="flex-1 overflow-y-auto py-4 px-3 space-y-1">
        {navItems.map((item) => {
          const Icon = item.icon
          const isActive =
            currentPath === item.href ||
            (item.href !== '/dashboard' && currentPath.startsWith(item.href))

          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                'flex items-center gap-3 px-3.5 py-2.5 rounded-lg text-sm font-medium transition-all duration-150 group',
                isActive
                  ? 'bg-accent-blue/15 text-accent-blue font-semibold border-l-4 border-accent-blue'
                  : 'text-slate-400 hover:text-slate-100 hover:bg-navy-700/60'
              )}
            >
              <Icon
                className={cn(
                  'w-4 h-4 shrink-0',
                  isActive ? 'text-accent-blue' : 'text-slate-400 group-hover:text-slate-200'
                )}
              />
              <span className="truncate">{item.label}</span>

              {item.badge && (
                <span className="ml-auto text-[10px] font-mono font-bold px-1.5 py-0.5 rounded leading-none shrink-0 bg-accent-cyan/15 text-accent-cyan border border-accent-cyan/30">
                  {item.badge}
                </span>
              )}

              {item.adminOnly && (
                <span
                  className={cn(
                    'ml-auto text-[9px] font-mono font-bold px-1.5 py-0.5 rounded leading-none shrink-0',
                    isAdmin
                      ? 'bg-purple-500/20 text-purple-300 border border-purple-500/30'
                      : 'bg-navy-900 text-slate-500 border border-navy-700'
                  )}
                  title={isAdmin ? 'Super Admin Control' : 'Requires Admin Access'}
                >
                  {isAdmin ? 'ADMIN' : <Lock className="w-2.5 h-2.5 inline" />}
                </span>
              )}
            </Link>
          )
        })}
      </div>

      {/* User Footer */}
      <div className="p-4 border-t border-navy-600/70 bg-navy-850/60">
        <div className="flex items-center justify-between">
          <div className="min-w-0 pr-2">
            <p className="text-sm font-medium text-slate-200 truncate">
              {user?.display_name || user?.username || 'SOC Analyst'}
            </p>
            <div className="flex items-center gap-1.5 mt-0.5">
              <span
                className={cn(
                  'text-[10px] font-mono font-bold uppercase px-1.5 py-0.2 rounded',
                  isAdmin
                    ? 'bg-purple-500/20 text-purple-300 border border-purple-500/30'
                    : 'bg-accent-blue/15 text-accent-cyan border border-accent-blue/20'
                )}
              >
                {user?.role || 'analyst'}
              </span>
            </div>
          </div>
          <button
            onClick={() => logout()}
            title="Sign out"
            className="p-2 text-slate-400 hover:text-red-400 hover:bg-navy-700 rounded-lg transition-colors"
          >
            <LogOut className="w-4 h-4" />
          </button>
        </div>
      </div>
    </aside>
  )
}
