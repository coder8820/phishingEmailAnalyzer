import React from 'react'
import { Inbox } from 'lucide-react'
import { cn } from '@/lib/utils'

interface EmptyStateProps {
  icon?: React.ReactNode
  title: string
  description?: string
  action?: React.ReactNode
  className?: string
}

export function EmptyState({
  icon = <Inbox className="w-10 h-10 text-slate-500" />,
  title,
  description,
  action,
  className,
}: EmptyStateProps) {
  return (
    <div
      className={cn(
        'flex flex-col items-center justify-center py-12 px-4 text-center rounded-xl border border-dashed border-navy-600 bg-navy-850/50',
        className
      )}
    >
      <div className="p-3 bg-navy-800 rounded-2xl mb-3 shadow-inner">{icon}</div>
      <h4 className="text-base font-medium text-slate-200">{title}</h4>
      {description && <p className="text-sm text-slate-400 max-w-sm mt-1">{description}</p>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  )
}
