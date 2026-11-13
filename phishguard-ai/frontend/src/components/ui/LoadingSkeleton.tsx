import { cn } from '@/lib/utils'

export function LoadingSkeleton({ className, variant }: { className?: string; variant?: string }) {
  return (
    <div
      className={cn(
        'animate-pulse bg-navy-700/60 rounded-lg',
        className
      )}
    />
  )
}
