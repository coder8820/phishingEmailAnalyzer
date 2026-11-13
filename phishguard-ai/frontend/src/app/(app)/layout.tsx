'use client'

import { useEffect, useState } from 'react'
import { useRouter, usePathname } from 'next/navigation'
import { useAuthStore } from '@/store/authStore'
import { Sidebar } from '@/components/layout/Sidebar'
import { TopNav } from '@/components/layout/TopNav'
import { FloatingAssistantWidget } from '@/components/chat/FloatingAssistantWidget'
import { Shield } from 'lucide-react'

export default function AppLayout({ children }: { children: React.ReactNode }) {
  const router = useRouter()
  const pathname = usePathname()
  const { isAuthenticated, loadUser, accessToken } = useAuthStore()
  const [ready, setReady] = useState(false)

  useEffect(() => {
    const token =
      accessToken ||
      (typeof window !== 'undefined' ? localStorage.getItem('access_token') : null)

    if (token) {
      loadUser().finally(() => {
        setReady(true)
      })
    } else {
      setReady(true)
      router.push('/login')
    }
  }, [accessToken, loadUser, router])

  const storedToken = typeof window !== 'undefined' ? localStorage.getItem('access_token') : null
  const hasTokenOrAuth = isAuthenticated || !!accessToken || !!storedToken

  if (!ready || !hasTokenOrAuth) {
    return (
      <div className="min-h-screen bg-navy-900 flex items-center justify-center">
        <div className="text-center">
          <Shield className="w-12 h-12 text-accent-blue mx-auto mb-4 animate-pulse" />
          <p className="text-slate-400">Authenticating...</p>
        </div>
      </div>
    )
  }

  return (
    <div className="flex h-screen bg-navy-900 overflow-hidden">
      <Sidebar currentPath={pathname} />
      <div className="flex flex-col flex-1 overflow-hidden">
        <TopNav />
        <main className="flex-1 overflow-y-auto p-6">{children}</main>
      </div>
      <FloatingAssistantWidget />
    </div>

  )
}
