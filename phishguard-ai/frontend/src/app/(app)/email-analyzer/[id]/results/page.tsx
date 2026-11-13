'use client'

import { useEffect } from 'react'
import { useRouter, useParams } from 'next/navigation'

export default function AnalysisResultRedirect() {
  const router = useRouter()
  const params = useParams()
  const id = params?.id

  useEffect(() => {
    if (id) {
      router.replace(`/email-analyzer?id=${id}`)
    } else {
      router.replace('/email-analyzer')
    }
  }, [id, router])

  return (
    <div className="flex items-center justify-center min-h-[60vh] text-slate-400">
      <div className="text-center space-y-2">
        <div className="w-8 h-8 border-2 border-accent-blue border-t-transparent rounded-full animate-spin mx-auto" />
        <p className="text-xs font-mono">Redirecting to Threat Analysis Workspace...</p>
      </div>
    </div>
  )
}
