'use client'

import React, { useEffect, useState, Suspense } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'
import Link from 'next/link'
import { CheckCircle2, AlertTriangle, RefreshCw, ArrowRight, ShieldCheck, Mail } from 'lucide-react'
import { handleGoogleOAuthCallback } from '@/services/gmailService'

function GmailOAuthCallbackContent() {
  const router = useRouter()
  const searchParams = useSearchParams()

  const [loading, setLoading] = useState(true)
  const [success, setSuccess] = useState(false)
  const [errorMessage, setErrorMessage] = useState<string | null>(null)
  const [connectedEmail, setConnectedEmail] = useState<string | null>(null)

  useEffect(() => {
    const code = searchParams.get('code')
    const state = searchParams.get('state')
    const errorParam = searchParams.get('error')

    if (errorParam) {
      setLoading(false)
      setErrorMessage(`Google OAuth error: ${errorParam}. Authorization was declined or cancelled.`)
      return
    }

    if (!code || !state) {
      setLoading(false)
      setErrorMessage('Missing required OAuth parameters (code or state). Please start the connection from PhishGuard AI.')
      return
    }

    let isMounted = true

    async function exchangeToken() {
      try {
        const result = await handleGoogleOAuthCallback({
          code: code || undefined,
          state: state || undefined,
        })
        if (isMounted) {
          setConnectedEmail(result.email_address)
          setSuccess(true)
          setLoading(false)
          // Redirect to dashboard after 2.5 seconds
          setTimeout(() => {
            router.push('/dashboard')
          }, 2500)
        }
      } catch (err: any) {
        if (isMounted) {
          const detail = err.response?.data?.detail || err.message || 'Failed to exchange authorization code with Google.'
          setErrorMessage(detail)
          setLoading(false)
        }
      }
    }

    exchangeToken()

    return () => {
      isMounted = false
    }
  }, [searchParams, router])

  return (
    <div className="min-h-[70vh] flex items-center justify-center p-4">
      <div className="bg-navy-850 border border-navy-700/80 rounded-2xl max-w-md w-full p-8 shadow-2xl text-center space-y-6">
        {loading && (
          <div className="space-y-4">
            <div className="w-16 h-16 rounded-2xl bg-accent-blue/10 border border-accent-blue/30 flex items-center justify-center mx-auto text-accent-blue shadow-lg">
              <RefreshCw className="w-8 h-8 animate-spin" />
            </div>
            <div className="space-y-1">
              <h2 className="text-xl font-bold font-mono text-white">Verifying Google Account</h2>
              <p className="text-xs text-slate-400 leading-relaxed">
                Calling Google Identity Services to exchange your authorization code and verify genuine Gmail mailbox access...
              </p>
            </div>
          </div>
        )}

        {success && (
          <div className="space-y-5">
            <div className="w-16 h-16 rounded-2xl bg-emerald-500/15 border border-emerald-500/30 flex items-center justify-center mx-auto text-emerald-400 shadow-lg shadow-emerald-500/10">
              <CheckCircle2 className="w-8 h-8" />
            </div>
            <div className="space-y-2">
              <h2 className="text-xl font-bold font-mono text-white">Gmail Connected & Verified</h2>
              <p className="text-xs text-slate-300">
                Authenticated mailbox successfully verified via Google API:
              </p>
              <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg bg-navy-900 border border-navy-700 text-accent-cyan font-mono text-xs">
                <Mail className="w-3.5 h-3.5" />
                <span>{connectedEmail}</span>
              </div>
            </div>

            <div className="bg-navy-900/60 border border-navy-800 rounded-xl p-3 text-left space-y-2 text-[11px] font-mono text-slate-400">
              <div className="flex items-center justify-between text-slate-300">
                <span>Scope Verified:</span>
                <span className="text-emerald-400 font-semibold">gmail.modify</span>
              </div>
              <div className="flex items-center justify-between text-slate-300">
                <span>Token Storage:</span>
                <span className="text-accent-blue font-semibold">AES-128 Encrypted at Rest</span>
              </div>
              <div className="flex items-center justify-between text-slate-300">
                <span>Redirecting:</span>
                <span className="text-slate-400">Returning to Defense Hub...</span>
              </div>
            </div>

            <div className="pt-2">
              <Link
                href="/dashboard"
                className="inline-flex items-center justify-center gap-2 w-full px-4 py-2.5 bg-gradient-to-r from-red-600 to-red-500 hover:from-red-500 hover:to-red-400 text-white rounded-xl text-xs font-mono font-semibold shadow-lg shadow-red-600/25 transition-all"
              >
                <span>Go to Defense Hub Now</span>
                <ArrowRight className="w-4 h-4" />
              </Link>
            </div>
          </div>
        )}

        {errorMessage && (
          <div className="space-y-5">
            <div className="w-16 h-16 rounded-2xl bg-red-500/15 border border-red-500/30 flex items-center justify-center mx-auto text-red-400 shadow-lg shadow-red-500/10">
              <AlertTriangle className="w-8 h-8" />
            </div>
            <div className="space-y-2">
              <h2 className="text-xl font-bold font-mono text-white">Connection Failed</h2>
              <div className="p-3 bg-red-500/10 border border-red-500/20 rounded-xl text-red-300 text-xs font-mono text-left leading-relaxed break-words">
                {errorMessage}
              </div>
            </div>

            <div className="pt-2 flex flex-col sm:flex-row gap-2">
              <Link
                href="/dashboard"
                className="flex-1 inline-flex items-center justify-center gap-2 px-4 py-2.5 bg-navy-800 hover:bg-navy-700 text-slate-300 border border-navy-700 rounded-xl text-xs font-mono font-semibold transition-colors"
              >
                <span>Return to Dashboard</span>
              </Link>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

export default function GmailOAuthCallbackPage() {
  return (
    <Suspense
      fallback={
        <div className="min-h-[70vh] flex items-center justify-center p-4">
          <div className="bg-navy-850 border border-navy-700/80 rounded-2xl max-w-md w-full p-8 shadow-2xl text-center space-y-4">
            <RefreshCw className="w-8 h-8 text-accent-blue animate-spin mx-auto" />
            <p className="text-xs font-mono text-slate-400">Loading OAuth verification...</p>
          </div>
        </div>
      }
    >
      <GmailOAuthCallbackContent />
    </Suspense>
  )
}
