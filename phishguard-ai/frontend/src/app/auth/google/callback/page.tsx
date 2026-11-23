'use client'

import React, { useEffect, useState, Suspense } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'
import Link from 'next/link'
import { CheckCircle2, AlertCircle, RefreshCw, ArrowRight, Shield } from 'lucide-react'
import { toast } from 'sonner'
import { useAuthStore } from '@/store/authStore'
import { GoogleIcon } from '@/components/ui/GoogleIcon'

function GoogleAuthCallbackContent() {
  const router = useRouter()
  const searchParams = useSearchParams()
  const { loginWithGoogleCallback } = useAuthStore()

  const [loading, setLoading] = useState(true)
  const [success, setSuccess] = useState(false)
  const [errorMessage, setErrorMessage] = useState<string | null>(null)
  const [userProfile, setUserProfile] = useState<{ displayName: string; email: string; isNew: boolean } | null>(null)

  useEffect(() => {
    const code = searchParams.get('code')
    const state = searchParams.get('state')
    const errorParam = searchParams.get('error')

    if (errorParam) {
      setLoading(false)
      setErrorMessage(`Google authentication was cancelled or denied (${errorParam}).`)
      return
    }

    if (!code || !state) {
      setLoading(false)
      setErrorMessage('Missing required authorization parameters (code or state). Please restart Google Sign-In.')
      return
    }

    let isMounted = true

    async function handleExchange() {
      try {
        const redirectUri = typeof window !== 'undefined' ? `${window.location.origin}/auth/google/callback` : undefined
        const result = await loginWithGoogleCallback(code as string, state as string, redirectUri)

        if (isMounted) {
          setUserProfile({
            displayName: result.user.display_name || result.user.username,
            email: result.user.email,
            isNew: result.is_new_user,
          })
          setSuccess(true)
          setLoading(false)
          toast.success(result.is_new_user ? 'Account created via Google SSO!' : 'Signed in via Google!')

          setTimeout(() => {
            router.push('/dashboard')
          }, 1800)
        }
      } catch (err: unknown) {
        if (isMounted) {
          const axiosError = err as { response?: { data?: { detail?: string; error?: { message?: string } } }; message?: string }
          const detail =
            axiosError?.response?.data?.detail ||
            axiosError?.response?.data?.error?.message ||
            axiosError?.message ||
            'Failed to complete Google Single Sign-On.'
          setErrorMessage(detail)
          setLoading(false)
        }
      }
    }

    handleExchange()

    return () => {
      isMounted = false
    }
  }, [searchParams, router, loginWithGoogleCallback])

  return (
    <div className="min-h-screen bg-navy-900 flex items-center justify-center p-4">
      {/* Background ambient lighting */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute -top-40 -left-40 w-96 h-96 bg-accent-blue/10 rounded-full blur-3xl" />
        <div className="absolute -bottom-40 -right-40 w-96 h-96 bg-accent-cyan/10 rounded-full blur-3xl" />
      </div>

      <div className="relative bg-navy-800 border border-navy-600 rounded-2xl max-w-md w-full p-8 shadow-2xl shadow-black/60 text-center space-y-6">
        {/* Brand logo */}
        <div className="flex justify-center items-center gap-2 mb-2">
          <div className="w-10 h-10 rounded-xl bg-accent-blue/10 border border-accent-blue/30 flex items-center justify-center text-accent-blue">
            <Shield className="w-5 h-5" />
          </div>
          <span className="font-bold text-slate-100 text-lg">PhishGuard AI</span>
        </div>

        {loading && (
          <div className="space-y-5 py-4">
            <div className="relative w-16 h-16 mx-auto flex items-center justify-center">
              <div className="absolute inset-0 rounded-full border-2 border-accent-blue/20 animate-ping" />
              <div className="w-16 h-16 rounded-2xl bg-navy-900 border border-navy-700 flex items-center justify-center text-accent-blue shadow-lg">
                <RefreshCw className="w-8 h-8 animate-spin text-accent-blue" />
              </div>
            </div>
            <div className="space-y-2">
              <h2 className="text-xl font-bold text-white">Verifying Google SSO</h2>
              <p className="text-xs text-slate-400 max-w-sm mx-auto leading-relaxed">
                Exchanging PKCE authorization code and establishing your authenticated SOC security session...
              </p>
            </div>
          </div>
        )}

        {success && userProfile && (
          <div className="space-y-5 py-2">
            <div className="w-16 h-16 rounded-2xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center mx-auto text-emerald-400 shadow-lg shadow-emerald-500/10">
              <CheckCircle2 className="w-8 h-8" />
            </div>
            <div className="space-y-2">
              <h2 className="text-xl font-bold text-white">
                {userProfile.isNew ? 'Account Created Successfully' : 'Authentication Successful'}
              </h2>
              <p className="text-xs text-slate-300">
                Welcome, <span className="font-semibold text-white">{userProfile.displayName}</span>
              </p>
              <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg bg-navy-900 border border-navy-700 text-slate-300 text-xs font-mono">
                <GoogleIcon className="w-3.5 h-3.5" />
                <span>{userProfile.email}</span>
              </div>
            </div>

            <p className="text-xs text-slate-500 flex items-center justify-center gap-1.5 animate-pulse">
              Redirecting to SOC Dashboard...
            </p>

            <Link
              href="/dashboard"
              className="inline-flex items-center justify-center gap-2 w-full py-2.5 px-4 rounded-lg bg-accent-blue hover:bg-blue-600 text-white font-medium text-sm transition-colors shadow-lg shadow-accent-blue/20"
            >
              <span>Go to Dashboard Now</span>
              <ArrowRight className="w-4 h-4" />
            </Link>
          </div>
        )}

        {errorMessage && (
          <div className="space-y-5 py-2">
            <div className="w-16 h-16 rounded-2xl bg-red-500/10 border border-red-500/30 flex items-center justify-center mx-auto text-red-400 shadow-lg shadow-red-500/10">
              <AlertCircle className="w-8 h-8" />
            </div>
            <div className="space-y-2">
              <h2 className="text-xl font-bold text-white">Google Sign-In Failed</h2>
              <p className="text-xs text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg p-3 text-left">
                {errorMessage}
              </p>
            </div>

            <div className="flex flex-col gap-2 pt-2">
              <Link
                href="/login"
                className="inline-flex items-center justify-center gap-2 w-full py-2.5 px-4 rounded-lg bg-accent-blue hover:bg-blue-600 text-white font-medium text-sm transition-colors"
              >
                Return to Login
              </Link>
              <Link
                href="/register"
                className="inline-flex items-center justify-center gap-2 w-full py-2.5 px-4 rounded-lg bg-navy-900 hover:bg-navy-700 border border-navy-600 text-slate-300 text-sm transition-colors"
              >
                Create Account with Email
              </Link>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

export default function GoogleAuthCallbackPage() {
  return (
    <Suspense
      fallback={
        <div className="min-h-screen bg-navy-900 flex items-center justify-center p-4">
          <div className="text-slate-400 text-sm flex items-center gap-2">
            <RefreshCw className="w-4 h-4 animate-spin text-accent-blue" />
            <span>Loading authentication...</span>
          </div>
        </div>
      }
    >
      <GoogleAuthCallbackContent />
    </Suspense>
  )
}
