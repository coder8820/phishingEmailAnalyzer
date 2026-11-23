'use client'

import React, { useState } from 'react'
import { useRouter } from 'next/navigation'
import { RefreshCw, Sparkles, AlertCircle, Info, ExternalLink } from 'lucide-react'
import { toast } from 'sonner'
import { GoogleIcon } from '@/components/ui/GoogleIcon'
import { googleAuthService } from '@/services/googleAuthService'
import { useAuthStore } from '@/store/authStore'
import { cn } from '@/lib/utils'

interface GoogleSignInButtonProps {
  intent?: 'login' | 'register'
  text?: string
  className?: string
  onError?: (error: string) => void
}

export function GoogleSignInButton({
  intent = 'login',
  text,
  className,
  onError,
}: GoogleSignInButtonProps) {
  const router = useRouter()
  const { loginWithGoogleDemo } = useAuthStore()
  const [loading, setLoading] = useState(false)
  const [showDemoModal, setShowDemoModal] = useState(false)
  const [demoEmail, setDemoEmail] = useState('google.analyst@phishguard.local')
  const [demoName, setDemoName] = useState('Google SOC Analyst')

  const defaultText =
    text || (intent === 'register' ? 'Sign up with Google' : 'Sign in with Google')

  const handleGoogleClick = async () => {
    setLoading(true)
    try {
      const config = await googleAuthService.getConfig()

      if (config.is_configured) {
        // Genuine Google OAuth 2.0 Flow
        const redirectUri = `${window.location.origin}/auth/google/callback`
        const { authorization_url } = await googleAuthService.getAuthUrl(intent, redirectUri)
        window.location.href = authorization_url
      } else {
        // Credentials not yet set in .env
        setLoading(false)
        if (config.demo_mode_allowed) {
          setShowDemoModal(true)
        } else {
          const msg =
            'Google OAuth 2.0 is not configured on the backend server. Please configure GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in .env.'
          onError?.(msg)
          toast.error(msg)
        }
      }
    } catch (err: unknown) {
      setLoading(false)
      const axiosError = err as { response?: { data?: { detail?: string } }; message?: string }
      const detail =
        axiosError?.response?.data?.detail ||
        axiosError?.message ||
        'Failed to initialize Google Sign-In.'
      onError?.(detail)
      toast.error(detail)
    }
  }

  const handleInstantDemoLogin = async () => {
    setLoading(true)
    try {
      await loginWithGoogleDemo(demoEmail, demoName)
      toast.success(`Signed in as ${demoName} via Google SSO!`)
      setShowDemoModal(false)
      router.push('/dashboard')
    } catch (err: unknown) {
      setLoading(false)
      const axiosError = err as { response?: { data?: { detail?: string } }; message?: string }
      const detail =
        axiosError?.response?.data?.detail ||
        axiosError?.message ||
        'Failed to complete demo Google sign-in.'
      onError?.(detail)
      toast.error(detail)
    }
  }

  return (
    <>
      <button
        type="button"
        onClick={handleGoogleClick}
        disabled={loading}
        className={cn(
          'w-full flex items-center justify-center gap-3 py-3 px-4 rounded-xl',
          'bg-navy-900 hover:bg-navy-700/80 border border-navy-600 hover:border-slate-400',
          'text-slate-200 hover:text-white font-medium text-sm transition-all duration-200',
          'shadow-md hover:shadow-lg focus:outline-none focus:ring-2 focus:ring-accent-blue/40',
          'disabled:opacity-60 disabled:cursor-not-allowed group',
          className
        )}
      >
        {loading ? (
          <RefreshCw className="w-4 h-4 animate-spin text-accent-blue" />
        ) : (
          <GoogleIcon className="w-5 h-5 flex-shrink-0 group-hover:scale-105 transition-transform" />
        )}
        <span>{loading ? 'Connecting to Google...' : defaultText}</span>
      </button>

      {/* Development / Demo Mode Modal when Google Cloud API keys are unconfigured */}
      {showDemoModal && (
        <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-navy-850 border border-navy-600 rounded-2xl max-w-md w-full p-6 shadow-2xl space-y-5 animate-fade-in text-left">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-accent-blue/10 border border-accent-blue/30 flex items-center justify-center">
                <GoogleIcon className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-base font-semibold text-white">Google OAuth Environment</h3>
                <p className="text-xs text-slate-400">Development SSO Simulator</p>
              </div>
            </div>

            <div className="bg-amber-500/10 border border-amber-500/30 rounded-xl p-3.5 space-y-1.5 text-xs text-amber-300">
              <div className="flex items-center gap-2 font-semibold">
                <Info className="w-4 h-4 flex-shrink-0" />
                <span>Google Cloud Client ID Not Set</span>
              </div>
              <p className="text-amber-300/80 leading-relaxed">
                <code className="bg-navy-900 px-1.5 py-0.5 rounded text-amber-200">GOOGLE_CLIENT_ID</code> is currently empty in <code className="bg-navy-900 px-1.5 py-0.5 rounded text-amber-200">.env</code>.
                You can test genuine Google SSO by adding your credentials, or test the flow right now with this Instant Google SSO test profile:
              </p>
            </div>

            <div className="space-y-3">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Google Account Name
                </label>
                <input
                  type="text"
                  value={demoName}
                  onChange={(e) => setDemoName(e.target.value)}
                  className="w-full bg-navy-900 border border-navy-600 rounded-lg px-3 py-2 text-sm text-slate-100 focus:outline-none focus:border-accent-blue"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Google Email Address
                </label>
                <input
                  type="email"
                  value={demoEmail}
                  onChange={(e) => setDemoEmail(e.target.value)}
                  className="w-full bg-navy-900 border border-navy-600 rounded-lg px-3 py-2 text-sm text-slate-100 focus:outline-none focus:border-accent-blue"
                />
              </div>
            </div>

            <div className="flex items-center gap-2 pt-2">
              <button
                type="button"
                onClick={() => setShowDemoModal(false)}
                className="flex-1 py-2.5 px-3 rounded-lg bg-navy-900 hover:bg-navy-700 text-slate-300 text-xs font-medium border border-navy-600 transition-colors"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleInstantDemoLogin}
                disabled={loading}
                className="flex-1 flex items-center justify-center gap-2 py-2.5 px-3 rounded-lg bg-accent-blue hover:bg-blue-600 text-white text-xs font-medium transition-colors shadow-lg shadow-accent-blue/20"
              >
                <Sparkles className="w-3.5 h-3.5" />
                <span>{loading ? 'Signing in...' : 'Sign In with Google'}</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  )
}
