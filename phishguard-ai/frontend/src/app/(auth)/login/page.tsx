'use client'

import { useState, useEffect } from 'react'
import { useRouter } from 'next/navigation'
import Link from 'next/link'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { Eye, EyeOff, Shield, AlertCircle, Lock } from 'lucide-react'
import { toast } from 'sonner'
import { useAuthStore } from '@/store/authStore'
import { GoogleSignInButton } from '@/components/auth/GoogleSignInButton'
import { cn } from '@/lib/utils'

const loginSchema = z.object({
  email: z.string().email('Invalid email address'),
  password: z.string().min(1, 'Password is required'),
})

type LoginFormData = z.infer<typeof loginSchema>

export default function LoginPage() {
  const router = useRouter()
  const { login, isLoading, isAuthenticated, accessToken } = useAuthStore()
  const [showPassword, setShowPassword] = useState(false)
  const [errorMessage, setErrorMessage] = useState<string | null>(null)

  const {
    register,
    handleSubmit,
    setValue,
    formState: { errors },
  } = useForm<LoginFormData>({
    resolver: zodResolver(loginSchema),
  })

  useEffect(() => {
    const token =
      accessToken || (typeof window !== 'undefined' ? localStorage.getItem('access_token') : null)
    if (isAuthenticated && token) {
      router.push('/dashboard')
    }
  }, [isAuthenticated, accessToken, router])

  const onSubmit = async (data: LoginFormData) => {
    setErrorMessage(null)
    try {
      await login(data.email, data.password)
      toast.success('Signed in successfully')
      router.push('/dashboard')
    } catch (err: unknown) {
      const axiosError = err as { response?: { status?: number; data?: { error?: { message?: string } } } }
      const status = axiosError?.response?.status
      if (status === 401) {
        setErrorMessage('Invalid email or password. Please try again.')
      } else if (status === 423) {
        setErrorMessage('Your account has been locked. Please contact your administrator.')
      } else {
        setErrorMessage('An error occurred. Please try again later.')
      }
    }
  }

  return (
    <div className="min-h-screen bg-navy-900 flex items-center justify-center p-4">
      {/* Background gradient effect */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute -top-40 -left-40 w-80 h-80 bg-accent-blue/5 rounded-full blur-3xl" />
        <div className="absolute -bottom-40 -right-40 w-80 h-80 bg-accent-cyan/5 rounded-full blur-3xl" />
      </div>

      <div className="relative w-full max-w-md">
        {/* Logo */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 bg-accent-blue/10 border border-accent-blue/30 rounded-2xl mb-4">
            <Shield className="w-8 h-8 text-accent-blue" />
          </div>
          <h1 className="text-2xl font-bold text-slate-100">PhishGuard AI</h1>
          <p className="text-slate-400 text-sm mt-1">Enterprise Phishing Detection Platform</p>
        </div>

        {/* Card */}
        <div className="bg-navy-800 border border-navy-600 rounded-2xl p-8 shadow-2xl shadow-black/50">
          <h2 className="text-xl font-semibold text-slate-100 mb-4">Sign in to your account</h2>

          {/* Quick Demo Fill Buttons */}
          <div className="mb-5 p-3 rounded-xl bg-navy-900/80 border border-navy-700">
            <p className="text-xs text-slate-400 mb-2 font-medium">Quick Demo Accounts:</p>
            <div className="grid grid-cols-2 gap-2">
              <button
                type="button"
                onClick={() => {
                  setValue('email', 'admin@phishguard.local', { shouldValidate: true })
                  setValue('password', 'AdminSecure2026!', { shouldValidate: true })
                }}
                className="text-xs py-1.5 px-2.5 rounded-lg bg-navy-800 hover:bg-navy-700 text-accent-blue border border-accent-blue/30 text-left transition-colors font-medium flex items-center justify-between"
              >
                <span>🛡️ Super Admin</span>
              </button>
              <button
                type="button"
                onClick={() => {
                  setValue('email', 'analyst@phishguard.local', { shouldValidate: true })
                  setValue('password', 'Analyst123!', { shouldValidate: true })
                }}
                className="text-xs py-1.5 px-2.5 rounded-lg bg-navy-800 hover:bg-navy-700 text-accent-cyan border border-accent-cyan/30 text-left transition-colors font-medium flex items-center justify-between"
              >
                <span>🔍 SOC Analyst</span>
              </button>
            </div>
          </div>

          {/* Error Banner */}
          {errorMessage && (
            <div className="flex items-start gap-3 bg-red-500/10 border border-red-500/30 rounded-lg p-4 mb-6">
              <AlertCircle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
              <p className="text-red-400 text-sm">{errorMessage}</p>
            </div>
          )}

          {/* Google Sign In Button */}
          <div className="mb-5">
            <GoogleSignInButton
              intent="login"
              text="Sign in with Google"
              onError={(err) => setErrorMessage(err)}
            />
          </div>

          {/* Divider */}
          <div className="relative flex py-1.5 items-center mb-5">
            <div className="flex-grow border-t border-navy-600"></div>
            <span className="flex-shrink mx-3 text-xs uppercase tracking-wider text-slate-500 font-medium">
              or continue with email
            </span>
            <div className="flex-grow border-t border-navy-600"></div>
          </div>

          <form onSubmit={handleSubmit(onSubmit)} className="space-y-5">
            {/* Email */}
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">
                Email address
              </label>
              <input
                {...register('email')}
                type="email"
                autoComplete="email"
                placeholder="analyst@organization.com"
                className={cn(
                  'w-full bg-navy-900 border rounded-lg px-4 py-3 text-slate-100 placeholder-slate-500',
                  'focus:outline-none focus:ring-2 focus:ring-accent-blue/50 focus:border-accent-blue/50',
                  'transition-colors duration-200',
                  errors.email ? 'border-red-500/50' : 'border-navy-600'
                )}
              />
              {errors.email && (
                <p className="text-red-400 text-xs mt-1">{errors.email.message}</p>
              )}
            </div>

            {/* Password */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <label className="block text-sm font-medium text-slate-300">Password</label>
                <button
                  type="button"
                  className="text-xs text-accent-blue hover:text-blue-400 transition-colors"
                >
                  Forgot password?
                </button>
              </div>
              <div className="relative">
                <input
                  {...register('password')}
                  type={showPassword ? 'text' : 'password'}
                  autoComplete="current-password"
                  placeholder="Enter your password"
                  className={cn(
                    'w-full bg-navy-900 border rounded-lg px-4 py-3 pr-12 text-slate-100 placeholder-slate-500',
                    'focus:outline-none focus:ring-2 focus:ring-accent-blue/50 focus:border-accent-blue/50',
                    'transition-colors duration-200',
                    errors.password ? 'border-red-500/50' : 'border-navy-600'
                  )}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 transition-colors"
                >
                  {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                </button>
              </div>
              {errors.password && (
                <p className="text-red-400 text-xs mt-1">{errors.password.message}</p>
              )}
            </div>

            {/* Submit Button */}
            <button
              type="submit"
              disabled={isLoading}
              className={cn(
                'w-full flex items-center justify-center gap-2 bg-accent-blue hover:bg-blue-600',
                'text-white font-medium rounded-lg px-4 py-3 transition-all duration-200',
                'focus:outline-none focus:ring-2 focus:ring-accent-blue/50 focus:ring-offset-2 focus:ring-offset-navy-800',
                'disabled:opacity-60 disabled:cursor-not-allowed'
              )}
            >
              {isLoading ? (
                <>
                  <span className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  Signing in...
                </>
              ) : (
                <>
                  <Lock className="w-4 h-4" />
                  Sign in
                </>
              )}
            </button>
          </form>

          <div className="mt-6 text-center">
            <p className="text-sm text-slate-400">
              Don&apos;t have an analyst account?{' '}
              <Link href="/register" className="text-accent-blue hover:text-blue-400 font-medium transition-colors">
                Register here
              </Link>
            </p>
          </div>

          <div className="mt-6 pt-6 border-t border-navy-600">
            <div className="flex items-center justify-between text-xs text-slate-500">
              <span>Protected by enterprise-grade SOC security</span>
              <Link href="/" className="text-slate-400 hover:text-slate-200 transition-colors">
                ← Back to Home
              </Link>
            </div>
          </div>
        </div>

        <p className="text-center text-xs text-slate-600 mt-6">
          PhishGuard AI v1.0.0 · © 2024 All rights reserved
        </p>
      </div>
    </div>
  )
}
