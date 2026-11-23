'use client'

import { useState } from 'react'
import { useRouter } from 'next/navigation'
import Link from 'next/link'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { Eye, EyeOff, Shield, AlertCircle, UserPlus, CheckCircle2 } from 'lucide-react'
import { toast } from 'sonner'
import { useAuthStore } from '@/store/authStore'
import { GoogleSignInButton } from '@/components/auth/GoogleSignInButton'
import { cn } from '@/lib/utils'

const registerSchema = z
  .object({
    display_name: z.string().min(2, 'Name must be at least 2 characters'),
    username: z
      .string()
      .min(3, 'Username must be at least 3 characters')
      .regex(/^[a-zA-Z0-9_-]+$/, 'Username can only contain letters, numbers, underscores and hyphens'),
    email: z.string().email('Please enter a valid email address'),
    organization_name: z.string().optional(),
    password: z
      .string()
      .min(8, 'Password must be at least 8 characters')
      .regex(/[A-Z]/, 'Must contain at least one uppercase letter')
      .regex(/[0-9]/, 'Must contain at least one number'),
    confirmPassword: z.string().min(1, 'Please confirm your password'),
  })
  .refine((data) => data.password === data.confirmPassword, {
    message: "Passwords don't match",
    path: ['confirmPassword'],
  })

type RegisterFormData = z.infer<typeof registerSchema>

export default function RegisterPage() {
  const router = useRouter()
  const { register: registerUser, isLoading } = useAuthStore()
  const [showPassword, setShowPassword] = useState(false)
  const [errorMessage, setErrorMessage] = useState<string | null>(null)

  const {
    register,
    handleSubmit,
    watch,
    formState: { errors },
  } = useForm<RegisterFormData>({
    resolver: zodResolver(registerSchema),
  })

  const passwordValue = watch('password', '')

  const onSubmit = async (data: RegisterFormData) => {
    setErrorMessage(null)
    try {
      await registerUser({
        email: data.email,
        password: data.password,
        username: data.username,
        display_name: data.display_name,
        organization_name: data.organization_name || undefined,
      })
      toast.success('Analyst account created successfully! Welcome to PhishGuard AI.')
      router.push('/dashboard')
    } catch (err: unknown) {
      const axiosError = err as { response?: { status?: number; data?: { detail?: string; error?: { message?: string } } } }
      const detail = axiosError?.response?.data?.detail || axiosError?.response?.data?.error?.message
      if (detail) {
        setErrorMessage(detail)
      } else {
        setErrorMessage('Failed to create account. Please verify your details or try again.')
      }
    }
  }

  return (
    <div className="min-h-screen bg-navy-900 flex items-center justify-center p-4 py-12">
      {/* Background glow effect */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute -top-40 -left-40 w-96 h-96 bg-accent-blue/10 rounded-full blur-3xl" />
        <div className="absolute -bottom-40 -right-40 w-96 h-96 bg-accent-cyan/10 rounded-full blur-3xl" />
      </div>

      <div className="relative w-full max-w-lg">
        {/* Brand header */}
        <div className="text-center mb-8">
          <Link href="/" className="inline-flex items-center gap-3 group">
            <div className="inline-flex items-center justify-center w-14 h-14 bg-accent-blue/10 border border-accent-blue/30 rounded-2xl group-hover:border-accent-blue/60 transition-all">
              <Shield className="w-7 h-7 text-accent-blue" />
            </div>
          </Link>
          <h1 className="text-2xl font-bold text-slate-100 mt-3">PhishGuard AI</h1>
          <p className="text-slate-400 text-sm mt-1">Join the Enterprise Threat Intelligence Platform</p>
        </div>

        {/* Card */}
        <div className="bg-navy-800 border border-navy-600 rounded-2xl p-8 shadow-2xl shadow-black/50">
          <div className="flex items-center justify-between mb-6">
            <div>
              <h2 className="text-xl font-semibold text-slate-100">Create Analyst Account</h2>
              <p className="text-xs text-slate-400 mt-1">Instant access to the phishing email analysis sandbox</p>
            </div>
            <span className="text-xs px-2.5 py-1 rounded-full bg-accent-blue/10 text-accent-blue border border-accent-blue/20">
              Free Analyst Tier
            </span>
          </div>

          {/* Error Banner */}
          {errorMessage && (
            <div className="flex items-start gap-3 bg-red-500/10 border border-red-500/30 rounded-lg p-4 mb-6">
              <AlertCircle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
              <p className="text-red-400 text-sm">{errorMessage}</p>
            </div>
          )}

          {/* Google Sign Up Button */}
          <div className="mb-5">
            <GoogleSignInButton
              intent="register"
              text="Sign up with Google"
              onError={(err) => setErrorMessage(err)}
            />
          </div>

          {/* Divider */}
          <div className="relative flex py-1.5 items-center mb-5">
            <div className="flex-grow border-t border-navy-600"></div>
            <span className="flex-shrink mx-3 text-xs uppercase tracking-wider text-slate-500 font-medium">
              or register with email
            </span>
            <div className="flex-grow border-t border-navy-600"></div>
          </div>

          <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Full Name */}
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1.5">
                  Full Name
                </label>
                <input
                  {...register('display_name')}
                  type="text"
                  placeholder="Alex Rivera"
                  className={cn(
                    'w-full bg-navy-900 border rounded-lg px-3.5 py-2.5 text-sm text-slate-100 placeholder-slate-500',
                    'focus:outline-none focus:ring-2 focus:ring-accent-blue/50 focus:border-accent-blue/50',
                    'transition-colors duration-200',
                    errors.display_name ? 'border-red-500/50' : 'border-navy-600'
                  )}
                />
                {errors.display_name && (
                  <p className="text-red-400 text-xs mt-1">{errors.display_name.message}</p>
                )}
              </div>

              {/* Username */}
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1.5">
                  SOC Username
                </label>
                <input
                  {...register('username')}
                  type="text"
                  placeholder="arivera_soc"
                  className={cn(
                    'w-full bg-navy-900 border rounded-lg px-3.5 py-2.5 text-sm text-slate-100 placeholder-slate-500',
                    'focus:outline-none focus:ring-2 focus:ring-accent-blue/50 focus:border-accent-blue/50',
                    'transition-colors duration-200',
                    errors.username ? 'border-red-500/50' : 'border-navy-600'
                  )}
                />
                {errors.username && (
                  <p className="text-red-400 text-xs mt-1">{errors.username.message}</p>
                )}
              </div>
            </div>

            {/* Email */}
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1.5">
                Work Email Address
              </label>
              <input
                {...register('email')}
                type="email"
                autoComplete="email"
                placeholder="analyst@enterprise.com"
                className={cn(
                  'w-full bg-navy-900 border rounded-lg px-3.5 py-2.5 text-sm text-slate-100 placeholder-slate-500',
                  'focus:outline-none focus:ring-2 focus:ring-accent-blue/50 focus:border-accent-blue/50',
                  'transition-colors duration-200',
                  errors.email ? 'border-red-500/50' : 'border-navy-600'
                )}
              />
              {errors.email && (
                <p className="text-red-400 text-xs mt-1">{errors.email.message}</p>
              )}
            </div>

            {/* Organization (Optional) */}
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1.5">
                Organization / Team <span className="text-slate-500">(Optional)</span>
              </label>
              <input
                {...register('organization_name')}
                type="text"
                placeholder="Global Security Operations"
                className={cn(
                  'w-full bg-navy-900 border rounded-lg px-3.5 py-2.5 text-sm text-slate-100 placeholder-slate-500',
                  'focus:outline-none focus:ring-2 focus:ring-accent-blue/50 focus:border-accent-blue/50',
                  'border-navy-600'
                )}
              />
            </div>

            {/* Password */}
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1.5">
                Password
              </label>
              <div className="relative">
                <input
                  {...register('password')}
                  type={showPassword ? 'text' : 'password'}
                  autoComplete="new-password"
                  placeholder="Min 8 chars, 1 uppercase, 1 number"
                  className={cn(
                    'w-full bg-navy-900 border rounded-lg px-3.5 py-2.5 pr-11 text-sm text-slate-100 placeholder-slate-500',
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
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
              {errors.password && (
                <p className="text-red-400 text-xs mt-1">{errors.password.message}</p>
              )}
            </div>

            {/* Confirm Password */}
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1.5">
                Confirm Password
              </label>
              <input
                {...register('confirmPassword')}
                type={showPassword ? 'text' : 'password'}
                autoComplete="new-password"
                placeholder="Re-enter password"
                className={cn(
                  'w-full bg-navy-900 border rounded-lg px-3.5 py-2.5 text-sm text-slate-100 placeholder-slate-500',
                  'focus:outline-none focus:ring-2 focus:ring-accent-blue/50 focus:border-accent-blue/50',
                  'transition-colors duration-200',
                  errors.confirmPassword ? 'border-red-500/50' : 'border-navy-600'
                )}
              />
              {errors.confirmPassword && (
                <p className="text-red-400 text-xs mt-1">{errors.confirmPassword.message}</p>
              )}
            </div>

            {/* Password security checks preview */}
            <div className="grid grid-cols-2 gap-2 text-xs py-1">
              <span className={cn('flex items-center gap-1.5', passwordValue.length >= 8 ? 'text-emerald-400' : 'text-slate-500')}>
                <CheckCircle2 className="w-3.5 h-3.5" /> 8+ Characters
              </span>
              <span className={cn('flex items-center gap-1.5', /[A-Z]/.test(passwordValue) ? 'text-emerald-400' : 'text-slate-500')}>
                <CheckCircle2 className="w-3.5 h-3.5" /> 1 Uppercase Letter
              </span>
            </div>

            {/* Submit Button */}
            <button
              type="submit"
              disabled={isLoading}
              className={cn(
                'w-full flex items-center justify-center gap-2 bg-accent-blue hover:bg-blue-600',
                'text-white font-medium rounded-lg px-4 py-3 transition-all duration-200 mt-2',
                'focus:outline-none focus:ring-2 focus:ring-accent-blue/50 focus:ring-offset-2 focus:ring-offset-navy-800',
                'disabled:opacity-60 disabled:cursor-not-allowed shadow-lg shadow-accent-blue/20'
              )}
            >
              {isLoading ? (
                <>
                  <span className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  Creating Account...
                </>
              ) : (
                <>
                  <UserPlus className="w-4 h-4" />
                  Create Analyst Account
                </>
              )}
            </button>
          </form>

          {/* Sign in redirect */}
          <div className="mt-6 text-center">
            <p className="text-sm text-slate-400">
              Already have an account?{' '}
              <Link href="/login" className="text-accent-blue hover:text-blue-400 font-medium transition-colors">
                Sign in to SOC Console
              </Link>
            </p>
          </div>

          <div className="mt-6 pt-5 border-t border-navy-600">
            <div className="flex items-center justify-between text-xs text-slate-500">
              <span>Zero-knowledge credential hashing</span>
              <Link href="/" className="text-slate-400 hover:text-slate-200 transition-colors">
                ← Back to Home
              </Link>
            </div>
          </div>
        </div>

        <p className="text-center text-xs text-slate-600 mt-6">
          PhishGuard AI v1.0.0 · Enterprise Phishing Defense Architecture
        </p>
      </div>
    </div>
  )
}
