'use client'

import React, { useState, useEffect } from 'react'
import { useRouter } from 'next/navigation'
import Link from 'next/link'
import { motion, AnimatePresence } from 'framer-motion'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import {
  Shield,
  Lock,
  Mail,
  User as UserIcon,
  Eye,
  EyeOff,
  AlertCircle,
  CheckCircle2,
  Sparkles,
  ArrowRight,
  UserPlus,
  KeyRound,
  ShieldCheck,
  ChevronDown,
  Building2,
} from 'lucide-react'
import { toast } from 'sonner'
import { useAuthStore } from '@/store/authStore'
import { GoogleSignInButton } from '@/components/auth/GoogleSignInButton'
import { cn } from '@/lib/utils'

// --- Validation Schemas ---
const loginSchema = z.object({
  email: z.string().email('Invalid email address'),
  password: z.string().min(1, 'Password is required'),
})
type LoginFormData = z.infer<typeof loginSchema>

const registerSchema = z
  .object({
    display_name: z.string().min(2, 'Name must be at least 2 characters'),
    username: z
      .string()
      .min(3, 'Username must be at least 3 characters')
      .regex(/^[a-zA-Z0-9_-]+$/, 'Letters, numbers, _, - only'),
    email: z.string().email('Valid email required'),
    organization_name: z.string().optional(),
    password: z
      .string()
      .min(8, 'Min 8 characters')
      .regex(/[A-Z]/, '1 uppercase letter required')
      .regex(/[0-9]/, '1 number required'),
    confirmPassword: z.string().min(1, 'Please confirm password'),
  })
  .refine((data) => data.password === data.confirmPassword, {
    message: "Passwords don't match",
    path: ['confirmPassword'],
  })
type RegisterFormData = z.infer<typeof registerSchema>

interface AuthCard3DProps {
  initialMode?: 'login' | 'register'
}

export function AuthCard3D({ initialMode = 'login' }: AuthCard3DProps) {
  const router = useRouter()
  const { login, register: registerUser, isLoading, isAuthenticated, accessToken } = useAuthStore()

  const [mode, setMode] = useState<'login' | 'register'>(initialMode)
  const [showLoginPassword, setShowLoginPassword] = useState(false)
  const [showRegPassword, setShowRegPassword] = useState(false)
  const [showConfirmPassword, setShowConfirmPassword] = useState(false)
  const [loginError, setLoginError] = useState<string | null>(null)
  const [registerError, setRegisterError] = useState<string | null>(null)
  const [rememberMe, setRememberMe] = useState(false)
  const [showOrgField, setShowOrgField] = useState(false)

  // Redirect if already authenticated
  useEffect(() => {
    const token =
      accessToken || (typeof window !== 'undefined' ? localStorage.getItem('access_token') : null)
    if (isAuthenticated && token) {
      router.push('/dashboard')
    }
  }, [isAuthenticated, accessToken, router])

  // Login Form
  const {
    register: loginReg,
    handleSubmit: handleLoginSubmit,
    setValue: setLoginValue,
    formState: { errors: loginErrors },
  } = useForm<LoginFormData>({
    resolver: zodResolver(loginSchema),
  })

  // Register Form
  const {
    register: regFormReg,
    handleSubmit: handleRegisterSubmit,
    watch: watchRegister,
    formState: { errors: regErrors },
  } = useForm<RegisterFormData>({
    resolver: zodResolver(registerSchema),
  })

  const regPasswordValue = watchRegister('password', '')

  // Switch Mode with URL sync
  const switchMode = (newMode: 'login' | 'register') => {
    setMode(newMode)
    setLoginError(null)
    setRegisterError(null)
    if (typeof window !== 'undefined') {
      window.history.replaceState(null, '', `/${newMode}`)
    }
  }

  // Submit Login
  const onLoginSubmit = async (data: LoginFormData) => {
    setLoginError(null)
    try {
      await login(data.email, data.password)
      toast.success('Signed in successfully. Initializing SOC workspace...')
      router.push('/dashboard')
    } catch (err: unknown) {
      const axiosError = err as { response?: { status?: number; data?: { detail?: string } } }
      const status = axiosError?.response?.status
      if (status === 401) {
        setLoginError('Invalid email or password.')
      } else if (status === 423) {
        setLoginError('Account temporarily locked due to failed attempts.')
      } else {
        setLoginError(axiosError?.response?.data?.detail || 'Authentication failed. Please verify credentials.')
      }
    }
  }

  // Submit Registration
  const onRegisterSubmit = async (data: RegisterFormData) => {
    setRegisterError(null)
    try {
      await registerUser({
        email: data.email,
        password: data.password,
        username: data.username,
        display_name: data.display_name,
        organization_name: data.organization_name || undefined,
      })
      toast.success('Analyst account provisioned! Welcome to Phishing EML Analyzer.')
      router.push('/dashboard')
    } catch (err: unknown) {
      const axiosError = err as { response?: { status?: number; data?: { detail?: string; error?: { message?: string } } } }
      const detail = axiosError?.response?.data?.detail || axiosError?.response?.data?.error?.message
      setRegisterError(detail || 'Registration failed. Please check details or try another email.')
    }
  }

  const isFlipped = mode === 'register'

  return (
    <div className="relative w-full max-w-[490px] mx-auto select-none [perspective:1400px]">
      {/* 3D Rotating Container */}
      <motion.div
        animate={{
          rotateY: isFlipped ? 180 : 0,
        }}
        transition={{
          duration: 0.75,
          ease: [0.16, 1, 0.3, 1],
        }}
        className="w-full relative [transform-style:preserve-3d]"
      >
        {/* =========================================================================
            FRONT FACE: LOGIN
            ========================================================================= */}
        <div
          className={cn(
            'w-full rounded-2xl bg-navy-900/80 backdrop-blur-xl border border-navy-600/80',
            'p-6 sm:p-7 shadow-[0_10px_40px_-10px_rgba(0,0,0,0.8),0_0_30px_-5px_rgba(6,182,212,0.12)]',
            'transition-opacity duration-300 [backface-visibility:hidden]',
            isFlipped ? 'pointer-events-none opacity-0 invisible absolute inset-0' : 'relative opacity-100 visible'
          )}
        >
          {/* Top Brand Header */}
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <div className="relative flex items-center justify-center w-10 h-10 rounded-xl bg-accent-blue/15 border border-accent-blue/40 shadow-inner">
                <Shield className="w-5 h-5 text-accent-cyan animate-pulse-slow" />
                <span className="absolute -top-1 -right-1 w-2.5 h-2.5 rounded-full bg-emerald-400 ring-2 ring-navy-900" />
              </div>
              <div>
                <h1 className="text-base font-bold text-white tracking-tight flex items-center gap-2">
                  <span>Phishing EML Analyzer</span>
                </h1>
                <p className="text-[11px] text-slate-400 font-mono flex items-center gap-1.5">
                  <span className="inline-block w-1.5 h-1.5 rounded-full bg-cyan-400" />
                  SOC Threat Detection Console
                </p>
              </div>
            </div>

            <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded-full bg-accent-cyan/10 border border-accent-cyan/30 text-accent-cyan">
              v1.0 Ready
            </span>
          </div>

          {/* Quick Demo Credentials Strip */}
          <div className="mb-3.5 p-2 rounded-lg bg-navy-950/60 border border-navy-700/60 flex items-center justify-between text-xs">
            <span className="text-[11px] text-slate-400 font-medium">Quick Demo:</span>
            <div className="flex items-center gap-1.5">
              <button
                type="button"
                tabIndex={isFlipped ? -1 : 0}
                onClick={() => {
                  setLoginValue('email', 'admin@phishguard.local', { shouldValidate: true })
                  setLoginValue('password', 'AdminSecure2026!', { shouldValidate: true })
                }}
                className="text-[11px] px-2 py-0.5 rounded bg-navy-800 hover:bg-navy-700 text-accent-blue border border-accent-blue/30 transition-colors font-medium"
              >
                Super Admin
              </button>
              <button
                type="button"
                tabIndex={isFlipped ? -1 : 0}
                onClick={() => {
                  setLoginValue('email', 'analyst@phishguard.local', { shouldValidate: true })
                  setLoginValue('password', 'Analyst123!', { shouldValidate: true })
                }}
                className="text-[11px] px-2 py-0.5 rounded bg-navy-800 hover:bg-navy-700 text-accent-cyan border border-accent-cyan/30 transition-colors font-medium"
              >
                SOC Analyst
              </button>
            </div>
          </div>

          {/* Google SSO Button */}
          <div className="mb-3.5">
            <GoogleSignInButton
              intent="login"
              text="Sign in with Google"
              className="py-2.5 text-xs font-semibold"
              onError={(err) => setLoginError(err)}
            />
          </div>

          {/* Divider */}
          <div className="relative flex items-center my-3">
            <div className="flex-grow border-t border-navy-700/80"></div>
            <span className="flex-shrink mx-3 text-[10px] uppercase tracking-wider text-slate-400 font-semibold font-mono">
              or analyst credentials
            </span>
            <div className="flex-grow border-t border-navy-700/80"></div>
          </div>

          {/* Error Banner */}
          {loginError && (
            <motion.div
              initial={{ opacity: 0, y: -4 }}
              animate={{ opacity: 1, y: 0 }}
              className="flex items-start gap-2 bg-red-500/10 border border-red-500/30 rounded-lg p-2.5 mb-3"
            >
              <AlertCircle className="w-4 h-4 text-red-400 flex-shrink-0 mt-0.5" />
              <p className="text-red-400 text-xs leading-snug">{loginError}</p>
            </motion.div>
          )}

          {/* Login Form */}
          <form onSubmit={handleLoginSubmit(onLoginSubmit)} className="space-y-3">
            {/* Email Field */}
            <div>
              <div className="relative">
                <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                <input
                  {...loginReg('email')}
                  type="email"
                  autoComplete="email"
                  tabIndex={isFlipped ? -1 : 0}
                  placeholder="analyst@enterprise.com"
                  className={cn(
                    'w-full bg-navy-950/80 border rounded-lg pl-9 pr-3.5 py-2.5 text-xs sm:text-sm text-slate-100 placeholder-slate-500',
                    'focus:outline-none focus:ring-2 focus:ring-accent-cyan/40 focus:border-accent-cyan',
                    'transition-colors duration-200',
                    loginErrors.email ? 'border-red-500/60' : 'border-navy-600/80'
                  )}
                />
              </div>
              {loginErrors.email && (
                <p className="text-red-400 text-[11px] mt-1 pl-1">{loginErrors.email.message}</p>
              )}
            </div>

            {/* Password Field */}
            <div>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                <input
                  {...loginReg('password')}
                  type={showLoginPassword ? 'text' : 'password'}
                  autoComplete="current-password"
                  tabIndex={isFlipped ? -1 : 0}
                  placeholder="Enter your security token or password"
                  className={cn(
                    'w-full bg-navy-950/80 border rounded-lg pl-9 pr-10 py-2.5 text-xs sm:text-sm text-slate-100 placeholder-slate-500',
                    'focus:outline-none focus:ring-2 focus:ring-accent-cyan/40 focus:border-accent-cyan',
                    'transition-colors duration-200',
                    loginErrors.password ? 'border-red-500/60' : 'border-navy-600/80'
                  )}
                />
                <button
                  type="button"
                  tabIndex={isFlipped ? -1 : 0}
                  onClick={() => setShowLoginPassword(!showLoginPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-200 transition-colors"
                >
                  {showLoginPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
              {loginErrors.password && (
                <p className="text-red-400 text-[11px] mt-1 pl-1">{loginErrors.password.message}</p>
              )}
            </div>

            {/* Remember Me & Forgot Password Row */}
            <div className="flex items-center justify-between text-xs pt-0.5">
              <label className="flex items-center gap-2 cursor-pointer text-slate-400 hover:text-slate-300">
                <input
                  type="checkbox"
                  checked={rememberMe}
                  onChange={(e) => setRememberMe(e.target.checked)}
                  tabIndex={isFlipped ? -1 : 0}
                  className="w-3.5 h-3.5 rounded bg-navy-950 border-navy-600 text-accent-cyan focus:ring-0 focus:ring-offset-0"
                />
                <span className="text-[11px]">Remember analyst session</span>
              </label>

              <button
                type="button"
                tabIndex={isFlipped ? -1 : 0}
                onClick={() => toast.info('Contact SOC administrator for password reset.')}
                className="text-[11px] text-accent-cyan hover:text-cyan-300 transition-colors font-medium"
              >
                Forgot password?
              </button>
            </div>

            {/* Submit Button */}
            <button
              type="submit"
              disabled={isLoading}
              tabIndex={isFlipped ? -1 : 0}
              className={cn(
                'w-full flex items-center justify-center gap-2 rounded-lg py-2.5 px-4 font-semibold text-xs sm:text-sm text-white',
                'bg-gradient-to-r from-accent-blue via-blue-600 to-accent-cyan hover:from-blue-600 hover:to-cyan-500',
                'shadow-lg shadow-blue-500/20 focus:outline-none focus:ring-2 focus:ring-accent-cyan/50',
                'disabled:opacity-60 disabled:cursor-not-allowed transition-all duration-200'
              )}
            >
              {isLoading ? (
                <>
                  <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  <span>Verifying SOC Credentials...</span>
                </>
              ) : (
                <>
                  <KeyRound className="w-4 h-4" />
                  <span>Sign In to SOC Console</span>
                </>
              )}
            </button>
          </form>

          {/* Flip to Register Transition Link */}
          <div className="mt-4 pt-3.5 border-t border-navy-700/60 text-center">
            <p className="text-xs text-slate-400">
              Need new analyst credentials?{' '}
              <button
                type="button"
                tabIndex={isFlipped ? -1 : 0}
                onClick={() => switchMode('register')}
                className="text-accent-cyan hover:text-cyan-300 font-semibold transition-colors inline-flex items-center gap-1 group"
              >
                <span>Create Account</span>
                <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-0.5 transition-transform" />
              </button>
            </p>
          </div>
        </div>

        {/* =========================================================================
            BACK FACE: REGISTRATION
            ========================================================================= */}
        <div
          className={cn(
            'w-full rounded-2xl bg-navy-900/80 backdrop-blur-xl border border-navy-600/80',
            'p-6 sm:p-7 shadow-[0_10px_40px_-10px_rgba(0,0,0,0.8),0_0_30px_-5px_rgba(59,130,246,0.12)]',
            'transition-opacity duration-300 [transform:rotateY(180deg)] [backface-visibility:hidden]',
            !isFlipped ? 'pointer-events-none opacity-0 invisible absolute inset-0' : 'relative opacity-100 visible'
          )}
        >
          {/* Top Brand Header */}
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <div className="relative flex items-center justify-center w-10 h-10 rounded-xl bg-accent-cyan/15 border border-accent-cyan/40 shadow-inner">
                <UserPlus className="w-5 h-5 text-accent-cyan" />
              </div>
              <div>
                <h2 className="text-base font-bold text-white tracking-tight">Create Analyst Account</h2>
                <p className="text-[11px] text-slate-400 font-mono">
                  Phishing EML Analyzer Sandbox Access
                </p>
              </div>
            </div>

            <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
              Analyst Tier
            </span>
          </div>

          {/* Google SSO Button for Registration */}
          <div className="mb-3.5">
            <GoogleSignInButton
              intent="register"
              text="Sign up with Google"
              className="py-2.5 text-xs font-semibold"
              onError={(err) => setRegisterError(err)}
            />
          </div>

          {/* Divider */}
          <div className="relative flex items-center my-3">
            <div className="flex-grow border-t border-navy-700/80"></div>
            <span className="flex-shrink mx-3 text-[10px] uppercase tracking-wider text-slate-400 font-semibold font-mono">
              or create with credentials
            </span>
            <div className="flex-grow border-t border-navy-700/80"></div>
          </div>

          {/* Error Banner */}
          {registerError && (
            <motion.div
              initial={{ opacity: 0, y: -4 }}
              animate={{ opacity: 1, y: 0 }}
              className="flex items-start gap-2 bg-red-500/10 border border-red-500/30 rounded-lg p-2.5 mb-3"
            >
              <AlertCircle className="w-4 h-4 text-red-400 flex-shrink-0 mt-0.5" />
              <p className="text-red-400 text-xs leading-snug">{registerError}</p>
            </motion.div>
          )}

          {/* Registration Form */}
          <form onSubmit={handleRegisterSubmit(onRegisterSubmit)} className="space-y-2.5">
            {/* Row 1: Full Name & Username */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
              <div>
                <div className="relative">
                  <UserIcon className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-400" />
                  <input
                    {...regFormReg('display_name')}
                    type="text"
                    tabIndex={!isFlipped ? -1 : 0}
                    placeholder="Full Name"
                    className={cn(
                      'w-full bg-navy-950/80 border rounded-lg pl-8 pr-2.5 py-2 text-xs sm:text-sm text-slate-100 placeholder-slate-500',
                      'focus:outline-none focus:ring-2 focus:ring-accent-cyan/40 focus:border-accent-cyan',
                      regErrors.display_name ? 'border-red-500/60' : 'border-navy-600/80'
                    )}
                  />
                </div>
                {regErrors.display_name && (
                  <p className="text-red-400 text-[10px] mt-0.5 pl-1">{regErrors.display_name.message}</p>
                )}
              </div>

              <div>
                <div className="relative">
                  <span className="absolute left-3 top-1/2 -translate-y-1/2 text-[11px] text-slate-400 font-mono">@</span>
                  <input
                    {...regFormReg('username')}
                    type="text"
                    tabIndex={!isFlipped ? -1 : 0}
                    placeholder="SOC Username"
                    className={cn(
                      'w-full bg-navy-950/80 border rounded-lg pl-8 pr-2.5 py-2 text-xs sm:text-sm text-slate-100 placeholder-slate-500',
                      'focus:outline-none focus:ring-2 focus:ring-accent-cyan/40 focus:border-accent-cyan',
                      regErrors.username ? 'border-red-500/60' : 'border-navy-600/80'
                    )}
                  />
                </div>
                {regErrors.username && (
                  <p className="text-red-400 text-[10px] mt-0.5 pl-1">{regErrors.username.message}</p>
                )}
              </div>
            </div>

            {/* Row 2: Work Email */}
            <div>
              <div className="relative">
                <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-400" />
                <input
                  {...regFormReg('email')}
                  type="email"
                  autoComplete="email"
                  tabIndex={!isFlipped ? -1 : 0}
                  placeholder="analyst@enterprise.com"
                  className={cn(
                    'w-full bg-navy-950/80 border rounded-lg pl-8 pr-3 py-2 text-xs sm:text-sm text-slate-100 placeholder-slate-500',
                    'focus:outline-none focus:ring-2 focus:ring-accent-cyan/40 focus:border-accent-cyan',
                    regErrors.email ? 'border-red-500/60' : 'border-navy-600/80'
                  )}
                />
              </div>
              {regErrors.email && (
                <p className="text-red-400 text-[10px] mt-0.5 pl-1">{regErrors.email.message}</p>
              )}
            </div>

            {/* Row 3: Password & Confirm Password */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
              <div>
                <div className="relative">
                  <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-400" />
                  <input
                    {...regFormReg('password')}
                    type={showRegPassword ? 'text' : 'password'}
                    tabIndex={!isFlipped ? -1 : 0}
                    placeholder="Password"
                    className={cn(
                      'w-full bg-navy-950/80 border rounded-lg pl-8 pr-8 py-2 text-xs sm:text-sm text-slate-100 placeholder-slate-500',
                      'focus:outline-none focus:ring-2 focus:ring-accent-cyan/40 focus:border-accent-cyan',
                      regErrors.password ? 'border-red-500/60' : 'border-navy-600/80'
                    )}
                  />
                  <button
                    type="button"
                    tabIndex={!isFlipped ? -1 : 0}
                    onClick={() => setShowRegPassword(!showRegPassword)}
                    className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-200"
                  >
                    {showRegPassword ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                  </button>
                </div>
                {regErrors.password && (
                  <p className="text-red-400 text-[10px] mt-0.5 pl-1">{regErrors.password.message}</p>
                )}
              </div>

              <div>
                <div className="relative">
                  <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-400" />
                  <input
                    {...regFormReg('confirmPassword')}
                    type={showConfirmPassword ? 'text' : 'password'}
                    tabIndex={!isFlipped ? -1 : 0}
                    placeholder="Confirm"
                    className={cn(
                      'w-full bg-navy-950/80 border rounded-lg pl-8 pr-8 py-2 text-xs sm:text-sm text-slate-100 placeholder-slate-500',
                      'focus:outline-none focus:ring-2 focus:ring-accent-cyan/40 focus:border-accent-cyan',
                      regErrors.confirmPassword ? 'border-red-500/60' : 'border-navy-600/80'
                    )}
                  />
                  <button
                    type="button"
                    tabIndex={!isFlipped ? -1 : 0}
                    onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                    className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-200"
                  >
                    {showConfirmPassword ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                  </button>
                </div>
                {regErrors.confirmPassword && (
                  <p className="text-red-400 text-[10px] mt-0.5 pl-1">{regErrors.confirmPassword.message}</p>
                )}
              </div>
            </div>

            {/* Password Validation Chips */}
            <div className="flex items-center gap-2 pt-0.5 pb-0.5">
              <span
                className={cn(
                  'text-[10px] font-mono px-2 py-0.5 rounded flex items-center gap-1 border transition-colors',
                  regPasswordValue.length >= 8
                    ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                    : 'bg-navy-950 text-slate-400 border-navy-700'
                )}
              >
                <CheckCircle2 className="w-3 h-3" /> 8+ Chars
              </span>
              <span
                className={cn(
                  'text-[10px] font-mono px-2 py-0.5 rounded flex items-center gap-1 border transition-colors',
                  /[A-Z]/.test(regPasswordValue)
                    ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                    : 'bg-navy-950 text-slate-400 border-navy-700'
                )}
              >
                <CheckCircle2 className="w-3 h-3" /> 1 Uppercase
              </span>
              <span
                className={cn(
                  'text-[10px] font-mono px-2 py-0.5 rounded flex items-center gap-1 border transition-colors',
                  /[0-9]/.test(regPasswordValue)
                    ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                    : 'bg-navy-950 text-slate-400 border-navy-700'
                )}
              >
                <CheckCircle2 className="w-3 h-3" /> 1 Number
              </span>
            </div>

            {/* Optional Organization Toggle */}
            <div>
              {!showOrgField ? (
                <button
                  type="button"
                  tabIndex={!isFlipped ? -1 : 0}
                  onClick={() => setShowOrgField(true)}
                  className="text-[11px] text-slate-400 hover:text-slate-300 flex items-center gap-1 transition-colors"
                >
                  <Building2 className="w-3.5 h-3.5" />
                  <span>+ Add Organization / SOC Team (Optional)</span>
                </button>
              ) : (
                <div className="relative animate-fade-in">
                  <Building2 className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-400" />
                  <input
                    {...regFormReg('organization_name')}
                    type="text"
                    tabIndex={!isFlipped ? -1 : 0}
                    placeholder="SOC Team / Organization Name"
                    className="w-full bg-navy-950/80 border border-navy-600/80 rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-accent-cyan"
                  />
                </div>
              )}
            </div>

            {/* Submit Button */}
            <button
              type="submit"
              disabled={isLoading}
              tabIndex={!isFlipped ? -1 : 0}
              className={cn(
                'w-full flex items-center justify-center gap-2 rounded-lg py-2.5 px-4 font-semibold text-xs sm:text-sm text-white mt-1',
                'bg-gradient-to-r from-accent-blue via-blue-600 to-accent-cyan hover:from-blue-600 hover:to-cyan-500',
                'shadow-lg shadow-blue-500/20 focus:outline-none focus:ring-2 focus:ring-accent-cyan/50',
                'disabled:opacity-60 disabled:cursor-not-allowed transition-all duration-200'
              )}
            >
              {isLoading ? (
                <>
                  <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  <span>Creating Account...</span>
                </>
              ) : (
                <>
                  <ShieldCheck className="w-4 h-4" />
                  <span>Create Analyst Account</span>
                </>
              )}
            </button>
          </form>

          {/* Flip to Login Transition Link */}
          <div className="mt-3.5 pt-3 border-t border-navy-700/60 text-center">
            <p className="text-xs text-slate-400">
              Already have an analyst account?{' '}
              <button
                type="button"
                tabIndex={!isFlipped ? -1 : 0}
                onClick={() => switchMode('login')}
                className="text-accent-cyan hover:text-cyan-300 font-semibold transition-colors inline-flex items-center gap-1 group"
              >
                <span>Back to Sign In</span>
                <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-0.5 transition-transform" />
              </button>
            </p>
          </div>
        </div>
      </motion.div>
    </div>
  )
}
