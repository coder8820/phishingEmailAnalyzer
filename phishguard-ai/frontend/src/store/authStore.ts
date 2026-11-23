import { create } from 'zustand'
import { persist } from 'zustand/middleware'
import type { User } from '@/types'
import { apiClient } from '@/lib/api'
import { googleAuthService, type GoogleAuthResponse } from '@/services/googleAuthService'

interface RegisterPayload {
  email: string
  password: string
  username?: string
  display_name?: string
  organization_name?: string
}

interface AuthState {
  user: User | null
  accessToken: string | null
  refreshToken: string | null
  isAuthenticated: boolean
  isLoading: boolean
  isHydrated: boolean
  setHydrated: (hydrated: boolean) => void
  setAuthData: (accessToken: string, refreshToken: string, user: User) => void
  login: (email: string, password: string) => Promise<void>
  register: (payload: RegisterPayload) => Promise<void>
  loginWithGoogleCallback: (code: string, state: string, redirectUri?: string) => Promise<GoogleAuthResponse>
  loginWithGoogleToken: (credential: string) => Promise<GoogleAuthResponse>
  loginWithGoogleDemo: (email?: string, displayName?: string) => Promise<GoogleAuthResponse>
  logout: () => Promise<void>
  loadUser: () => Promise<void>
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set, get) => ({
      user: null,
      accessToken: null,
      refreshToken: null,
      isAuthenticated: false,
      isLoading: false,
      isHydrated: false,

      setHydrated: (hydrated: boolean) => set({ isHydrated: hydrated }),

      setAuthData: (accessToken: string, refreshToken: string, user: User) => {
        if (typeof window !== 'undefined') {
          localStorage.setItem('access_token', accessToken)
          localStorage.setItem('refresh_token', refreshToken)
        }
        set({
          accessToken,
          refreshToken,
          user,
          isAuthenticated: true,
          isLoading: false,
        })
      },

      login: async (email: string, password: string) => {
        set({ isLoading: true })
        try {
          const { data } = await apiClient.post('/auth/login', { email, password })
          const { access_token, refresh_token, user } = data.data
          if (typeof window !== 'undefined') {
            localStorage.setItem('access_token', access_token)
            localStorage.setItem('refresh_token', refresh_token)
          }
          set({
            accessToken: access_token,
            refreshToken: refresh_token,
            user: user ?? get().user,
            isAuthenticated: true,
            isLoading: false,
          })
          await get().loadUser()
        } catch (err) {
          set({ isLoading: false })
          throw err
        }
      },

      register: async (payload: RegisterPayload) => {
        set({ isLoading: true })
        try {
          const { data } = await apiClient.post('/auth/register', payload)
          const { access_token, refresh_token, user } = data.data
          if (typeof window !== 'undefined') {
            localStorage.setItem('access_token', access_token)
            localStorage.setItem('refresh_token', refresh_token)
          }
          set({
            accessToken: access_token,
            refreshToken: refresh_token,
            user: user,
            isAuthenticated: true,
            isLoading: false,
          })
          await get().loadUser()
        } catch (err) {
          set({ isLoading: false })
          throw err
        }
      },

      loginWithGoogleCallback: async (code: string, state: string, redirectUri?: string) => {
        set({ isLoading: true })
        try {
          const result = await googleAuthService.exchangeCallback(code, state, redirectUri)
          if (typeof window !== 'undefined') {
            localStorage.setItem('access_token', result.access_token)
            localStorage.setItem('refresh_token', result.refresh_token)
          }
          set({
            accessToken: result.access_token,
            refreshToken: result.refresh_token,
            user: result.user,
            isAuthenticated: true,
            isLoading: false,
          })
          await get().loadUser()
          return result
        } catch (err) {
          set({ isLoading: false })
          throw err
        }
      },

      loginWithGoogleToken: async (credential: string) => {
        set({ isLoading: true })
        try {
          const result = await googleAuthService.verifyIdToken(credential)
          if (typeof window !== 'undefined') {
            localStorage.setItem('access_token', result.access_token)
            localStorage.setItem('refresh_token', result.refresh_token)
          }
          set({
            accessToken: result.access_token,
            refreshToken: result.refresh_token,
            user: result.user,
            isAuthenticated: true,
            isLoading: false,
          })
          await get().loadUser()
          return result
        } catch (err) {
          set({ isLoading: false })
          throw err
        }
      },

      loginWithGoogleDemo: async (email?: string, displayName?: string) => {
        set({ isLoading: true })
        try {
          const result = await googleAuthService.demoLogin(email, displayName)
          if (typeof window !== 'undefined') {
            localStorage.setItem('access_token', result.access_token)
            localStorage.setItem('refresh_token', result.refresh_token)
          }
          set({
            accessToken: result.access_token,
            refreshToken: result.refresh_token,
            user: result.user,
            isAuthenticated: true,
            isLoading: false,
          })
          await get().loadUser()
          return result
        } catch (err) {
          set({ isLoading: false })
          throw err
        }
      },

      logout: async () => {
        try {
          await apiClient.post('/auth/logout')
        } catch {
          // ignore logout errors
        }
        if (typeof window !== 'undefined') {
          localStorage.removeItem('access_token')
          localStorage.removeItem('refresh_token')
        }
        set({ user: null, accessToken: null, refreshToken: null, isAuthenticated: false })
      },

      loadUser: async () => {
        const token =
          get().accessToken ||
          (typeof window !== 'undefined' ? localStorage.getItem('access_token') : null)

        if (!token) {
          set({ user: null, accessToken: null, isAuthenticated: false })
          return
        }

        try {
          const { data } = await apiClient.get('/auth/me')
          set({ user: data.data, isAuthenticated: true, accessToken: token })
        } catch (err: unknown) {
          const axiosError = err as { response?: { status?: number } }
          if (axiosError?.response?.status === 401) {
            get().logout()
          }
        }
      },
    }),
    {
      name: 'phishguard-auth',
      partialize: (s) => ({
        user: s.user,
        accessToken: s.accessToken,
        refreshToken: s.refreshToken,
        isAuthenticated: s.isAuthenticated,
      }),
      onRehydrateStorage: () => (state) => {
        state?.setHydrated(true)
      },
    }
  )
)
