import { apiClient } from '@/lib/api'
import type { User } from '@/types'

export interface GoogleAuthConfig {
  is_configured: boolean
  client_id: string
  demo_mode_allowed: boolean
}

export interface GoogleAuthResponse {
  access_token: string
  refresh_token: string
  token_type: string
  is_new_user: boolean
  user: User
}

export const googleAuthService = {
  /**
   * Fetches Google OAuth configuration status from the backend.
   */
  async getConfig(): Promise<GoogleAuthConfig> {
    const { data } = await apiClient.get('/auth/google/config')
    return data.data
  },

  /**
   * Generates a Google OAuth authorization URL with PKCE and signed CSRF state.
   */
  async getAuthUrl(intent: 'login' | 'register' = 'login', redirectUri?: string): Promise<{ authorization_url: string; state: string }> {
    const params = new URLSearchParams()
    params.set('intent', intent)
    if (redirectUri) {
      params.set('redirect_uri', redirectUri)
    }
    const { data } = await apiClient.get(`/auth/google/url?${params.toString()}`)
    return data.data
  },

  /**
   * Exchanges Google authorization code for PhishGuard JWT tokens.
   */
  async exchangeCallback(code: string, state: string, redirectUri?: string): Promise<GoogleAuthResponse> {
    const { data } = await apiClient.post('/auth/google/callback', {
      code,
      state,
      redirect_uri: redirectUri,
    })
    return data.data
  },

  /**
   * Authenticates directly via Google Identity Services (GIS) ID token.
   */
  async verifyIdToken(credential: string): Promise<GoogleAuthResponse> {
    const { data } = await apiClient.post('/auth/google/token', {
      credential,
    })
    return data.data
  },

  /**
   * Instant Google SSO authentication for local development & demonstration.
   */
  async demoLogin(email?: string, displayName?: string): Promise<GoogleAuthResponse> {
    const { data } = await apiClient.post('/auth/google/demo', {
      email,
      display_name: displayName,
    })
    return data.data
  },
}
