import { apiClient } from '@/lib/api'

export interface CyberResource {
  id: string
  title: string
  url: string
  category: string
  badge: string
  description: string
  tags: string[]
}

export interface ChatMessage {
  id: string
  sender: 'user' | 'assistant'
  content: string
  sources: CyberResource[]
  created_at: string
}

export interface ChatSession {
  id: string
  title: string
  created_at: string
  updated_at: string
  message_count?: number
}

export interface ChatSessionDetail extends ChatSession {
  messages: ChatMessage[]
}

export const chatService = {
  async getSessions(): Promise<ChatSession[]> {
    const res = await apiClient.get('/chat/sessions')
    return res.data.data
  },

  async createSession(title?: string): Promise<ChatSessionDetail> {
    const res = await apiClient.post('/chat/sessions', { title })
    return res.data.data
  },

  async getSession(sessionId: string): Promise<ChatSessionDetail> {
    const res = await apiClient.get(`/chat/sessions/${sessionId}`)
    return res.data.data
  },

  async sendMessage(sessionId: string, content: string) {
    const res = await apiClient.post(`/chat/sessions/${sessionId}/messages`, { content })
    return res.data.data
  },

  async clearSession(sessionId: string) {
    const res = await apiClient.delete(`/chat/sessions/${sessionId}/clear`)
    return res.data.data
  },

  async deleteSession(sessionId: string) {
    const res = await apiClient.delete(`/chat/sessions/${sessionId}`)
    return res.data.data
  },

  async deleteAllSessions() {
    const res = await apiClient.delete('/chat/sessions')
    return res.data.data
  },

  async getResources(): Promise<CyberResource[]> {
    const res = await apiClient.get('/chat/resources')
    return res.data.data
  },
}
