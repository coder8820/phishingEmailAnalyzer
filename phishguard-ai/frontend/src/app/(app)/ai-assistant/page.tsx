'use client'

import React, { useState, useEffect, useRef } from 'react'
import {
  Bot,
  User as UserIcon,
  Send,
  Plus,
  Trash2,
  RotateCcw,
  Sparkles,
  ExternalLink,
  Shield,
  Search,
  MessageSquare,
  Globe,
  Copy,
  Check,
  ChevronRight,
  Terminal,
  HelpCircle,
} from 'lucide-react'
import { toast } from 'sonner'
import {
  chatService,
  ChatSession,
  ChatSessionDetail,
  ChatMessage,
  CyberResource,
} from '@/services/chatService'
import { MarkdownContent } from '@/components/chat/MarkdownContent'
import { ResourceCard } from '@/components/chat/ResourceCard'
import { ResourcesCatalogModal } from '@/components/chat/ResourcesCatalogModal'

const QUICK_PROMPTS = [
  {
    icon: '🔍',
    title: 'Email Analysis Workflow',
    prompt: 'PhishGuard AI email analyzer kaisy kaam krta hy? Step-by-step full working detail ma btao.',
  },
  {
    icon: '🛡️',
    title: 'SPF, DKIM & DMARC',
    prompt: 'Explain the difference between SPF, DKIM, and DMARC, and how PhishGuard detects spoofed headers.',
  },
  {
    icon: '📊',
    title: 'Risk Score Breakdown',
    prompt: 'PhishGuard AI ka 0 to 100 Risk Score kaisy calculate hota hy? Weights aur classification tiers btao.',
  },
  {
    icon: '🌐',
    title: 'External Tools & Sources',
    prompt: 'Email investigation k lea best external platforms, threat feeds aur sandboxes k valid sources aur links provide kro.',
  },
  {
    icon: '🚨',
    title: 'SOC Incident Response',
    prompt: 'How should a SOC analyst triage and investigate a high-risk phishing incident in PhishGuard?',
  },
  {
    icon: '🎯',
    title: 'IOC Extraction & Defanging',
    prompt: 'What are Indicators of Compromise (IOCs) and why does PhishGuard automatically defang URLs and IPs?',
  },
]

export default function AIAssistantPage() {
  const [sessions, setSessions] = useState<ChatSession[]>([])
  const [activeSessionId, setActiveSessionId] = useState<string | null>(null)
  const [activeSession, setActiveSession] = useState<ChatSessionDetail | null>(null)
  const [inputMessage, setInputMessage] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [isInitializing, setIsInitializing] = useState(true)
  const [searchQuery, setSearchQuery] = useState('')
  const [resources, setResources] = useState<CyberResource[]>([])
  const [isCatalogOpen, setIsCatalogOpen] = useState(false)
  const [copiedMsgId, setCopiedMsgId] = useState<string | null>(null)

  const messagesEndRef = useRef<HTMLDivElement>(null)
  const textareaRef = useRef<HTMLTextAreaElement>(null)

  // Scroll to bottom on new message
  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }

  useEffect(() => {
    scrollToBottom()
  }, [activeSession?.messages, isLoading])

  // Load initial sessions and resources
  useEffect(() => {
    const init = async () => {
      try {
        const [sessionList, resourceList] = await Promise.all([
          chatService.getSessions(),
          chatService.getResources(),
        ])
        setSessions(sessionList)
        setResources(resourceList)

        if (sessionList.length > 0) {
          await loadSession(sessionList[0].id)
        } else {
          await handleNewChat(false)
        }
      } catch (err) {
        console.error('Failed to load chat data:', err)
        toast.error('Failed to load chat history')
      } finally {
        setIsInitializing(false)
      }
    }
    init()
  }, [])

  const loadSession = async (sessionId: string) => {
    try {
      setActiveSessionId(sessionId)
      const detail = await chatService.getSession(sessionId)
      setActiveSession(detail)
    } catch {
      toast.error('Could not load conversation')
    }
  }

  const handleNewChat = async (notify = true) => {
    try {
      const newSession = await chatService.createSession()
      setSessions((prev) => [newSession, ...prev])
      setActiveSessionId(newSession.id)
      setActiveSession(newSession)
      if (notify) toast.success('New conversation started')
      if (textareaRef.current) {
        textareaRef.current.focus()
      }
    } catch {
      toast.error('Failed to create new conversation')
    }
  }

  const handleSendMessage = async (textToSend?: string) => {
    const text = (textToSend ?? inputMessage).trim()
    if (!text || isLoading) return

    let currentId = activeSessionId
    if (!currentId) {
      const newSession = await chatService.createSession()
      currentId = newSession.id
      setSessions((prev) => [newSession, ...prev])
      setActiveSessionId(currentId)
    }

    setInputMessage('')
    setIsLoading(true)

    // Optimistically append user message to UI
    const tempUserMsg: ChatMessage = {
      id: `temp-${Date.now()}`,
      sender: 'user',
      content: text,
      sources: [],
      created_at: new Date().toISOString(),
    }

    setActiveSession((prev) =>
      prev
        ? {
            ...prev,
            messages: [...prev.messages, tempUserMsg],
          }
        : null
    )

    try {
      const response = await chatService.sendMessage(currentId, text)

      // Replace with actual messages from backend
      setActiveSession((prev) => {
        if (!prev) return null
        const filtered = prev.messages.filter((m) => !m.id.startsWith('temp-'))
        return {
          ...prev,
          title: response.session_title,
          messages: [...filtered, response.user_message, response.assistant_message],
        }
      })

      // Update session title in sidebar list
      setSessions((prev) =>
        prev.map((s) =>
          s.id === currentId
            ? {
                ...s,
                title: response.session_title,
                updated_at: new Date().toISOString(),
              }
            : s
        )
      )
    } catch (err) {
      console.error('Send message error:', err)
      toast.error('Failed to get response from AI Assistant')
    } finally {
      setIsLoading(false)
    }
  }

  const handleClearChat = async () => {
    if (!activeSessionId) return
    if (!confirm('Are you sure you want to clear all messages in this conversation?')) return

    try {
      await chatService.clearSession(activeSessionId)
      setActiveSession((prev) => (prev ? { ...prev, title: 'New Conversation', messages: [] } : null))
      setSessions((prev) =>
        prev.map((s) => (s.id === activeSessionId ? { ...s, title: 'New Conversation', message_count: 0 } : s))
      )
      toast.success('Conversation messages cleared')
    } catch {
      toast.error('Failed to clear conversation')
    }
  }

  const handleDeleteSession = async (sessionId: string, e?: React.MouseEvent) => {
    if (e) e.stopPropagation()
    if (!confirm('Are you sure you want to permanently delete this conversation?')) return

    try {
      await chatService.deleteSession(sessionId)
      const remaining = sessions.filter((s) => s.id !== sessionId)
      setSessions(remaining)
      toast.success('Conversation deleted')

      if (activeSessionId === sessionId) {
        if (remaining.length > 0) {
          loadSession(remaining[0].id)
        } else {
          handleNewChat(false)
        }
      }
    } catch {
      toast.error('Failed to delete conversation')
    }
  }

  const handleDeleteAllSessions = async () => {
    if (!confirm('Are you sure you want to delete ALL chat sessions? This cannot be undone.')) return

    try {
      await chatService.deleteAllSessions()
      setSessions([])
      setActiveSession(null)
      setActiveSessionId(null)
      toast.success('All conversation history deleted')
      await handleNewChat(false)
    } catch {
      toast.error('Failed to reset chat history')
    }
  }

  const handleCopyMessage = (text: string, id: string) => {
    navigator.clipboard.writeText(text)
    setCopiedMsgId(id)
    toast.success('Copied to clipboard')
    setTimeout(() => setCopiedMsgId(null), 2000)
  }

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      handleSendMessage()
    }
  }

  const filteredSessions = sessions.filter((s) =>
    s.title.toLowerCase().includes(searchQuery.toLowerCase())
  )

  return (
    <div className="flex h-[calc(100vh-6rem)] rounded-2xl bg-navy-900 border border-navy-700/80 shadow-2xl overflow-hidden">
      {/* ============================================================ */}
      {/* LEFT SIDEBAR: Conversation History & Tools */}
      {/* ============================================================ */}
      <aside className="w-80 border-r border-navy-700/80 bg-navy-850 flex flex-col shrink-0 select-none">
        {/* Sidebar Header */}
        <div className="p-4 border-b border-navy-700/80 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <div className="w-8 h-8 rounded-lg bg-accent-blue/20 border border-accent-blue/30 flex items-center justify-center">
                <Sparkles className="w-4 h-4 text-accent-cyan" />
              </div>
              <div>
                <h3 className="text-sm font-bold text-white">AI Assistant</h3>
                <span className="text-[10px] text-accent-cyan font-mono tracking-wider">
                  SOC Copilot v1.0
                </span>
              </div>
            </div>

            <button
              onClick={() => setIsCatalogOpen(true)}
              title="Browse External Security Platforms"
              className="p-1.5 rounded-lg bg-navy-800 border border-navy-700 text-slate-300 hover:text-accent-cyan hover:border-accent-cyan/40 transition-colors"
            >
              <Globe className="w-4 h-4" />
            </button>
          </div>

          {/* New Chat Button */}
          <button
            onClick={() => handleNewChat(true)}
            className="w-full flex items-center justify-center gap-2 py-2.5 px-4 rounded-xl bg-accent-blue hover:bg-blue-600 text-white text-xs font-semibold shadow-lg shadow-accent-blue/20 transition-all active:scale-[0.98]"
          >
            <Plus className="w-4 h-4" />
            <span>New Chat Conversation</span>
          </button>

          {/* Search Conversations */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search conversations..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-8 pr-3 py-1.5 rounded-lg bg-navy-900 border border-navy-700 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-accent-cyan transition-colors"
            />
          </div>
        </div>

        {/* Sessions List */}
        <div className="flex-1 overflow-y-auto p-2 space-y-1">
          {filteredSessions.length === 0 ? (
            <div className="py-8 text-center text-xs text-slate-400 px-4">
              {searchQuery ? 'No matching conversations' : 'No conversation history'}
            </div>
          ) : (
            filteredSessions.map((s) => {
              const isActive = s.id === activeSessionId
              return (
                <div
                  key={s.id}
                  onClick={() => loadSession(s.id)}
                  className={`group flex items-center justify-between px-3 py-2.5 rounded-xl cursor-pointer text-xs font-medium transition-all ${
                    isActive
                      ? 'bg-accent-blue/15 text-white border border-accent-blue/30 shadow-sm'
                      : 'text-slate-300 hover:bg-navy-800/80 hover:text-white'
                  }`}
                >
                  <div className="flex items-center gap-2.5 min-w-0 pr-2">
                    <MessageSquare
                      className={`w-3.5 h-3.5 shrink-0 ${
                        isActive ? 'text-accent-cyan' : 'text-slate-500 group-hover:text-slate-300'
                      }`}
                    />
                    <span className="truncate">{s.title || 'New Conversation'}</span>
                  </div>

                  <div className="flex items-center gap-1 shrink-0">
                    <button
                      onClick={(e) => handleDeleteSession(s.id, e)}
                      title="Delete chat"
                      className="p-1 rounded text-slate-500 hover:text-red-400 hover:bg-navy-700/60 transition-colors opacity-0 group-hover:opacity-100"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>
              )
            })
          )}
        </div>

        {/* Sidebar Footer */}
        <div className="p-3 border-t border-navy-700/80 bg-navy-900/60 flex items-center justify-between text-xs">
          <button
            onClick={() => setIsCatalogOpen(true)}
            className="flex items-center gap-1.5 text-accent-cyan hover:text-cyan-300 font-medium transition-colors"
          >
            <Globe className="w-3.5 h-3.5" />
            <span>External Tools (18)</span>
          </button>

          {sessions.length > 0 && (
            <button
              onClick={handleDeleteAllSessions}
              className="text-slate-400 hover:text-red-400 text-[11px] transition-colors"
              title="Delete all chat history"
            >
              Clear All
            </button>
          )}
        </div>
      </aside>

      {/* ============================================================ */}
      {/* RIGHT MAIN CHAT AREA */}
      {/* ============================================================ */}
      <main className="flex-1 flex flex-col bg-navy-900 overflow-hidden">
        {/* Chat Area Top Bar */}
        <div className="h-16 px-6 border-b border-navy-700/80 bg-navy-850 flex items-center justify-between shrink-0">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-accent-blue/30 to-accent-cyan/20 border border-accent-cyan/30 flex items-center justify-center shadow-md">
              <Bot className="w-5 h-5 text-accent-cyan" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-sm font-bold text-white truncate max-w-md">
                  {activeSession?.title || 'New Conversation'}
                </h2>
                <span className="flex items-center gap-1 text-[10px] font-mono text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 px-2 py-0.5 rounded-full">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                  Online
                </span>
              </div>
              <p className="text-[11px] text-slate-400">
                PhishGuard AI Copilot • Explains system architecture, risk scores, SPF/DKIM/DMARC & verified resources
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => setIsCatalogOpen(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-navy-800 border border-navy-700 text-xs text-slate-300 hover:text-accent-cyan hover:border-accent-cyan/40 transition-colors"
            >
              <Globe className="w-3.5 h-3.5 text-accent-cyan" />
              <span className="hidden sm:inline">External Tools</span>
            </button>

            <button
              onClick={handleClearChat}
              title="Clear messages in this conversation"
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-navy-800 border border-navy-700 text-xs text-slate-300 hover:text-amber-300 hover:border-amber-400/40 transition-colors"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">Clear Chat</span>
            </button>

            {activeSessionId && (
              <button
                onClick={(e) => handleDeleteSession(activeSessionId, e)}
                title="Delete this conversation"
                className="p-1.5 rounded-lg bg-navy-800 border border-navy-700 text-slate-400 hover:text-red-400 hover:border-red-400/40 transition-colors"
              >
                <Trash2 className="w-4 h-4" />
              </button>
            )}
          </div>
        </div>

        {/* Message Thread Container */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {isInitializing ? (
            <div className="h-full flex items-center justify-center">
              <div className="text-center space-y-3">
                <Shield className="w-10 h-10 text-accent-cyan mx-auto animate-pulse" />
                <p className="text-xs text-slate-400">Initializing PhishGuard AI Security Copilot...</p>
              </div>
            </div>
          ) : !activeSession || activeSession.messages.length === 0 ? (
            /* Empty State Hero with Quick Prompts */
            <div className="max-w-3xl mx-auto py-8 space-y-8 animate-fade-in">
              <div className="text-center space-y-3">
                <div className="w-16 h-16 rounded-2xl bg-gradient-to-tr from-accent-blue/20 to-accent-cyan/20 border border-accent-cyan/30 flex items-center justify-center mx-auto shadow-xl shadow-accent-blue/10">
                  <Bot className="w-8 h-8 text-accent-cyan" />
                </div>
                <h1 className="text-2xl font-bold text-white tracking-tight">
                  PhishGuard AI Assistant 🛡️
                </h1>
                <p className="text-sm text-slate-300 max-w-xl mx-auto leading-relaxed">
                  Apne <strong>Phishing Email Analyzer</strong> k baray ma kuch b poochein — working flow, SPF/DKIM/DMARC protocols, risk scoring calculations, ya external cybersecurity sources k verified links.
                </p>
              </div>

              {/* Quick Prompt Cards */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                {QUICK_PROMPTS.map((item, idx) => (
                  <button
                    key={idx}
                    onClick={() => handleSendMessage(item.prompt)}
                    className="flex items-start gap-3 p-4 rounded-xl bg-navy-800/90 border border-navy-700/80 hover:border-accent-cyan/60 hover:bg-navy-800 text-left transition-all group shadow-sm active:scale-[0.99]"
                  >
                    <span className="text-xl shrink-0">{item.icon}</span>
                    <div className="min-w-0">
                      <p className="text-xs font-bold text-slate-200 group-hover:text-accent-cyan transition-colors">
                        {item.title}
                      </p>
                      <p className="text-[11px] text-slate-400 line-clamp-2 mt-0.5">
                        {item.prompt}
                      </p>
                    </div>
                  </button>
                ))}
              </div>
            </div>
          ) : (
            /* Render Message History */
            activeSession.messages.map((msg) => {
              const isAssistant = msg.sender === 'assistant'
              return (
                <div
                  key={msg.id}
                  className={`flex gap-3.5 max-w-4xl ${isAssistant ? '' : 'ml-auto justify-end'}`}
                >
                  {isAssistant && (
                    <div className="w-8 h-8 rounded-lg bg-accent-blue/20 border border-accent-blue/30 flex items-center justify-center shrink-0 mt-1 shadow-sm">
                      <Bot className="w-4 h-4 text-accent-cyan" />
                    </div>
                  )}

                  <div className={`space-y-3 max-w-[85%] ${isAssistant ? 'w-full' : ''}`}>
                    <div
                      className={`p-4 rounded-2xl shadow-md ${
                        isAssistant
                          ? 'bg-navy-800/95 border border-navy-700/90 text-slate-200'
                          : 'bg-accent-blue text-white ml-auto'
                      }`}
                    >
                      {/* Message Content */}
                      {isAssistant ? (
                        <MarkdownContent content={msg.content} />
                      ) : (
                        <p className="text-sm whitespace-pre-wrap leading-relaxed">{msg.content}</p>
                      )}

                      {/* Attached External Resource Cards if any */}
                      {isAssistant && msg.sources && msg.sources.length > 0 && (
                        <div className="mt-4 pt-4 border-t border-navy-700 space-y-2">
                          <div className="flex items-center gap-1.5 text-xs font-semibold text-accent-cyan">
                            <Globe className="w-3.5 h-3.5" />
                            <span>Verified External Platforms & Sources:</span>
                          </div>
                          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                            {msg.sources.map((src, sIdx) => (
                              <ResourceCard key={sIdx} resource={src} compact={true} />
                            ))}
                          </div>
                        </div>
                      )}
                    </div>

                    {/* Action Bar (Copy, Timestamp) */}
                    {isAssistant && (
                      <div className="flex items-center gap-3 px-1 text-[11px] text-slate-500">
                        <button
                          onClick={() => handleCopyMessage(msg.content, msg.id)}
                          className="flex items-center gap-1 hover:text-slate-300 transition-colors"
                        >
                          {copiedMsgId === msg.id ? (
                            <>
                              <Check className="w-3 h-3 text-green-400" />
                              <span className="text-green-400">Copied</span>
                            </>
                          ) : (
                            <>
                              <Copy className="w-3 h-3" />
                              <span>Copy response</span>
                            </>
                          )}
                        </button>
                      </div>
                    )}
                  </div>

                  {!isAssistant && (
                    <div className="w-8 h-8 rounded-lg bg-navy-700 border border-navy-600 flex items-center justify-center shrink-0 mt-1">
                      <UserIcon className="w-4 h-4 text-slate-300" />
                    </div>
                  )}
                </div>
              )
            })
          )}

          {/* Loading Indicator */}
          {isLoading && (
            <div className="flex gap-3.5 max-w-4xl">
              <div className="w-8 h-8 rounded-lg bg-accent-blue/20 border border-accent-blue/30 flex items-center justify-center shrink-0 mt-1">
                <Bot className="w-4 h-4 text-accent-cyan" />
              </div>
              <div className="p-4 rounded-2xl bg-navy-800/90 border border-navy-700 flex items-center gap-3 shadow-md">
                <div className="flex gap-1.5">
                  <div className="w-2 h-2 rounded-full bg-accent-cyan animate-bounce" />
                  <div
                    className="w-2 h-2 rounded-full bg-accent-blue animate-bounce"
                    style={{ animationDelay: '0.2s' }}
                  />
                  <div
                    className="w-2 h-2 rounded-full bg-cyan-300 animate-bounce"
                    style={{ animationDelay: '0.4s' }}
                  />
                </div>
                <span className="text-xs text-slate-400 font-mono">
                  PhishGuard Copilot analyzing & generating response...
                </span>
              </div>
            </div>
          )}

          <div ref={messagesEndRef} />
        </div>

        {/* Input Bar */}
        <div className="p-4 border-t border-navy-700/80 bg-navy-850">
          <div className="max-w-4xl mx-auto">
            <div className="relative flex items-end gap-2 p-2 rounded-2xl bg-navy-950 border border-navy-700 focus-within:border-accent-cyan/80 transition-colors shadow-inner">
              <textarea
                ref={textareaRef}
                rows={1}
                placeholder="Ask about PhishGuard AI, email security, SPF/DKIM, or request external sources..."
                value={inputMessage}
                onChange={(e) => setInputMessage(e.target.value)}
                onKeyDown={handleKeyDown}
                className="w-full max-h-32 p-2 bg-transparent text-sm text-slate-100 placeholder-slate-500 focus:outline-none resize-none leading-relaxed"
                style={{ minHeight: '44px' }}
              />

              <button
                onClick={() => handleSendMessage()}
                disabled={!inputMessage.trim() || isLoading}
                className={`p-2.5 rounded-xl transition-all shrink-0 ${
                  inputMessage.trim() && !isLoading
                    ? 'bg-accent-blue hover:bg-blue-600 text-white shadow-md shadow-accent-blue/20'
                    : 'bg-navy-800 text-slate-500 cursor-not-allowed'
                }`}
              >
                <Send className="w-4 h-4" />
              </button>
            </div>

            <div className="mt-2 flex items-center justify-between text-[11px] text-slate-500 px-1">
              <span>Press <strong>Enter</strong> to send • <strong>Shift + Enter</strong> for new line</span>
              <button
                onClick={() => setIsCatalogOpen(true)}
                className="text-accent-cyan hover:underline flex items-center gap-1"
              >
                <span>Browse Verified External Platforms</span>
                <ExternalLink className="w-3 h-3" />
              </button>
            </div>
          </div>
        </div>
      </main>

      {/* External Resources Modal */}
      <ResourcesCatalogModal
        isOpen={isCatalogOpen}
        onClose={() => setIsCatalogOpen(false)}
        resources={resources}
      />
    </div>
  )
}
