'use client'

import React, { useState, useEffect, useRef } from 'react'
import {
  Bot,
  X,
  Send,
  Sparkles,
  Maximize2,
  Trash2,
  RotateCcw,
  Globe,
  ExternalLink,
  ChevronDown,
} from 'lucide-react'
import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { chatService, ChatSessionDetail, ChatMessage, CyberResource } from '@/services/chatService'
import { MarkdownContent } from './MarkdownContent'
import { ResourceCard } from './ResourceCard'
import { toast } from 'sonner'

export function FloatingAssistantWidget() {
  const pathname = usePathname()
  const [isOpen, setIsOpen] = useState(false)
  const [session, setSession] = useState<ChatSessionDetail | null>(null)
  const [inputMessage, setInputMessage] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const messagesEndRef = useRef<HTMLDivElement>(null)

  // Load or create a session when opened
  useEffect(() => {
    if (isOpen && !session) {
      const init = async () => {
        try {
          const sessions = await chatService.getSessions()
          if (sessions.length > 0) {
            const detail = await chatService.getSession(sessions[0].id)
            setSession(detail)
          } else {
            const newSession = await chatService.createSession('Quick Assistant Chat')
            setSession(newSession)
          }
        } catch {
          // Fallback
        }
      }
      init()
    }
  }, [isOpen, session])

  useEffect(() => {
    if (isOpen) {
      messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
    }
  }, [session?.messages, isOpen, isLoading])

  const handleSend = async (e?: React.FormEvent) => {
    if (e) e.preventDefault()
    const text = inputMessage.trim()
    if (!text || isLoading) return

    let currentSession = session
    if (!currentSession) {
      try {
        currentSession = await chatService.createSession('Quick Assistant Chat')
        setSession(currentSession)
      } catch {
        toast.error('Could not start assistant session')
        return
      }
    }

    setInputMessage('')
    setIsLoading(true)

    const tempMsg: ChatMessage = {
      id: `temp-${Date.now()}`,
      sender: 'user',
      content: text,
      sources: [],
      created_at: new Date().toISOString(),
    }

    setSession((prev) =>
      prev
        ? {
            ...prev,
            messages: [...prev.messages, tempMsg],
          }
        : null
    )

    try {
      const res = await chatService.sendMessage(currentSession.id, text)
      setSession((prev) => {
        if (!prev) return null
        const filtered = prev.messages.filter((m) => !m.id.startsWith('temp-'))
        return {
          ...prev,
          title: res.session_title,
          messages: [...filtered, res.user_message, res.assistant_message],
        }
      })
    } catch {
      toast.error('Assistant error')
    } finally {
      setIsLoading(false)
    }
  }

  const handleClear = async () => {
    if (!session?.id) return
    try {
      await chatService.clearSession(session.id)
      setSession((prev) => (prev ? { ...prev, messages: [] } : null))
      toast.success('Chat cleared')
    } catch {
      toast.error('Could not clear chat')
    }
  }

  // Don't show floating widget if already on the full /ai-assistant page
  if (pathname === '/ai-assistant') {
    return null
  }

  return (
    <div className="fixed bottom-6 right-6 z-50">
      {/* Floating Trigger Button */}
      {!isOpen && (
        <button
          onClick={() => setIsOpen(true)}
          className="group relative flex items-center gap-2.5 px-4 py-3 rounded-full bg-gradient-to-r from-accent-blue to-accent-cyan text-white font-semibold text-xs shadow-2xl shadow-accent-cyan/25 hover:shadow-accent-cyan/40 hover:scale-105 active:scale-95 transition-all"
        >
          <div className="relative">
            <Bot className="w-5 h-5" />
            <span className="absolute -top-1 -right-1 w-2.5 h-2.5 rounded-full bg-emerald-400 border-2 border-navy-900 animate-pulse" />
          </div>
          <span>Ask PhishGuard AI</span>
          <span className="px-1.5 py-0.5 rounded-full bg-white/20 text-[10px] font-mono">
            Copilot
          </span>
        </button>
      )}

      {/* Floating Chat Drawer */}
      {isOpen && (
        <div className="w-[420px] max-w-[95vw] h-[580px] max-h-[85vh] flex flex-col rounded-2xl bg-navy-900 border border-navy-700 shadow-2xl overflow-hidden animate-slide-in">
          {/* Header */}
          <div className="px-4 py-3 bg-navy-850 border-b border-navy-700 flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <div className="w-7 h-7 rounded-lg bg-accent-blue/20 border border-accent-blue/30 flex items-center justify-center">
                <Bot className="w-4 h-4 text-accent-cyan" />
              </div>
              <div>
                <h4 className="text-xs font-bold text-white flex items-center gap-1.5">
                  <span>PhishGuard AI Copilot</span>
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                </h4>
                <p className="text-[10px] text-slate-400">SOC Assistant & Resources</p>
              </div>
            </div>

            <div className="flex items-center gap-1">
              <button
                onClick={handleClear}
                title="Clear current messages"
                className="p-1.5 rounded-lg text-slate-400 hover:text-amber-300 hover:bg-navy-800 transition-colors"
              >
                <RotateCcw className="w-3.5 h-3.5" />
              </button>

              <Link
                href="/ai-assistant"
                onClick={() => setIsOpen(false)}
                title="Open full page assistant"
                className="p-1.5 rounded-lg text-slate-400 hover:text-accent-cyan hover:bg-navy-800 transition-colors"
              >
                <Maximize2 className="w-3.5 h-3.5" />
              </Link>

              <button
                onClick={() => setIsOpen(false)}
                className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-navy-800 transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          </div>

          {/* Messages */}
          <div className="flex-1 overflow-y-auto p-4 space-y-4 text-xs">
            {(!session || session.messages.length === 0) && (
              <div className="py-6 text-center space-y-3">
                <div className="w-12 h-12 rounded-xl bg-accent-blue/15 border border-accent-blue/30 flex items-center justify-center mx-auto">
                  <Sparkles className="w-6 h-6 text-accent-cyan" />
                </div>
                <p className="text-xs font-semibold text-slate-200">How can I assist your investigation?</p>
                <p className="text-[11px] text-slate-400 px-4">
                  Ask anything about PhishGuard features, SPF/DKIM/DMARC, risk scoring, or external threat intel sources.
                </p>
                <div className="pt-2 flex flex-col gap-1.5 px-2">
                  {[
                    'PhishGuard kaisy kaam krta hy?',
                    'Explain SPF, DKIM & DMARC in detail',
                    'Recommend external threat intel tools & sandboxes',
                  ].map((chip, i) => (
                    <button
                      key={i}
                      onClick={() => {
                        setInputMessage(chip)
                        // Trigger send
                        setTimeout(() => {
                          const form = document.getElementById('floating-chat-form') as HTMLFormElement
                          form?.requestSubmit()
                        }, 50)
                      }}
                      className="p-2 rounded-lg bg-navy-850 hover:bg-navy-800 border border-navy-700/80 text-left text-[11px] text-slate-300 hover:text-accent-cyan transition-colors"
                    >
                      💡 {chip}
                    </button>
                  ))}
                </div>
              </div>
            )}

            {session?.messages.map((m) => {
              const isAssistant = m.sender === 'assistant'
              return (
                <div
                  key={m.id}
                  className={`flex gap-2.5 ${isAssistant ? '' : 'justify-end'}`}
                >
                  {isAssistant && (
                    <div className="w-6 h-6 rounded-md bg-accent-blue/20 border border-accent-blue/30 flex items-center justify-center shrink-0 mt-0.5">
                      <Bot className="w-3.5 h-3.5 text-accent-cyan" />
                    </div>
                  )}

                  <div className={`space-y-2 max-w-[85%] ${isAssistant ? 'w-full' : ''}`}>
                    <div
                      className={`p-3 rounded-xl ${
                        isAssistant
                          ? 'bg-navy-800 border border-navy-700/90 text-slate-200'
                          : 'bg-accent-blue text-white'
                      }`}
                    >
                      {isAssistant ? (
                        <MarkdownContent content={m.content} />
                      ) : (
                        <p className="whitespace-pre-wrap">{m.content}</p>
                      )}

                      {/* Sources if any */}
                      {isAssistant && m.sources && m.sources.length > 0 && (
                        <div className="mt-3 pt-2.5 border-t border-navy-700 space-y-1.5">
                          <span className="text-[10px] font-semibold text-accent-cyan flex items-center gap-1">
                            <Globe className="w-3 h-3" /> External Sources:
                          </span>
                          {m.sources.slice(0, 3).map((s, idx) => (
                            <ResourceCard key={idx} resource={s} compact={true} />
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              )
            })}

            {isLoading && (
              <div className="flex gap-2">
                <div className="w-6 h-6 rounded-md bg-accent-blue/20 border border-accent-blue/30 flex items-center justify-center shrink-0">
                  <Bot className="w-3.5 h-3.5 text-accent-cyan" />
                </div>
                <div className="p-3 rounded-xl bg-navy-800 border border-navy-700 text-[11px] text-slate-400 flex items-center gap-2">
                  <span className="animate-pulse">Thinking & analyzing...</span>
                </div>
              </div>
            )}

            <div ref={messagesEndRef} />
          </div>

          {/* Input Footer */}
          <form
            id="floating-chat-form"
            onSubmit={handleSend}
            className="p-3 bg-navy-850 border-t border-navy-700 flex items-center gap-2"
          >
            <input
              type="text"
              placeholder="Ask a question..."
              value={inputMessage}
              onChange={(e) => setInputMessage(e.target.value)}
              className="flex-1 px-3 py-2 rounded-xl bg-navy-950 border border-navy-700 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-accent-cyan transition-colors"
            />
            <button
              type="submit"
              disabled={!inputMessage.trim() || isLoading}
              className={`p-2 rounded-xl text-white transition-all ${
                inputMessage.trim() && !isLoading
                  ? 'bg-accent-blue hover:bg-blue-600'
                  : 'bg-navy-800 text-slate-600 cursor-not-allowed'
              }`}
            >
              <Send className="w-4 h-4" />
            </button>
          </form>
        </div>
      )}
    </div>
  )
}
