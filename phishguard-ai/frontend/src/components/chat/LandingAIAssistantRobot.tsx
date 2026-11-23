'use client'

import React, { useState, useEffect, useRef } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import Link from 'next/link'
import {
  Sparkles,
  X,
  Send,
  Shield,
  ArrowRight,
  Maximize2,
  RotateCcw,
  Bot,
  ExternalLink,
  HelpCircle,
  Zap,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { useAuthStore } from '@/store/authStore'
import { chatService, ChatSessionDetail } from '@/services/chatService'

const PROMPT_SUGGESTIONS = [
  'How do I detect a phishing email?',
  'Explain SPF, DKIM & DMARC in simple terms',
  'What is a BEC (Business Email Compromise) attack?',
  'How does PhishGuard analyze .eml files?',
]

const PROACTIVE_MESSAGES = [
  {
    title: 'Need Email Inspection?',
    text: 'Psst! Received a suspicious email? Ask me how to extract headers & spot spoofing!',
    chip: 'Ask Assistant',
  },
  {
    title: 'Active SOC Defense',
    text: 'I can explain SPF, DKIM & DMARC alignment rules or analyze threat indicators for you.',
    chip: 'Explain Protocols',
  },
  {
    title: 'AI Threat Sandbox',
    text: 'Want to test our sandbox? Upload an .eml file or try our interactive demo scenarios!',
    chip: 'Explore Demo',
  },
  {
    title: 'Security Tip',
    text: 'Attackers love lookalike domains (typosquatting). Always check the raw Return-Path header!',
    chip: 'Learn More',
  },
]

interface Message {
  id: string
  sender: 'user' | 'assistant'
  text: string
  timestamp: string
}

export function LandingAIAssistantRobot() {
  const { isAuthenticated } = useAuthStore()
  const [isOpen, setIsOpen] = useState(false)
  const [showSpeechBubble, setShowSpeechBubble] = useState(false)
  const [bubbleIndex, setBubbleIndex] = useState(0)
  const [isWiggling, setIsWiggling] = useState(false)
  const [messages, setMessages] = useState<Message[]>([
    {
      id: 'welcome',
      sender: 'assistant',
      text: "👋 Hi there! I'm your **PhishGuard AI Assistant**. Ask me anything about phishing detection, email header analysis, or how our sandbox protects your organization.",
      timestamp: 'Just now',
    },
  ])
  const [inputValue, setInputValue] = useState('')
  const [isTyping, setIsTyping] = useState(false)
  const [chatSession, setChatSession] = useState<ChatSessionDetail | null>(null)
  const messagesEndRef = useRef<HTMLDivElement>(null)

  // Auto-scroll chat window
  useEffect(() => {
    if (isOpen) {
      messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
    }
  }, [messages, isOpen, isTyping])

  // --- ATTRACT USER: Trigger Robot Movement Every 1 Minute (60 seconds) ---
  useEffect(() => {
    // Initial friendly greeting after 4 seconds
    const initialGreetingTimeout = setTimeout(() => {
      triggerAttentionAnimation()
    }, 4000)

    // Repeat every 1 minute (60,000 ms)
    const interval = setInterval(() => {
      triggerAttentionAnimation()
    }, 60000)

    function triggerAttentionAnimation() {
      // Don't interrupt if chat dialog is already open
      setIsOpen((currentlyOpen) => {
        if (!currentlyOpen) {
          setIsWiggling(true)
          setShowSpeechBubble(true)
          setBubbleIndex((prev) => (prev + 1) % PROACTIVE_MESSAGES.length)

          // Wiggle lasts 1.4s
          setTimeout(() => setIsWiggling(false), 1400)

          // Bubble auto-hides after 8 seconds
          setTimeout(() => {
            setShowSpeechBubble(false)
          }, 8500)
        }
        return currentlyOpen
      })
    }

    return () => {
      clearTimeout(initialGreetingTimeout)
      clearInterval(interval)
    }
  }, [])

  // Send message handler
  const handleSendMessage = async (textToSend?: string) => {
    const text = (textToSend || inputValue).trim()
    if (!text || isTyping) return

    setInputValue('')
    setShowSpeechBubble(false)

    const userMsg: Message = {
      id: String(Date.now()),
      sender: 'user',
      text,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    }
    setMessages((prev) => [...prev, userMsg])
    setIsTyping(true)

    // If authenticated, try real backend chat assistant
    if (isAuthenticated) {
      try {
        let session = chatSession
        if (!session) {
          session = await chatService.createSession('Landing Assistant Chat')
          setChatSession(session)
        }
        const response = await chatService.sendMessage(session.id, text)
        const botMsg: Message = {
          id: response.id || String(Date.now() + 1),
          sender: 'assistant',
          text: response.content,
          timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        }
        setMessages((prev) => [...prev, botMsg])
        setIsTyping(false)
        return
      } catch {
        // Fallback to local intelligence if backend session fails
      }
    }

    // Interactive built-in security intelligence for guest landing visitors
    setTimeout(() => {
      const lower = text.toLowerCase()
      let reply = ''

      if (lower.includes('spf') || lower.includes('dkim') || lower.includes('dmarc')) {
        reply =
          "🛡️ **Email Authentication Trio Explained:**\n\n" +
          "• **SPF (Sender Policy Framework):** Publishes authorized sending mail servers in DNS. If the transmitting IP isn't listed, SPF fails.\n" +
          "• **DKIM (DomainKeys Identified Mail):** Signs emails with a private cryptographic key verified by public DNS key to ensure no message tampering.\n" +
          "• **DMARC:** Defines what to do (`none`, `quarantine`, `reject`) when SPF/DKIM don't match the human-visible 'From' domain."
      } else if (lower.includes('bec') || lower.includes('compromise') || lower.includes('fraud')) {
        reply =
          "⚠️ **Business Email Compromise (BEC):**\n\n" +
          "Attackers often bypass anti-spam filters by sending text-only emails impersonating executives, suppliers, or attorneys. Common indicators include:\n" +
          "1. Urgent requests for wire transfers or invoice bank detail changes.\n" +
          "2. Cousin/typosquatted domains (e.g., `micros0ft.com` or `paypa1.com`).\n" +
          "3. Mismatched `Reply-To` and `Return-Path` headers."
      } else if (lower.includes('how') && (lower.includes('analyze') || lower.includes('eml') || lower.includes('upload'))) {
        reply =
          "📂 **How PhishGuard Analyzes .eml Files:**\n\n" +
          "1. **Header Forensics:** Parses all hops, timestamps, authentication headers (SPF/DKIM/DMARC).\n" +
          "2. **URL Intelligence:** De-obfuscates redirect chains, punycode, and checks live threat feeds (URLhaus, VirusTotal).\n" +
          "3. **Attachment Safety:** Inspects binary magic bytes to detect disguised malware.\n" +
          "4. **AI Risk Scoring:** Evaluates psychological coercion and generates an explainable 0–100 threat score."
      } else if (lower.includes('detect') || lower.includes('spot') || lower.includes('phishing')) {
        reply =
          "🔍 **Key Indicators to Spot Phishing:**\n\n" +
          "• **Artificial Urgency:** 'Account suspended in 24 hours!'\n" +
          "• **Sender Domain Discrepancy:** The display name says 'PayPal' but the domain is `@billing-portal-update.net`.\n" +
          "• **Hidden Links:** Hovering reveals the destination URL doesn't match the anchor text.\n" +
          "• **Suspicious Attachments:** `.iso`, `.vbs`, double-extension files like `invoice.pdf.exe`."
      } else {
        reply =
          `I received your query: "${text}".\n\n` +
          "As your SOC Security Copilot, I recommend trying our interactive email analysis sandbox above, or creating a free analyst account to test full `.eml` parsing and real-time Gmail quarantine!"
      }

      const botMsg: Message = {
        id: String(Date.now() + 1),
        sender: 'assistant',
        text: reply,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      }
      setMessages((prev) => [...prev, botMsg])
      setIsTyping(false)
    }, 750)
  }

  const currentBubble = PROACTIVE_MESSAGES[bubbleIndex]

  return (
    <>
      {/* ─────────────────────────────────────────────────────────────────────────────
          1. FLOATING ANIMATED ROBOT & ATTRACTOR BUBBLE (Fixed Bottom-Right)
          ───────────────────────────────────────────────────────────────────────────── */}
      <div className="fixed bottom-6 right-6 z-40 flex flex-col items-end pointer-events-auto select-none">
        {/* Proactive Speech Bubble (Pops up every 1 min) */}
        <AnimatePresence>
          {showSpeechBubble && !isOpen && (
            <motion.div
              initial={{ opacity: 0, y: 12, scale: 0.9 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, y: 8, scale: 0.9 }}
              transition={{ duration: 0.25 }}
              onClick={() => {
                setIsOpen(true)
                setShowSpeechBubble(false)
              }}
              className="mb-3 max-w-[270px] p-3 rounded-2xl bg-navy-850/95 border border-accent-cyan/40 backdrop-blur-xl shadow-2xl shadow-cyan-500/15 cursor-pointer text-left group"
            >
              <div className="flex items-center justify-between mb-1">
                <span className="text-[10px] font-mono uppercase text-accent-cyan flex items-center gap-1 font-semibold">
                  <span className="w-1.5 h-1.5 rounded-full bg-accent-cyan animate-pulse" />
                  {currentBubble.title}
                </span>
                <button
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation()
                    setShowSpeechBubble(false)
                  }}
                  className="text-slate-400 hover:text-white p-0.5 rounded transition-colors"
                >
                  <X className="w-3 h-3" />
                </button>
              </div>
              <p className="text-xs text-slate-200 leading-snug">{currentBubble.text}</p>
              <div className="mt-2 flex items-center justify-between text-[11px] font-medium text-accent-cyan group-hover:text-cyan-300">
                <span>{currentBubble.chip} →</span>
                <span className="text-[10px] text-slate-500 font-mono">Click robot</span>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Robot Button / Trigger */}
        <div className="relative group">
          {/* Subtle Cyber Glow Ring */}
          <div className="absolute -inset-1 rounded-full bg-gradient-to-r from-accent-cyan via-accent-blue to-cyan-500 opacity-60 blur-md group-hover:opacity-100 transition-opacity animate-pulse-slow" />

          {/* Periodic 1-min Ripple Wave Ping */}
          {isWiggling && (
            <span className="absolute -inset-2 rounded-full border-2 border-accent-cyan/80 animate-ping pointer-events-none" />
          )}

          {/* Animated Robot Avatar Container */}
          <motion.button
            type="button"
            onClick={() => {
              setIsOpen(!isOpen)
              setShowSpeechBubble(false)
            }}
            animate={
              isWiggling
                ? {
                    y: [0, -14, 2, -10, 0],
                    rotate: [0, -16, 16, -10, 10, 0],
                    scale: [1, 1.15, 1.05, 1.12, 1],
                  }
                : {
                    y: [0, -6, 0],
                  }
            }
            transition={
              isWiggling
                ? { duration: 1.2, ease: 'easeInOut' }
                : { duration: 2.5, repeat: Infinity, ease: 'easeInOut' }
            }
            className={cn(
              'relative w-14 h-14 sm:w-16 sm:h-16 rounded-2xl flex items-center justify-center',
              'bg-gradient-to-b from-navy-800 to-navy-900 border border-accent-cyan/50',
              'shadow-xl shadow-cyan-500/20 hover:border-accent-cyan transition-colors',
              'focus:outline-none focus:ring-2 focus:ring-accent-cyan/60'
            )}
            title="PhishGuard AI Assistant — Click to Chat"
            aria-label="Open AI Assistant"
          >
            {/* --- SVG HIGH-TECH CYBER ROBOT --- */}
            <svg
              viewBox="0 0 64 64"
              className="w-10 h-10 sm:w-11 sm:h-11 drop-shadow-[0_0_8px_rgba(6,182,212,0.6)]"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
            >
              {/* Antenna Stem */}
              <line x1="32" y1="12" x2="32" y2="4" stroke="#06b6d4" strokeWidth="2.5" strokeLinecap="round" />
              {/* Antenna Glowing Orb */}
              <circle cx="32" cy="4" r="3" fill="#38bdf8" />
              <circle cx="32" cy="4" r="5" stroke="#06b6d4" strokeWidth="1" opacity="0.6" />

              {/* Robot Head */}
              <rect x="14" y="12" width="36" height="26" rx="8" fill="#0d1b2a" stroke="#06b6d4" strokeWidth="2" />

              {/* Ears / Side Screws */}
              <rect x="10" y="20" width="4" height="10" rx="2" fill="#3b82f6" />
              <rect x="50" y="20" width="4" height="10" rx="2" fill="#3b82f6" />

              {/* Visor / Eye Screen */}
              <rect x="19" y="18" width="26" height="14" rx="4" fill="#050a14" stroke="#1e293b" strokeWidth="1" />

              {/* Cyan Digital Eyes (Blinking / Scanning) */}
              <circle cx="26" cy="25" r="3.2" fill="#06b6d4">
                <animate attributeName="opacity" values="1;0.2;1" dur="3s" repeatCount="indefinite" />
              </circle>
              <circle cx="38" cy="25" r="3.2" fill="#06b6d4">
                <animate attributeName="opacity" values="1;0.2;1" dur="3s" repeatCount="indefinite" />
              </circle>

              {/* Subtle Mouth Line / Voice Visualizer */}
              <line x1="28" y1="34" x2="36" y2="34" stroke="#38bdf8" strokeWidth="1.5" strokeLinecap="round" />

              {/* Neck */}
              <rect x="28" y="38" width="8" height="3" rx="1" fill="#1e293b" />

              {/* Torso / Body */}
              <path
                d="M18 41C18 41 20 40 32 40C44 40 46 41 46 41L49 53C49 55 47 56 45 56H19C17 56 15 55 15 53L18 41Z"
                fill="#0d1b2a"
                stroke="#3b82f6"
                strokeWidth="1.8"
              />

              {/* Central Power Arc / Shield Core */}
              <polygon points="32,44 36,48 32,52 28,48" fill="#06b6d4">
                <animate attributeName="fill" values="#06b6d4;#38bdf8;#06b6d4" dur="1.8s" repeatCount="indefinite" />
              </polygon>

              {/* Hover Thruster Glow Flame */}
              <ellipse cx="32" cy="59" rx="6" ry="2" fill="#06b6d4" opacity="0.8">
                <animate attributeName="rx" values="6;8;6" dur="0.8s" repeatCount="indefinite" />
                <animate attributeName="opacity" values="0.8;0.3;0.8" dur="0.8s" repeatCount="indefinite" />
              </ellipse>
            </svg>

            {/* Notification Badge if bubble is active */}
            {showSpeechBubble && (
              <span className="absolute -top-1 -right-1 flex h-3.5 w-3.5">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75" />
                <span className="relative inline-flex rounded-full h-3.5 w-3.5 bg-accent-cyan border border-navy-900" />
              </span>
            )}
          </motion.button>
        </div>
      </div>

      {/* ─────────────────────────────────────────────────────────────────────────────
          2. EXPANDED AI ASSISTANT CHAT DIALOG (Modal Popover)
          ───────────────────────────────────────────────────────────────────────────── */}
      <AnimatePresence>
        {isOpen && (
          <motion.div
            initial={{ opacity: 0, scale: 0.9, y: 20 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.9, y: 20 }}
            transition={{ duration: 0.2 }}
            className={cn(
              'fixed bottom-24 right-4 sm:right-6 z-50',
              'w-[calc(100vw-2rem)] sm:w-[410px] h-[520px] max-h-[80vh]',
              'flex flex-col rounded-2xl bg-navy-900/95 border border-navy-700/90 backdrop-blur-2xl',
              'shadow-2xl shadow-cyan-500/10 overflow-hidden'
            )}
          >
            {/* Header */}
            <div className="p-3.5 bg-navy-850/90 border-b border-navy-700/80 flex items-center justify-between">
              <div className="flex items-center gap-2.5">
                <div className="w-8 h-8 rounded-lg bg-accent-cyan/15 border border-accent-cyan/40 flex items-center justify-center text-accent-cyan">
                  <Bot className="w-4 h-4" />
                </div>
                <div>
                  <h3 className="text-xs font-bold text-white flex items-center gap-1.5">
                    <span>PhishGuard AI Assistant</span>
                    <span className="inline-block w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                  </h3>
                  <p className="text-[10px] text-slate-400 font-mono">SOC Threat Intelligence Copilot</p>
                </div>
              </div>

              <div className="flex items-center gap-1">
                <Link
                  href="/login"
                  title="Open Full Assistant in Console"
                  className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-navy-750 transition-colors"
                >
                  <Maximize2 className="w-3.5 h-3.5" />
                </Link>
                <button
                  type="button"
                  onClick={() => setIsOpen(false)}
                  className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-navy-750 transition-colors"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
            </div>

            {/* Quick Suggestion Chips */}
            <div className="p-2 bg-navy-950/60 border-b border-navy-800 flex items-center gap-1.5 overflow-x-auto no-scrollbar text-[11px]">
              <span className="text-[10px] text-slate-500 font-mono pl-1 flex items-center gap-1 flex-shrink-0">
                <Zap className="w-3 h-3 text-accent-cyan" /> Suggested:
              </span>
              {PROMPT_SUGGESTIONS.map((sug, i) => (
                <button
                  key={i}
                  type="button"
                  onClick={() => handleSendMessage(sug)}
                  className="px-2.5 py-1 rounded-full bg-navy-800 hover:bg-navy-700 text-slate-300 hover:text-white border border-navy-700 hover:border-accent-cyan/40 flex-shrink-0 transition-colors text-[10px]"
                >
                  {sug}
                </button>
              ))}
            </div>

            {/* Messages Feed */}
            <div className="flex-1 p-3.5 overflow-y-auto space-y-3 font-sans text-xs">
              {messages.map((m) => (
                <div
                  key={m.id}
                  className={cn('flex flex-col', m.sender === 'user' ? 'items-end' : 'items-start')}
                >
                  <div
                    className={cn(
                      'max-w-[85%] rounded-xl p-3 leading-relaxed',
                      m.sender === 'user'
                        ? 'bg-accent-blue text-white rounded-br-none shadow-md'
                        : 'bg-navy-800/90 text-slate-200 border border-navy-700/80 rounded-bl-none shadow-sm'
                    )}
                  >
                    <p className="whitespace-pre-line text-xs">{m.text}</p>
                  </div>
                  <span className="text-[9px] text-slate-500 mt-1 px-1 font-mono">{m.timestamp}</span>
                </div>
              ))}

              {isTyping && (
                <div className="flex items-center gap-2 text-slate-400 text-xs bg-navy-800/60 border border-navy-700/60 rounded-xl p-2.5 w-fit">
                  <Bot className="w-3.5 h-3.5 text-accent-cyan animate-spin" />
                  <span>AI Copilot is analyzing...</span>
                </div>
              )}
              <div ref={messagesEndRef} />
            </div>

            {/* Action Call to Action Banner inside dialog */}
            <div className="p-2 bg-navy-950/80 border-t border-navy-800/80 flex items-center justify-between text-xs">
              <span className="text-[11px] text-slate-400">Ready to inspect raw `.eml` files?</span>
              <Link
                href="/login"
                className="px-2.5 py-1 rounded bg-accent-blue/20 hover:bg-accent-blue/30 text-accent-cyan text-[11px] font-medium flex items-center gap-1 border border-accent-cyan/30 transition-colors"
              >
                <span>SOC Login</span>
                <ArrowRight className="w-3 h-3" />
              </Link>
            </div>

            {/* Input Footer */}
            <div className="p-2.5 bg-navy-850/90 border-t border-navy-700/80 flex items-center gap-2">
              <input
                type="text"
                value={inputValue}
                onChange={(e) => setInputValue(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault()
                    handleSendMessage()
                  }
                }}
                placeholder="Ask about phishing detection, SPF, DKIM..."
                className="flex-1 bg-navy-950/80 border border-navy-700 rounded-lg px-3 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-accent-cyan transition-colors"
              />
              <button
                type="button"
                onClick={() => handleSendMessage()}
                disabled={!inputValue.trim() || isTyping}
                className="p-2 rounded-lg bg-accent-cyan hover:bg-cyan-400 text-navy-950 font-semibold disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                title="Send Message"
              >
                <Send className="w-3.5 h-3.5" />
              </button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </>
  )
}
