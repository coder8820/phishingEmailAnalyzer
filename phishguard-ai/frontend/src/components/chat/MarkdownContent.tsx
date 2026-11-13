'use client'

import React, { useState } from 'react'
import { Copy, Check, ExternalLink } from 'lucide-react'

interface MarkdownContentProps {
  content: string
}

export function MarkdownContent({ content }: MarkdownContentProps) {
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null)

  const copyToClipboard = (text: string, index: number) => {
    navigator.clipboard.writeText(text)
    setCopiedIndex(index)
    setTimeout(() => setCopiedIndex(null), 2000)
  }

  // Pre-process code blocks
  const parts = content.split(/(```[\s\S]*?```)/g)

  let codeBlockCounter = 0

  return (
    <div className="space-y-3 text-sm leading-relaxed text-slate-200">
      {parts.map((part, pIdx) => {
        if (part.startsWith('```') && part.endsWith('```')) {
          const currentIndex = codeBlockCounter++
          const lines = part.slice(3, -3).trim().split('\n')
          const language = lines[0].match(/^[a-zA-Z0-9_-]+$/) ? lines[0] : ''
          const code = (language ? lines.slice(1) : lines).join('\n')

          return (
            <div
              key={pIdx}
              className="my-3 rounded-xl border border-navy-600/80 bg-navy-950 overflow-hidden shadow-md"
            >
              <div className="flex items-center justify-between px-3.5 py-1.5 bg-navy-900 border-b border-navy-700/60 text-xs font-mono text-slate-400">
                <span>{language || 'text'}</span>
                <button
                  type="button"
                  onClick={() => copyToClipboard(code, currentIndex)}
                  className="flex items-center gap-1.5 px-2 py-0.5 rounded hover:bg-navy-800 hover:text-slate-200 transition-colors"
                >
                  {copiedIndex === currentIndex ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-green-400" />
                      <span className="text-green-400">Copied</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5" />
                      <span>Copy</span>
                    </>
                  )}
                </button>
              </div>
              <pre className="p-3.5 overflow-x-auto text-xs font-mono text-cyan-300 leading-relaxed">
                <code>{code}</code>
              </pre>
            </div>
          )
        }

        return <TextBlock key={pIdx} text={part} />
      })}
    </div>
  )
}

function TextBlock({ text }: { text: string }) {
  const lines = text.split('\n')
  const elements: React.ReactNode[] = []

  let inTable = false
  let tableHeader: string[] = []
  let tableRows: string[][] = []

  const flushTable = (key: string) => {
    if (inTable && tableHeader.length > 0) {
      elements.push(
        <div key={key} className="my-3 overflow-x-auto rounded-lg border border-navy-600 shadow-sm">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="bg-navy-800/90 border-b border-navy-600 text-slate-300">
                {tableHeader.map((h, i) => (
                  <th key={i} className="px-3.5 py-2.5 font-semibold">
                    <InlineFormatted text={h} />
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-navy-700/50 bg-navy-900/60">
              {tableRows.map((row, rIdx) => (
                <tr key={rIdx} className="hover:bg-navy-800/40 transition-colors">
                  {row.map((cell, cIdx) => (
                    <td key={cIdx} className="px-3.5 py-2.5 text-slate-300">
                      <InlineFormatted text={cell} />
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )
    }
    inTable = false
    tableHeader = []
    tableRows = []
  }

  lines.forEach((line, index) => {
    const trimmed = line.trim()

    // Detect Markdown Table
    if (trimmed.startsWith('|') && trimmed.endsWith('|')) {
      const cells = trimmed
        .slice(1, -1)
        .split('|')
        .map((c) => c.trim())

      // Skip separator line (|---|---|)
      if (cells.every((c) => /^:?-+:?$/.test(c))) {
        inTable = true
        return
      }

      if (!inTable) {
        tableHeader = cells
        inTable = true
      } else {
        tableRows.push(cells)
      }
      return
    } else if (inTable) {
      flushTable(`table-${index}`)
    }

    if (!trimmed) {
      return
    }

    // Headings
    if (trimmed.startsWith('#### ')) {
      elements.push(
        <h4 key={index} className="text-sm font-semibold text-accent-cyan mt-3 mb-1">
          <InlineFormatted text={trimmed.slice(5)} />
        </h4>
      )
    } else if (trimmed.startsWith('### ')) {
      elements.push(
        <h3 key={index} className="text-base font-bold text-white mt-4 mb-1.5 flex items-center gap-2">
          <InlineFormatted text={trimmed.slice(4)} />
        </h3>
      )
    } else if (trimmed.startsWith('## ')) {
      elements.push(
        <h2 key={index} className="text-lg font-bold text-white mt-5 mb-2">
          <InlineFormatted text={trimmed.slice(3)} />
        </h2>
      )
    } else if (trimmed.startsWith('# ')) {
      elements.push(
        <h1 key={index} className="text-xl font-extrabold text-white mt-6 mb-2">
          <InlineFormatted text={trimmed.slice(2)} />
        </h1>
      )
    }
    // Blockquote
    else if (trimmed.startsWith('> ')) {
      elements.push(
        <blockquote
          key={index}
          className="pl-3.5 py-1 border-l-2 border-accent-blue/70 bg-accent-blue/5 text-slate-300 italic text-xs rounded-r my-2"
        >
          <InlineFormatted text={trimmed.slice(2)} />
        </blockquote>
      )
    }
    // Bullet list
    else if (/^[-*]\s+/.test(trimmed)) {
      elements.push(
        <div key={index} className="flex items-start gap-2.5 my-1 pl-1">
          <span className="w-1.5 h-1.5 rounded-full bg-accent-cyan shrink-0 mt-2" />
          <div className="flex-1">
            <InlineFormatted text={trimmed.replace(/^[-*]\s+/, '')} />
          </div>
        </div>
      )
    }
    // Numbered list
    else if (/^\d+\.\s+/.test(trimmed)) {
      const match = trimmed.match(/^(\d+)\.\s+(.*)/)
      if (match) {
        elements.push(
          <div key={index} className="flex items-start gap-2.5 my-1 pl-1">
            <span className="text-xs font-mono font-bold text-accent-blue shrink-0 mt-0.5">
              {match[1]}.
            </span>
            <div className="flex-1">
              <InlineFormatted text={match[2]} />
            </div>
          </div>
        )
      }
    }
    // Paragraph
    else {
      elements.push(
        <p key={index} className="my-1.5">
          <InlineFormatted text={trimmed} />
        </p>
      )
    }
  })

  if (inTable) {
    flushTable('table-end')
  }

  return <>{elements}</>
}

function InlineFormatted({ text }: { text: string }) {
  // Regex pattern for Links, Bold, and Inline Code
  const pattern = /(\[.*?\]\(https?:\/\/[^\s)]+\)|\*\*.*?\*\*|`[^`]+`)/g
  const parts = text.split(pattern)

  return (
    <>
      {parts.map((segment, idx) => {
        // Link [Title](URL)
        const linkMatch = segment.match(/^\[(.*?)\]\((https?:\/\/[^\s)]+)\)$/)
        if (linkMatch) {
          return (
            <a
              key={idx}
              href={linkMatch[2]}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-0.5 text-accent-cyan hover:text-cyan-300 underline underline-offset-2 font-medium transition-colors"
            >
              <span>{linkMatch[1]}</span>
              <ExternalLink className="w-3 h-3 ml-0.5 inline shrink-0" />
            </a>
          )
        }

        // Bold **text**
        if (segment.startsWith('**') && segment.endsWith('**')) {
          return (
            <strong key={idx} className="font-semibold text-slate-100">
              {segment.slice(2, -2)}
            </strong>
          )
        }

        // Inline code `code`
        if (segment.startsWith('`') && segment.endsWith('`')) {
          return (
            <code
              key={idx}
              className="px-1.5 py-0.5 rounded bg-navy-950 border border-navy-700 font-mono text-[11px] text-cyan-300"
            >
              {segment.slice(1, -1)}
            </code>
          )
        }

        return <span key={idx}>{segment}</span>
      })}
    </>
  )
}
