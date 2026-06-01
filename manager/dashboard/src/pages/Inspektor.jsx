import { useState, useEffect, useRef, useCallback } from 'react'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { useInspektor } from '../context/InspektorContext'
import { mdComponents, timeAgo } from '../components/InspektorMarkdown'
import { exportReportToPdf } from '../inspektorPdf'

export default function Inspektor() {
  const { messages, busy, error, lastMeta, send, runReport, clearChat, markActive } = useInspektor()
  const [input, setInput] = useState('')
  const scrollRef = useRef(null)
  const inputRef = useRef(null)

  // Mark the conversation as actively watched while this page is mounted and
  // the tab is visible — this resets the unread badge and suppresses notifs.
  useEffect(() => {
    const sync = () => markActive(!document.hidden)
    sync()
    document.addEventListener('visibilitychange', sync)
    return () => {
      document.removeEventListener('visibilitychange', sync)
      markActive(false)
    }
  }, [markActive])

  // Keep the view pinned to the latest message
  useEffect(() => {
    const el = scrollRef.current
    if (el) el.scrollTop = el.scrollHeight
  }, [messages, busy])

  const onSend = useCallback(() => {
    const text = input.trim()
    if (!text || busy) return
    setInput('')
    send(text)
    inputRef.current?.focus()
  }, [input, busy, send])

  const onKeyDown = e => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      onSend()
    }
  }

  const isEmpty = messages.length <= 1 && messages[0]?.id === 'intro'

  return (
    <div className="flex flex-col h-[calc(100vh-2rem)] sm:h-[calc(100vh-3rem)] animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between gap-3 mb-4 shrink-0">
        <div className="flex items-center gap-3 min-w-0">
          <div className="relative flex items-center justify-center w-11 h-11 rounded-xl bg-gradient-to-br from-accent/25 to-accent/5 ring-1 ring-accent/30 text-accent shrink-0">
            <InspektorGlyph />
            <span
              className={`absolute -bottom-0.5 -right-0.5 w-3 h-3 rounded-full ring-2 ring-surface ${
                busy ? 'bg-verdict-suspicious animate-pulse' : 'bg-verdict-benign'
              }`}
            />
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <h1 className="text-xl font-semibold text-text-primary tracking-tight">Inspektor</h1>
              <span className="text-[9px] font-semibold uppercase tracking-wider px-1.5 py-0.5 rounded bg-accent/15 text-accent">
                AI Analyst
              </span>
            </div>
            <span className="text-[11px] text-text-muted">
              {busy
                ? 'Reading the hive…'
                : lastMeta?.generated_at
                  ? `Last briefing ${timeAgo(lastMeta.generated_at)}`
                  : 'AI threat analyst — on demand'}
            </span>
          </div>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <button
            onClick={clearChat}
            disabled={busy || isEmpty}
            title="Clear conversation"
            className="inline-flex items-center gap-2 px-3 py-2 rounded-lg bg-surface-tertiary text-text-secondary hover:text-verdict-malicious hover:bg-verdict-malicious/10 text-sm font-semibold transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
          >
            <TrashIcon />
            <span className="hidden sm:inline">Clear</span>
          </button>
          <button
            onClick={runReport}
            disabled={busy}
            className="inline-flex items-center gap-2 px-3.5 py-2 rounded-lg bg-accent/15 text-accent hover:bg-accent/25 text-sm font-semibold transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <ReportIcon />
            <span className="hidden sm:inline">Generate report</span>
            <span className="sm:hidden">Report</span>
          </button>
        </div>
      </div>

      {/* Chat stream */}
      <div
        ref={scrollRef}
        className="glass-card flex-1 overflow-y-auto p-4 sm:p-6 space-y-5 min-h-0 scroll-smooth"
      >
        {messages.map(m => (
          <Message key={m.id} msg={m} onExport={exportReportToPdf} />
        ))}

        {busy && (
          <div className="flex items-center gap-2.5 text-text-muted text-sm">
            <span className="flex items-center justify-center w-7 h-7 rounded-lg bg-accent/15 text-accent shrink-0">
              <InspektorGlyph size={15} />
            </span>
            <span className="flex gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-accent animate-bounce" style={{ animationDelay: '0ms' }} />
              <span className="w-1.5 h-1.5 rounded-full bg-accent animate-bounce" style={{ animationDelay: '150ms' }} />
              <span className="w-1.5 h-1.5 rounded-full bg-accent animate-bounce" style={{ animationDelay: '300ms' }} />
            </span>
            <span className="text-xs">Inspektor is reading the hive… you can keep browsing.</span>
          </div>
        )}

        {error && (
          <div className="text-xs text-verdict-malicious bg-verdict-malicious/10 border border-verdict-malicious/20 rounded-lg px-3 py-2">
            {error}
          </div>
        )}
      </div>

      {/* Composer */}
      <div className="mt-4 shrink-0">
        <div className="glass-card flex items-end gap-2 p-2 focus-within:ring-1 focus-within:ring-accent/40 transition-shadow">
          <textarea
            ref={inputRef}
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={onKeyDown}
            rows={1}
            placeholder="Ask Inspektor about attackers, alerts, kill-chains…"
            className="flex-1 resize-none bg-transparent px-3 py-2 text-sm text-text-primary placeholder:text-text-muted outline-none max-h-32"
          />
          <button
            onClick={onSend}
            disabled={busy || !input.trim()}
            className="shrink-0 inline-flex items-center justify-center w-9 h-9 rounded-lg bg-accent text-white hover:bg-accent-hover transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
            aria-label="Send"
          >
            <SendIcon />
          </button>
        </div>
        <p className="text-[10px] text-text-muted mt-1.5 px-1">
          Inspektor runs only when you ask — leave the page while it thinks, you'll get a notification when it answers.
        </p>
      </div>
    </div>
  )
}

// A single chat bubble (user or assistant; assistant reports get a PDF action)
function Message({ msg, onExport }) {
  const isUser = msg.role === 'user'
  if (isUser) {
    return (
      <div className="flex justify-end">
        <div className="max-w-[85%] rounded-2xl rounded-br-sm bg-accent/15 text-text-primary px-4 py-2.5 text-sm whitespace-pre-wrap">
          {msg.content}
        </div>
      </div>
    )
  }
  return (
    <div className="flex gap-3">
      <span className="flex items-center justify-center w-7 h-7 rounded-lg bg-accent/15 text-accent shrink-0 mt-0.5">
        <InspektorGlyph size={15} />
      </span>
      <div className="min-w-0 flex-1">
        {msg.kind === 'report' && (
          <div className="flex items-center justify-between gap-2 mb-2">
            <span className="text-[10px] font-semibold uppercase tracking-wider text-text-muted">
              Threat briefing
              {msg.meta?.threats_analyzed != null ? ` · ${msg.meta.threats_analyzed} threats` : ''}
            </span>
            <button
              onClick={() => onExport(msg.content, msg.meta || {})}
              className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-surface-tertiary hover:bg-surface-hover text-text-secondary hover:text-text-primary text-[11px] font-semibold transition-colors"
            >
              <PdfIcon />
              Export PDF
            </button>
          </div>
        )}
        <div
          className={`max-w-none ${
            msg.kind === 'report'
              ? 'glass-card p-4 border border-border/50'
              : 'rounded-2xl rounded-bl-sm bg-surface-tertiary/50 px-4 py-2.5'
          }`}
        >
          <ReactMarkdown remarkPlugins={[remarkGfm]} components={mdComponents}>
            {msg.content}
          </ReactMarkdown>
        </div>
      </div>
    </div>
  )
}

// Inspektor brand glyph: a magnifier with a check, matching the navbar item
function InspektorGlyph({ size = 20 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="10.5" cy="10.5" r="6.5" />
      <path d="m20 20-4.5-4.5" />
      <path d="m8 10.5 1.8 1.8L13 9" />
    </svg>
  )
}

function ReportIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
      <path d="M14 2v6h6M8 13h8M8 17h8M8 9h2" />
    </svg>
  )
}

function TrashIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M3 6h18M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2m3 0v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6" />
      <line x1="10" y1="11" x2="10" y2="17" />
      <line x1="14" y1="11" x2="14" y2="17" />
    </svg>
  )
}

function SendIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M22 2 11 13M22 2l-7 20-4-9-9-4 20-7z" />
    </svg>
  )
}

function PdfIcon() {
  return (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
      <path d="M14 2v6h6" />
      <path d="M9 15h6M9 18h3" />
    </svg>
  )
}
