import { useState, useEffect, useRef, useCallback } from 'react'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { fetchInspectorReport, generateInspectorReport, sendInspectorChat } from '../api'
import { mdComponents, timeAgo } from '../components/InspectorMarkdown'
import { exportReportToPdf } from '../inspectorPdf'

let _idSeq = 0
const nextId = () => `m${Date.now().toString(36)}-${++_idSeq}`

const STORAGE_KEY = 'melissae.inspector.chat'

const INTRO = {
  id: 'intro',
  role: 'assistant',
  kind: 'chat',
  content:
    "Hi, I'm **Inspector**, your AI threat analyst. Ask me anything about the honeypot network, or hit **Generate report** for a full threat briefing you can export to PDF.",
}

function loadStoredMessages() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (!raw) return null
    const parsed = JSON.parse(raw)
    if (Array.isArray(parsed) && parsed.length > 0) return parsed
  } catch {
    /* ignore corrupted storage */
  }
  return null
}

// Dedicated Inspector page: chat interface + on-demand report + PDF export
export default function Inspector() {
  const [messages, setMessages] = useState(() => loadStoredMessages() || [INTRO])
  const [input, setInput] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const [lastMeta, setLastMeta] = useState(null)
  const scrollRef = useRef(null)
  const inputRef = useRef(null)
  const restoredRef = useRef(loadStoredMessages() != null)

  useEffect(() => {
    if (restoredRef.current) return
    let cancelled = false
    fetchInspectorReport()
      .then(data => {
        if (cancelled || !data?.markdown) return
        setLastMeta(data)
        setMessages(prev => [
          ...prev,
          { id: nextId(), role: 'assistant', kind: 'report', content: data.markdown, meta: data },
        ])
      })
      .catch(() => {})
    return () => { cancelled = true }
  }, [])

  // Persist the conversation on every change
  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(messages))
    } catch {
    }
    // Track the most recent report for the header timestamp
    const lastReport = [...messages].reverse().find(m => m.kind === 'report')
    if (lastReport?.meta) setLastMeta(lastReport.meta)
  }, [messages])

  // Keep the view pinned to the latest message
  useEffect(() => {
    const el = scrollRef.current
    if (el) el.scrollTop = el.scrollHeight
  }, [messages, busy])

  // Reset the conversation back to a fresh state
  const clearChat = useCallback(() => {
    if (busy) return
    setMessages([INTRO])
    setLastMeta(null)
    setError(null)
    restoredRef.current = false
    try {
      localStorage.removeItem(STORAGE_KEY)
    } catch {
      /* ignore */
    }
    inputRef.current?.focus()
  }, [busy])

  const historyFor = useCallback(
    () =>
      messages
        .filter(m => m.role === 'user' || m.role === 'assistant')
        .map(m => ({ role: m.role, content: m.content })),
    [messages],
  )

  const send = useCallback(async () => {
    const text = input.trim()
    if (!text || busy) return
    setError(null)
    const userMsg = { id: nextId(), role: 'user', kind: 'chat', content: text }
    const history = historyFor()
    setMessages(prev => [...prev, userMsg])
    setInput('')
    setBusy(true)
    try {
      const data = await sendInspectorChat(text, history)
      setMessages(prev => [
        ...prev,
        { id: nextId(), role: 'assistant', kind: 'chat', content: data.reply || '(no answer)' },
      ])
    } catch (e) {
      setError(e.message)
    } finally {
      setBusy(false)
      inputRef.current?.focus()
    }
  }, [input, busy, historyFor])

  const runReport = useCallback(async () => {
    if (busy) return
    setError(null)
    setMessages(prev => [
      ...prev,
      { id: nextId(), role: 'user', kind: 'chat', content: '📋 Generate a full threat briefing' },
    ])
    setBusy(true)
    try {
      const data = await generateInspectorReport()
      setLastMeta(data)
      setMessages(prev => [
        ...prev,
        { id: nextId(), role: 'assistant', kind: 'report', content: data.markdown, meta: data },
      ])
    } catch (e) {
      setError(e.message)
    } finally {
      setBusy(false)
    }
  }, [busy])

  const onKeyDown = e => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      send()
    }
  }

  return (
    <div className="flex flex-col h-[calc(100vh-2rem)] sm:h-[calc(100vh-3rem)] animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between gap-3 mb-4 shrink-0">
        <div className="flex items-center gap-3 min-w-0">
          <div className="flex items-center justify-center w-10 h-10 rounded-xl bg-accent/15 text-accent text-lg font-bold shrink-0">
            I
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <h1 className="text-xl font-semibold text-text-primary tracking-tight">Inspector</h1>
              <span className="text-[9px] font-semibold uppercase tracking-wider px-1.5 py-0.5 rounded bg-accent/15 text-accent">
                AI Analyst
              </span>
            </div>
            <span className="text-[11px] text-text-muted">
              {lastMeta?.generated_at
                ? `Last briefing ${timeAgo(lastMeta.generated_at)}`
                : 'AI threat analyst — on demand'}
            </span>
          </div>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <button
            onClick={clearChat}
            disabled={busy || (messages.length <= 1 && messages[0]?.id === 'intro')}
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
        className="glass-card flex-1 overflow-y-auto p-4 sm:p-6 space-y-5 min-h-0"
      >
        {messages.map(m => (
          <Message key={m.id} msg={m} onExport={exportReportToPdf} />
        ))}

        {busy && (
          <div className="flex items-center gap-2 text-text-muted text-sm">
            <span className="flex items-center justify-center w-7 h-7 rounded-lg bg-accent/15 text-accent text-xs font-bold shrink-0">
              I
            </span>
            <span className="flex gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-accent animate-bounce" style={{ animationDelay: '0ms' }} />
              <span className="w-1.5 h-1.5 rounded-full bg-accent animate-bounce" style={{ animationDelay: '150ms' }} />
              <span className="w-1.5 h-1.5 rounded-full bg-accent animate-bounce" style={{ animationDelay: '300ms' }} />
            </span>
            <span className="text-xs">Inspector is thinking…</span>
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
        <div className="glass-card flex items-end gap-2 p-2">
          <textarea
            ref={inputRef}
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={onKeyDown}
            rows={1}
            placeholder="Ask Inspector about attackers, alerts, kill-chains…"
            className="flex-1 resize-none bg-transparent px-3 py-2 text-sm text-text-primary placeholder:text-text-muted outline-none max-h-32"
          />
          <button
            onClick={send}
            disabled={busy || !input.trim()}
            className="shrink-0 inline-flex items-center justify-center w-9 h-9 rounded-lg bg-accent text-white hover:bg-accent-hover transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
            aria-label="Send"
          >
            <SendIcon />
          </button>
        </div>
        <p className="text-[10px] text-text-muted mt-1.5 px-1">
          Inspector runs only when you ask — no automatic polling. Reports can be exported to PDF.
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
        <div className="max-w-[85%] rounded-2xl rounded-br-sm bg-accent/15 text-text-primary px-4 py-2.5 text-sm">
          {msg.content}
        </div>
      </div>
    )
  }
  return (
    <div className="flex gap-3">
      <span className="flex items-center justify-center w-7 h-7 rounded-lg bg-accent/15 text-accent text-xs font-bold shrink-0 mt-0.5">
        I
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
