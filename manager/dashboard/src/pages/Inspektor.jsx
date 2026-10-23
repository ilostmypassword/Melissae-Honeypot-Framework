import { useState, useEffect, useRef, useCallback } from 'react'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { useInspektor } from '../context/InspektorContext'
import { mdComponents, timeAgo } from '../components/InspektorMarkdown'
import { exportReportToPdf } from '../inspektorPdf'
import { fetchInspektorStatus } from '../api'

export default function Inspektor() {
  const { messages, busy, error, lastMeta, send, runReport, clearChat, markActive } = useInspektor()
  const [input, setInput] = useState('')
  const scrollRef = useRef(null)
  const inputRef = useRef(null)

  const [status, setStatus] = useState(null)
  const [statusLoading, setStatusLoading] = useState(true)

  const checkStatus = useCallback(() => {
    setStatusLoading(true)
    return fetchInspektorStatus()
      .then(setStatus)
      .catch(() => setStatus({ enabled: false, ready: false, configured: false }))
      .finally(() => setStatusLoading(false))
  }, [])

  useEffect(() => { checkStatus() }, [checkStatus])

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

  if (statusLoading) {
    return <InspektorLoadingState />
  }

  if (!status?.configured) {
    return <InspektorSetupGuide onRetry={checkStatus} />
  }

  return (
    <div className="flex flex-col h-[calc(100vh-2rem)] sm:h-[calc(100vh-3rem)] animate-fade-in">
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


function InspektorLoadingState() {
  return (
    <div className="flex flex-col h-[calc(100vh-2rem)] sm:h-[calc(100vh-3rem)] animate-fade-in">
      <div className="flex items-center gap-3 mb-4 shrink-0">
        <div className="skeleton w-11 h-11 rounded-xl" />
        <div className="space-y-2">
          <div className="skeleton h-4 w-28" />
          <div className="skeleton h-3 w-40" />
        </div>
      </div>
      <div className="skeleton flex-1 rounded-xl" />
    </div>
  )
}

// Shown instead of the chat when Inspektor has no Bedrock credentials
// configured yet — walks the user through enabling it via the manager CLI.
function InspektorSetupGuide({ onRetry }) {
  const [checking, setChecking] = useState(false)

  const handleRetry = async () => {
    setChecking(true)
    try {
      await onRetry()
    } finally {
      setChecking(false)
    }
  }

  return (
    <div className="flex flex-col h-[calc(100vh-2rem)] sm:h-[calc(100vh-3rem)] animate-fade-in">
      <div className="flex items-center justify-between gap-3 mb-4 shrink-0">
        <div className="flex items-center gap-3 min-w-0">
          <div className="relative flex items-center justify-center w-11 h-11 rounded-xl bg-gradient-to-br from-accent/25 to-accent/5 ring-1 ring-accent/30 text-accent shrink-0">
            <InspektorGlyph />
            <span className="absolute -bottom-0.5 -right-0.5 w-3 h-3 rounded-full ring-2 ring-surface bg-text-muted" />
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <h1 className="text-xl font-semibold text-text-primary tracking-tight">Inspektor</h1>
              <span className="text-[9px] font-semibold uppercase tracking-wider px-1.5 py-0.5 rounded bg-surface-tertiary text-text-muted">
                Not configured
              </span>
            </div>
            <span className="text-[11px] text-text-muted">AI threat analyst — setup required</span>
          </div>
        </div>
        <button
          onClick={handleRetry}
          disabled={checking}
          className="inline-flex items-center gap-2 px-3.5 py-2 rounded-lg bg-surface-tertiary hover:bg-surface-hover text-text-secondary hover:text-text-primary text-sm font-semibold transition-colors disabled:opacity-50 disabled:cursor-not-allowed shrink-0"
        >
          <RefreshIcon spinning={checking} />
          {checking ? 'Checking…' : 'Check again'}
        </button>
      </div>


      <div className="glass-card flex-1 overflow-y-auto p-5 sm:p-8">
        <div className="max-w-2xl mx-auto space-y-6">
          <div className="text-center space-y-2">
            <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-gradient-to-br from-accent/25 to-accent/5 ring-1 ring-accent/30 text-accent mb-1">
              <KeyIcon />
            </div>
            <h2 className="text-lg font-semibold text-text-primary">Inspektor isn't set up yet</h2>
            <p className="text-sm text-text-secondary max-w-md mx-auto">
              Inspektor needs AWS Bedrock credentials. Setup takes about a minute.
            </p>
          </div>

          <ol className="space-y-4">
            <Step n={1} title="Run the setup wizard">
              <p>In the <code className="font-mono text-xs bg-surface-tertiary px-1.5 py-0.5 rounded">manager/</code> directory on your host:</p>
              <CodeBlock>./melissae-manager.sh inspektor</CodeBlock>
            </Step>
            <Step n={2} title="Enter your AWS Bedrock credentials">
              <p>
                Access key, secret key, region and model ID. Make sure the model is enabled in
                <strong> AWS Console → Bedrock → Model access</strong>.
              </p>
            </Step>
            <Step n={3} title="Check again" last>
              <p>Once the container is up, click <strong>Check again</strong> above.</p>
            </Step>
          </ol>

          <p className="text-[11px] text-text-muted text-center pt-2 border-t border-border/40">
            Re-run the same command at any time to change credentials or disable Inspektor.
          </p>
        </div>
      </div>
    </div>
  )
}

function Step({ n, title, children, last }) {
  return (
    <li className="flex gap-3">
      <div className="flex flex-col items-center shrink-0">
        <span className="flex items-center justify-center w-7 h-7 rounded-full bg-accent/15 text-accent text-xs font-bold">
          {n}
        </span>
        {!last && <span className="w-px flex-1 bg-border/50 mt-1" />}
      </div>
      <div className="min-w-0 pb-1 space-y-1.5">
        <div className="text-sm font-semibold text-text-primary">{title}</div>
        <div className="text-[13px] leading-relaxed text-text-secondary space-y-1.5">{children}</div>
      </div>
    </li>
  )
}

function CodeBlock({ children }) {
  return (
    <pre className="text-[12.5px] font-mono bg-surface-tertiary/80 border border-border/50 rounded-lg px-3 py-2 overflow-x-auto text-accent">
      {children}
    </pre>
  )
}

function KeyIcon() {
  return (
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="7.5" cy="15.5" r="5.5" />
      <path d="m21 2-9.6 9.6M15.5 7.5 18 10M18 10l2.5-2.5M15.5 7.5 13 5" />
    </svg>
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
        {Array.isArray(msg.trace) && msg.trace.length > 0 && (
          <TracePanel trace={msg.trace} />
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

function TracePanel({ trace }) {
  const [open, setOpen] = useState(false)
  const [expanded, setExpanded] = useState(() => new Set())

  const toggleStep = i => {
    setExpanded(prev => {
      const next = new Set(prev)
      if (next.has(i)) next.delete(i)
      else next.add(i)
      return next
    })
  }

  return (
    <div className="mb-2 border border-border/50 rounded-lg bg-surface-tertiary/30 overflow-hidden">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center justify-between gap-2 px-3 py-2 text-[11px] font-semibold uppercase tracking-wider text-text-muted hover:text-text-primary transition-colors"
      >
        <span className="flex items-center gap-2">
          <BrainIcon />
          Thinking · {trace.length} step{trace.length === 1 ? '' : 's'}
        </span>
        <ChevronIcon open={open} />
      </button>
      {open && (
        <div className="border-t border-border/50 px-3 py-2 space-y-2">
          {trace.map((step, i) => {
            const isOpen = expanded.has(i)
            return (
              <div key={i} className="rounded-md bg-surface/60 border border-border/40">
                <button
                  onClick={() => toggleStep(i)}
                  className="w-full flex items-center justify-between gap-2 px-3 py-1.5 text-left hover:bg-surface-hover/40 transition-colors"
                >
                  <div className="flex items-center gap-2 min-w-0">
                    <span className="text-[10px] font-mono text-text-muted shrink-0">#{step.step}</span>
                    <span className="text-[11px] font-mono text-accent truncate">
                      {step.tool || '(no tool)'}
                    </span>
                  </div>
                  <ChevronIcon open={isOpen} small />
                </button>
                {isOpen && (
                  <div className="px-3 pb-2 pt-1 space-y-2 border-t border-border/30">
                    {step.thought && (
                      <TraceBlock label="Reasoning" body={step.thought} />
                    )}
                    {step.input && (
                      <TraceBlock label="Input" body={step.input} mono />
                    )}
                    {step.output && (
                      <TraceBlock label="Output" body={step.output} mono />
                    )}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

function TraceBlock({ label, body, mono }) {
  return (
    <div>
      <div className="text-[9px] font-semibold uppercase tracking-wider text-text-muted mb-0.5">
        {label}
      </div>
      <pre
        className={`text-[11px] leading-snug whitespace-pre-wrap break-words text-text-secondary bg-surface-tertiary/60 rounded px-2 py-1.5 max-h-60 overflow-auto ${
          mono ? 'font-mono' : ''
        }`}
      >
        {body}
      </pre>
    </div>
  )
}

function BrainIcon() {
  return (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 5a3 3 0 0 0-3 3v.5a3 3 0 0 0-2 5.2A3 3 0 0 0 9 19a3 3 0 0 0 3-3V5Z" />
      <path d="M12 5a3 3 0 0 1 3 3v.5a3 3 0 0 1 2 5.2A3 3 0 0 1 15 19a3 3 0 0 1-3-3" />
    </svg>
  )
}

function ChevronIcon({ open, small }) {
  const s = small ? 11 : 13
  return (
    <svg
      width={s} height={s} viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"
      className={`transition-transform ${open ? 'rotate-180' : ''}`}
    >
      <path d="m6 9 6 6 6-6" />
    </svg>
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

function RefreshIcon({ spinning }) {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={spinning ? 'animate-spin' : ''}>
      <path d="M21 12a9 9 0 1 1-3-6.7L21 8" />
      <path d="M21 3v5h-5" />
    </svg>
  )
}
