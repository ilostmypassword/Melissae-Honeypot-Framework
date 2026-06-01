import { useState, useEffect, useCallback } from 'react'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { fetchInspectorReport } from '../api'

const REFRESH_INTERVAL = 60_000

// Tailwind-styled renderers so the AI Markdown matches the dashboard theme
const mdComponents = {
  h2: ({ children }) => (
    <h2 className="text-sm font-bold uppercase tracking-widest text-text-secondary mt-1 mb-2">
      {children}
    </h2>
  ),
  h3: ({ children }) => (
    <h3 className="text-xs font-bold uppercase tracking-wider text-accent mt-4 mb-2">
      {children}
    </h3>
  ),
  p: ({ children }) => (
    <p className="text-sm text-text-secondary leading-relaxed mb-2">{children}</p>
  ),
  strong: ({ children }) => (
    <strong className="font-semibold text-text-primary">{children}</strong>
  ),
  ul: ({ children }) => (
    <ul className="space-y-1.5 mb-2 ml-1">{children}</ul>
  ),
  li: ({ children }) => (
    <li className="text-sm text-text-secondary leading-snug flex gap-2">
      <span className="text-accent shrink-0 mt-1.5 w-1 h-1 rounded-full bg-accent" />
      <span className="min-w-0">{children}</span>
    </li>
  ),
  code: ({ children }) => (
    <code className="font-mono text-[12px] px-1.5 py-0.5 rounded bg-surface-tertiary text-text-primary">
      {children}
    </code>
  ),
  table: ({ children }) => (
    <div className="overflow-x-auto my-2 rounded-lg border border-border/50">
      <table className="w-full text-xs">{children}</table>
    </div>
  ),
  thead: ({ children }) => (
    <thead className="bg-surface-tertiary/60">{children}</thead>
  ),
  th: ({ children }) => (
    <th className="text-left font-semibold uppercase tracking-wide text-[10px] text-text-muted px-3 py-2">
      {children}
    </th>
  ),
  td: ({ children }) => (
    <td className="px-3 py-2 text-text-secondary border-t border-border/40 align-top">
      {children}
    </td>
  ),
  a: ({ children, href }) => (
    <a href={href} className="text-accent hover:text-accent-hover underline" target="_blank" rel="noreferrer">
      {children}
    </a>
  ),
}

// AI threat briefing card rendered on the dashboard home page
export default function InspectorBriefing() {
  const [report, setReport] = useState(null)
  const [loading, setLoading] = useState(true)

  const load = useCallback(async () => {
    try {
      const data = await fetchInspectorReport()
      setReport(data)
    } catch {
      setReport(null)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    load()
    const t = setInterval(load, REFRESH_INTERVAL)
    return () => clearInterval(t)
  }, [load])

  const generatedAgo = report?.generated_at
    ? timeAgo(report.generated_at)
    : null

  return (
    <div className="glass-card p-5 relative overflow-hidden">
      {/* Accent glow */}
      <div className="absolute -top-16 -right-16 w-48 h-48 bg-accent/10 rounded-full blur-3xl pointer-events-none" />

      <div className="flex items-center justify-between mb-4 relative">
        <div className="flex items-center gap-2.5">
          <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-accent/15 text-accent text-base font-bold">
            I
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-sm font-bold text-text-primary tracking-tight">Inspector</span>
              <span className="text-[9px] font-semibold uppercase tracking-wider px-1.5 py-0.5 rounded bg-accent/15 text-accent">
                AI Analyst
              </span>
            </div>
            <span className="text-[10px] text-text-muted">
              {report?.threats_analyzed != null
                ? `${report.threats_analyzed} threats analyzed`
                : 'Threat briefing'}
            </span>
          </div>
        </div>
        {generatedAgo && (
          <span className="text-[10px] text-text-muted flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 bg-verdict-benign rounded-full animate-pulse-slow" />
            {generatedAgo}
          </span>
        )}
      </div>

      <div className="relative">
        {loading ? (
          <div className="space-y-2">
            <div className="skeleton h-4 w-3/4" />
            <div className="skeleton h-4 w-full" />
            <div className="skeleton h-4 w-5/6" />
          </div>
        ) : report?.markdown ? (
          <div className="max-w-none">
            <ReactMarkdown remarkPlugins={[remarkGfm]} components={mdComponents}>
              {report.markdown}
            </ReactMarkdown>
          </div>
        ) : (
          <div className="flex flex-col items-center justify-center text-center py-8">
            <div className="text-2xl mb-2 opacity-40">🤖</div>
            <div className="text-xs text-text-muted">No briefing available yet</div>
            <div className="text-[10px] text-text-muted/70 mt-1">
              Inspector publishes a new analysis every 5 minutes
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

// Compact "x min ago" formatter for an ISO timestamp
function timeAgo(iso) {
  const then = new Date(iso).getTime()
  if (Number.isNaN(then)) return null
  const secs = Math.max(0, Math.floor((Date.now() - then) / 1000))
  if (secs < 60) return 'just now'
  const mins = Math.floor(secs / 60)
  if (mins < 60) return `${mins}m ago`
  const hours = Math.floor(mins / 60)
  if (hours < 24) return `${hours}h ago`
  return `${Math.floor(hours / 24)}d ago`
}
