import { useState, useEffect, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { fetchInspektorReport } from '../api'
import { useInspektor } from '../context/InspektorContext'
import { timeAgo } from './InspektorMarkdown'
import { exportReportToPdf } from '../inspektorPdf'

function stripInline(line) {
  return line
    .replace(/\*\*(.*?)\*\*/g, '$1')
    .replace(/\*(.*?)\*/g, '$1')
    .replace(/`([^`]*)`/g, '$1')
    .replace(/\[([^\]]*)\]\([^)]*\)/g, '$1')
    .trim()
}

function summarize(markdown, max = 220) {
  if (!markdown) return ''
  const lines = String(markdown).replace(/\r/g, '').split('\n')

  // Preferred: the Posture line, with its label stripped for a clean sentence.
  for (const raw of lines) {
    const clean = stripInline(raw.trim())
    const m = clean.match(/^posture\s*[:\u2014-]\s*(.+)$/i)
    if (m && m[1].length >= 8) {
      let s = m[1].trim().replace(/^(calm|elevated|critical)\b[\s.,:;\u2013\u2014-]*/i, '').trim()
      if (s.length < 8) s = m[1].trim()
      if (s) s = s.charAt(0).toUpperCase() + s.slice(1)
      return s.length > max ? `${s.slice(0, max).trimEnd()}…` : s
    }
  }

  // Fallback: first substantive prose line (skip headings, tables, lists).
  for (const raw of lines) {
    const line = raw.trim()
    if (!line) continue
    if (/^#{1,6}\s/.test(line)) continue          // headings
    if (/^[|>-]/.test(line) || /^\*\s/.test(line)) continue // tables / quotes / bullets
    if (/^\d+\.\s/.test(line)) continue           // ordered list
    const clean = stripInline(line)
    if (clean.length < 12) continue
    return clean.length > max ? `${clean.slice(0, max).trimEnd()}…` : clean
  }
  return ''
}

// Rich, interactive Inspektor panel for the dashboard home page.
export default function InspektorBriefing() {
  const navigate = useNavigate()
  const { lastMeta, busy, runReport, send } = useInspektor()
  const [fetched, setFetched] = useState(null)
  const [loading, setLoading] = useState(true)
  const [ask, setAsk] = useState('')

  useEffect(() => {
    let cancelled = false
    fetchInspektorReport()
      .then(data => { if (!cancelled) setFetched(data?.markdown ? data : null) })
      .catch(() => { if (!cancelled) setFetched(null) })
      .finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [])

  const report = lastMeta?.markdown ? lastMeta : fetched
  const counts = report?.counts || {}
  const total = (counts.malicious || 0) + (counts.suspicious || 0) + (counts.benign || 0)
  const generatedAgo = timeAgo(report?.generated_at)
  const summary = summarize(report?.markdown)

  const onAsk = useCallback(e => {
    e.preventDefault()
    e.stopPropagation()
    const text = ask.trim()
    if (!text) return
    setAsk('')
    send(text)
    navigate('/inspektor')
  }, [ask, send, navigate])

  const onExport = useCallback(e => {
    e.preventDefault()
    e.stopPropagation()
    if (report?.markdown) exportReportToPdf(report.markdown, report)
  }, [report])

  const onGenerate = useCallback(e => {
    e.preventDefault()
    e.stopPropagation()
    runReport()
  }, [runReport])

  const seg = key => (total ? `${((counts[key] || 0) / total) * 100}%` : '0%')

  return (
    <div className="glass-card p-5 relative overflow-hidden group">
      <div className="absolute -top-16 -right-16 w-48 h-48 bg-accent/10 rounded-full blur-3xl pointer-events-none" />

      {/* Header — clickable to open the chat */}
      <button
        onClick={() => navigate('/inspektor')}
        className="flex items-center gap-4 relative w-full text-left"
      >
        <div className="relative flex items-center justify-center w-12 h-12 rounded-xl bg-gradient-to-br from-accent/25 to-accent/5 ring-1 ring-accent/30 text-accent shrink-0">
          <InspektorGlyph />
          <span
            className={`absolute -bottom-0.5 -right-0.5 w-3 h-3 rounded-full ring-2 ring-surface-secondary ${
              busy ? 'bg-verdict-suspicious animate-pulse' : 'bg-verdict-benign'
            }`}
          />
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="text-sm font-bold text-text-primary tracking-tight">Inspektor</span>
            <span className="text-[9px] font-semibold uppercase tracking-wider px-1.5 py-0.5 rounded bg-accent/15 text-accent">
              AI Analyst
            </span>
          </div>
          <span className="text-[11px] text-text-muted">
            {busy
              ? 'Analyzing the honeypot network…'
              : generatedAgo
                ? `Last briefing ${generatedAgo}`
                : 'AI threat analyst — on demand'}
          </span>
        </div>
        <span className="shrink-0 inline-flex items-center gap-1.5 text-accent text-sm font-semibold opacity-0 group-hover:opacity-100 transition-opacity">
          <span className="hidden sm:inline">Open</span>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="transition-transform group-hover:translate-x-0.5">
            <path d="M5 12h14M12 5l7 7-7 7" />
          </svg>
        </span>
      </button>

      {/* Body */}
      <div className="relative mt-4">
        {loading ? (
          <div className="space-y-2">
            <div className="skeleton h-2.5 w-full" />
            <div className="skeleton h-2.5 w-4/5" />
            <div className="skeleton h-2 w-32 mt-3" />
          </div>
        ) : report ? (
          <>
            {/* Verdict breakdown bar */}
            {total > 0 && (
              <div className="mb-3">
                <div className="flex h-2 rounded-full overflow-hidden bg-surface-tertiary">
                  <div className="bg-verdict-malicious" style={{ width: seg('malicious') }} />
                  <div className="bg-verdict-suspicious" style={{ width: seg('suspicious') }} />
                  <div className="bg-verdict-benign" style={{ width: seg('benign') }} />
                </div>
                <div className="flex items-center flex-wrap gap-x-4 gap-y-1 mt-2 text-[11px]">
                  <Legend color="bg-verdict-malicious" label="Malicious" value={counts.malicious || 0} />
                  <Legend color="bg-verdict-suspicious" label="Suspicious" value={counts.suspicious || 0} />
                  <Legend color="bg-verdict-benign" label="Benign" value={counts.benign || 0} />
                  <span className="ml-auto text-text-muted">{report.threats_analyzed ?? total} analyzed</span>
                </div>
              </div>
            )}

            {/* Briefing summary preview */}
            {summary && (
              <p className="text-[12.5px] leading-relaxed text-text-secondary line-clamp-3">
                {summary}
              </p>
            )}

            {/* Actions */}
            <div className="flex items-center gap-2 mt-3.5">
              <button
                onClick={onGenerate}
                disabled={busy}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-accent/15 text-accent hover:bg-accent/25 text-xs font-semibold transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <RefreshIcon spinning={busy} />
                {busy ? 'Analyzing…' : 'Regenerate'}
              </button>
              <button
                onClick={onExport}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-surface-tertiary hover:bg-surface-hover text-text-secondary hover:text-text-primary text-xs font-semibold transition-colors"
              >
                <PdfIcon />
                Export PDF
              </button>
            </div>
          </>
        ) : (
          <div className="flex flex-col items-start gap-3">
            <p className="text-[12.5px] text-text-secondary leading-relaxed">
              No briefing yet. Let Inspektor read the whole hive and produce a
              SOC-ready threat summary.
            </p>
            <button
              onClick={onGenerate}
              disabled={busy}
              className="inline-flex items-center gap-2 px-3.5 py-2 rounded-lg bg-accent text-white hover:bg-accent-hover text-sm font-semibold transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <RefreshIcon spinning={busy} />
              {busy ? 'Analyzing…' : 'Generate first briefing'}
            </button>
          </div>
        )}

        {/* Quick-ask composer */}
        <form onSubmit={onAsk} className="mt-4 flex items-center gap-2">
          <input
            value={ask}
            onChange={e => setAsk(e.target.value)}
            placeholder="Ask Inspektor a question…"
            className="flex-1 min-w-0 bg-surface-tertiary/60 rounded-lg px-3 py-2 text-xs text-text-primary placeholder:text-text-muted outline-none focus:ring-1 focus:ring-accent/40 transition-shadow"
          />
          <button
            type="submit"
            disabled={!ask.trim()}
            className="shrink-0 inline-flex items-center justify-center w-8 h-8 rounded-lg bg-accent text-white hover:bg-accent-hover transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
            aria-label="Ask Inspektor"
          >
            <SendIcon />
          </button>
        </form>
      </div>
    </div>
  )
}

function Legend({ color, label, value }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-text-muted">
      <span className={`w-1.5 h-1.5 rounded-full ${color}`} />
      <span className="text-text-secondary font-semibold">{value}</span>
      <span>{label}</span>
    </span>
  )
}

function InspektorGlyph({ size = 22 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="10.5" cy="10.5" r="6.5" />
      <path d="m20 20-4.5-4.5" />
      <path d="m8 10.5 1.8 1.8L13 9" />
    </svg>
  )
}

function RefreshIcon({ spinning }) {
  return (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={spinning ? 'animate-spin' : ''}>
      <path d="M21 12a9 9 0 1 1-3-6.7L21 8" />
      <path d="M21 3v5h-5" />
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

function SendIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M22 2 11 13M22 2l-7 20-4-9-9-4 20-7z" />
    </svg>
  )
}
