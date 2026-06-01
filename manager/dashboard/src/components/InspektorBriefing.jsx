import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { fetchInspektorReport } from '../api'
import { timeAgo } from './InspektorMarkdown'

// Compact Inspektor teaser card for the dashboard home page.
export default function InspektorBriefing() {
  const [report, setReport] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let cancelled = false
    fetchInspektorReport()
      .then(data => { if (!cancelled) setReport(data?.markdown ? data : null) })
      .catch(() => { if (!cancelled) setReport(null) })
      .finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [])

  const counts = report?.counts || {}
  const generatedAgo = timeAgo(report?.generated_at)

  return (
    <Link
      to="/inspektor"
      className="glass-card p-5 relative overflow-hidden block group hover:border-accent/40 transition-colors"
    >
      <div className="absolute -top-16 -right-16 w-48 h-48 bg-accent/10 rounded-full blur-3xl pointer-events-none" />

      <div className="flex items-center gap-4 relative">
        <div className="flex items-center justify-center w-12 h-12 rounded-xl bg-accent/15 text-accent text-xl font-bold shrink-0">
          I
        </div>

        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="text-sm font-bold text-text-primary tracking-tight">Inspektor</span>
            <span className="text-[9px] font-semibold uppercase tracking-wider px-1.5 py-0.5 rounded bg-accent/15 text-accent">
              AI Analyst
            </span>
          </div>
          {loading ? (
            <div className="skeleton h-3 w-40 mt-2" />
          ) : report ? (
            <div className="flex items-center flex-wrap gap-x-3 gap-y-1 mt-1.5 text-[11px] text-text-muted">
              <span>{report.threats_analyzed ?? 0} threats analyzed</span>
              {counts.malicious != null && (
                <span className="text-verdict-malicious">{counts.malicious} malicious</span>
              )}
              {generatedAgo && (
                <span className="flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 bg-verdict-benign rounded-full animate-pulse-slow" />
                  {generatedAgo}
                </span>
              )}
            </div>
          ) : (
            <p className="text-[11px] text-text-muted mt-1.5">
              Chat with Inspektor and generate threat briefings on demand.
            </p>
          )}
        </div>

        <div className="shrink-0 inline-flex items-center gap-1.5 text-accent text-sm font-semibold">
          <span className="hidden sm:inline">Open</span>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="transition-transform group-hover:translate-x-0.5">
            <path d="M5 12h14M12 5l7 7-7 7" />
          </svg>
        </div>
      </div>
    </Link>
  )
}
