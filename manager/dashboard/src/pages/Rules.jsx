import { useState, useEffect, useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import { fetchRules } from '../api'
import { SeverityTag } from '../components/Tags'
import { formatTimestampUTC } from '../utils'

const REFRESH_INTERVAL = 30_000
const SEVERITIES = ['critical', 'high', 'medium', 'low']
// Trigger and last-run columns only show on wide screens
const COLS = 'md:grid-cols-[72px_1fr_96px_56px_20px] xl:grid-cols-[80px_1fr_100px_64px_100px_180px_20px]'

// MITRE technique id -> ATT&CK URL (sub-techniques use a nested path)
function mitreUrl(id) {
  const [base, sub] = String(id).toUpperCase().split('.')
  return `https://attack.mitre.org/techniques/${base}/${sub ? `${sub}/` : ''}`
}

function scoreTone(score) {
  if (score >= 70) return 'text-verdict-malicious'
  if (score >= 40) return 'text-verdict-suspicious'
  return 'text-verdict-benign'
}

// Read-only catalog of the YAML detection rules loaded by the rule engine
export default function Rules() {
  const [rules, setRules] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [query, setQuery] = useState('')
  const [severity, setSeverity] = useState('')
  const [showDisabled, setShowDisabled] = useState(true)
  const [expanded, setExpanded] = useState(null)

  useEffect(() => {
    let cancelled = false
    const load = async () => {
      try {
        const data = await fetchRules()
        if (cancelled) return
        setRules(Array.isArray(data) ? data : [])
        setError(null)
      } catch (err) {
        if (!cancelled) setError(err.message)
      } finally {
        if (!cancelled) setLoading(false)
      }
    }
    load()
    const t = setInterval(load, REFRESH_INTERVAL)
    return () => { cancelled = true; clearInterval(t) }
  }, [])

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    return rules.filter(r => {
      if (!showDisabled && !r.enabled) return false
      if (severity && (r.severity || '').toLowerCase() !== severity) return false
      if (!q) return true
      const haystack = [r.id, r.name, r.description, r.mql, ...(r.tags || []), ...(r.mitre || [])]
        .filter(Boolean).join(' ').toLowerCase()
      return haystack.includes(q)
    })
  }, [rules, query, severity, showDisabled])

  if (loading) {
    return (
      <div className="space-y-6 animate-fade-in">
        <div className="skeleton h-7 w-40" />
        <div className="space-y-2">
          {Array.from({ length: 6 }, (_, i) => (
            <div key={i} className="skeleton h-14 rounded-xl" />
          ))}
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="glass-card text-verdict-malicious p-6 text-center border-verdict-malicious/20 animate-fade-in">
        <div className="font-medium">Unable to load rules</div>
        <div className="text-sm mt-1 opacity-60">{error}</div>
      </div>
    )
  }

  const enabledCount = rules.filter(r => r.enabled).length

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-end justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-xl font-semibold text-text-primary tracking-tight">Detection Rules</h1>
          <p className="text-xs text-text-secondary mt-1">
            {rules.length} rules — <span className="text-verdict-benign">{enabledCount} enabled</span>
            {rules.length - enabledCount > 0 && (
              <span className="text-text-muted">, {rules.length - enabledCount} disabled</span>
            )}
          </p>
        </div>
        <p className="text-[10px] text-text-muted">
          Read-only — rules are defined in <code className="text-accent">rules/*.yml</code>
        </p>
      </div>

      {/* Filters */}
      <div className="glass-card p-3 flex flex-wrap items-center gap-3">
        <input
          type="text"
          value={query}
          onChange={e => setQuery(e.target.value)}
          placeholder="Filter by id, name, MQL, tag or MITRE technique…"
          className="flex-1 min-w-[220px] bg-surface-tertiary border border-border rounded-lg px-3 py-2 text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:border-accent/50"
        />
        <div className="flex items-center gap-1">
          {['', ...SEVERITIES].map(s => (
            <button
              key={s || 'all'}
              onClick={() => setSeverity(s)}
              className={`px-2.5 py-1.5 rounded-md text-[10px] font-semibold uppercase tracking-widest transition-colors ${
                severity === s
                  ? 'bg-accent/15 text-accent-hover'
                  : 'text-text-muted hover:text-text-primary hover:bg-surface-hover/50'
              }`}
            >
              {s || 'All'}
            </button>
          ))}
        </div>
        <label className="flex items-center gap-2 text-xs text-text-secondary cursor-pointer select-none">
          <input
            type="checkbox"
            checked={showDisabled}
            onChange={e => setShowDisabled(e.target.checked)}
            className="accent-accent"
          />
          Show disabled
        </label>
      </div>

      {/* Rule list */}
      {rules.length === 0 ? (
        <div className="glass-card p-12 text-center">
          <p className="text-text-secondary">No rules loaded</p>
          <p className="text-sm text-text-muted mt-1">
            Add YAML rules to <code className="text-accent">rules/</code> on the manager
          </p>
        </div>
      ) : filtered.length === 0 ? (
        <div className="glass-card p-8 text-center text-sm text-text-muted">No rule matches these filters</div>
      ) : (
        <div className="glass-card overflow-hidden">
          <div className={`hidden md:grid ${COLS} gap-4 px-4 py-2.5 border-b border-border text-[10px] font-semibold uppercase tracking-widest text-text-muted`}>
            <span>Id</span>
            <span>Rule</span>
            <span>Severity</span>
            <span className="text-right">Score</span>
            <span className="hidden xl:block">Trigger</span>
            <span className="hidden xl:block">Last run</span>
            <span />
          </div>
          {filtered.map(rule => (
            <RuleRow
              key={rule.id || rule.source_file}
              rule={rule}
              open={expanded === rule.id}
              onToggle={() => setExpanded(expanded === rule.id ? null : rule.id)}
            />
          ))}
        </div>
      )}
    </div>
  )
}

function RuleRow({ rule, open, onToggle }) {
  const navigate = useNavigate()
  const disabled = !rule.enabled

  return (
    <div className={`border-b border-border/60 last:border-b-0 ${disabled ? 'opacity-55' : ''}`}>
      <button
        onClick={onToggle}
        aria-expanded={open}
        className={`w-full text-left grid grid-cols-[1fr_auto] ${COLS} gap-x-4 gap-y-1 items-center px-4 py-3 hover:bg-surface-hover/40 transition-colors`}
      >
        <span className="font-mono text-xs text-accent-hover">{rule.id}</span>
        <span className="min-w-0 order-first md:order-none col-span-2 md:col-span-1 flex items-center gap-2">
          <span className="text-sm text-text-primary truncate">{rule.name || rule.id}</span>
          {disabled && (
            <span className="shrink-0 px-1.5 py-0.5 rounded text-[9px] font-bold uppercase tracking-widest bg-gray-500/15 text-gray-400">
              Disabled
            </span>
          )}
        </span>
        <span className="hidden md:block"><SeverityTag severity={rule.severity} /></span>
        <span className={`hidden md:block text-right font-mono text-sm font-semibold ${scoreTone(rule.score)}`}>
          +{rule.score}
        </span>
        <span className="hidden xl:block font-mono text-[11px] text-text-secondary">
          ≥{rule.threshold} / {rule.group_by}
        </span>
        <span className="hidden xl:block text-[11px] text-text-muted truncate">
          {rule.last_run_at ? formatTimestampUTC(rule.last_run_at) : 'Never'}
        </span>
        <svg
          width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"
          className={`hidden md:block text-text-muted transition-transform ${open ? 'rotate-180' : ''}`}
        >
          <path d="M6 9l6 6 6-6" />
        </svg>
      </button>

      {open && (
        <div className="px-4 pb-4 pt-1 space-y-4 animate-fade-in">
          {rule.description && (
            <p className="text-sm text-text-secondary leading-relaxed max-w-3xl">{String(rule.description).trim()}</p>
          )}

          <div>
            <p className="text-[9px] uppercase tracking-wider text-text-muted font-medium mb-1.5">MQL query</p>
            <pre className="bg-surface-tertiary border border-border rounded-lg px-3 py-2.5 text-xs font-mono text-text-primary whitespace-pre-wrap break-all">
              {String(rule.mql || '').trim()}
            </pre>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-x-4 gap-y-3 text-xs">
            <Info label="Severity" value={<SeverityTag severity={rule.severity} />} />
            <Info label="Score" value={<span className={`font-mono ${scoreTone(rule.score)}`}>+{rule.score}</span>} />
            <Info label="Threshold" value={`≥ ${rule.threshold} per ${rule.group_by}`} />
            <Info label="Schedule" value={rule.schedule || '—'} />
            <Info label="Lookback" value={rule.lookback || '—'} />
            <Info label="Source" value={rule.source_file} />
            <Info label="Last run" value={rule.last_run_at ? formatTimestampUTC(rule.last_run_at) : 'Never'} />
            <Info label="Last alerts" value={rule.last_alerts_emitted ?? '—'} />
            <Info label="Groups hit" value={rule.last_groups_triggered ?? '—'} />
          </div>

          {(rule.tags?.length > 0 || rule.mitre?.length > 0) && (
            <div className="flex flex-wrap items-center gap-1.5">
              {rule.mitre?.map(t => (
                <a
                  key={t}
                  href={mitreUrl(t)}
                  target="_blank"
                  rel="noreferrer"
                  className="px-2 py-0.5 rounded-md text-[10px] font-mono font-semibold bg-verdict-malicious/10 text-verdict-malicious hover:bg-verdict-malicious/20 transition-colors"
                >
                  {t}
                </a>
              ))}
              {rule.tags?.map(t => (
                <span key={t} className="px-2 py-0.5 rounded-md text-[10px] font-semibold bg-surface-hover text-text-secondary">
                  {t}
                </span>
              ))}
            </div>
          )}

          <div className="flex flex-wrap gap-2">
            <button
              onClick={() => navigate(`/alerts?rule_id=${encodeURIComponent(rule.id)}`)}
              className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-accent/10 text-accent-hover hover:bg-accent/20 transition-colors"
            >
              View alerts
            </button>
            {rule.mql && (
              <button
                onClick={() => navigate(`/search?q=${encodeURIComponent(String(rule.mql).trim())}`)}
                className="px-3 py-1.5 rounded-lg text-xs font-semibold text-text-secondary border border-border hover:text-text-primary hover:bg-surface-hover/50 transition-colors"
              >
                Run query in Search
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

function Info({ label, value }) {
  return (
    <div className="flex flex-col gap-1 min-w-0">
      <span className="text-[9px] uppercase tracking-wider text-text-muted font-medium">{label}</span>
      <span className="font-mono text-[11px] text-text-secondary truncate">{value}</span>
    </div>
  )
}
