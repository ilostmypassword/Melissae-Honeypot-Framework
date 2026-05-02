import { useState, useEffect, useMemo, useCallback } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { fetchAlerts, updateAlertStatus, updateAlertsBulk } from '../api'
import { SeverityTag, AlertStatusTag, ProtocolTag } from '../components/Tags'

const REFRESH_INTERVAL = 20_000
const STATUS_FILTERS = [
  { label: 'Active', value: 'new,acknowledged' },
  { label: 'New', value: 'new' },
  { label: 'Acknowledged', value: 'acknowledged' },
  { label: 'Resolved', value: 'resolved' },
  { label: 'All', value: '' },
]
const SEVERITY_FILTERS = [
  { label: 'All', value: '' },
  { label: 'Critical', value: 'critical' },
  { label: 'High', value: 'high' },
  { label: 'Medium', value: 'medium' },
  { label: 'Low', value: 'low' },
]

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 }
const STATUS_ORDER = { new: 0, acknowledged: 1, resolved: 2 }

function sortAlerts(list) {
  return [...list].sort((a, b) => {
    const s = (STATUS_ORDER[a.status] ?? 9) - (STATUS_ORDER[b.status] ?? 9)
    if (s !== 0) return s
    const sev = (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9)
    if (sev !== 0) return sev
    return String(b.created_at || '').localeCompare(String(a.created_at || ''))
  })
}

function formatTime(iso) {
  if (!iso) return '—'
  try {
    const d = new Date(iso)
    if (Number.isNaN(d.getTime())) return iso
    return d.toLocaleString(undefined, {
      year: 'numeric', month: 'short', day: '2-digit',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
    })
  } catch {
    return iso
  }
}

// Alerts backlog page
export default function Alerts() {
  const navigate = useNavigate()
  const [searchParams, setSearchParams] = useSearchParams()
  const [alerts, setAlerts] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [statusFilter, setStatusFilter] = useState(searchParams.get('status') ?? 'new,acknowledged')
  const [severityFilter, setSeverityFilter] = useState(searchParams.get('severity') ?? '')
  const [ruleFilter, setRuleFilter] = useState(searchParams.get('rule_id') ?? '')
  const [selected, setSelected] = useState(new Set())
  const [busy, setBusy] = useState(false)

  const load = useCallback(async () => {
    try {
      const filters = {}
      if (statusFilter) filters.status = statusFilter
      if (severityFilter) filters.severity = severityFilter
      if (ruleFilter) filters.rule_id = ruleFilter
      filters.limit = 1000
      const data = await fetchAlerts(filters)
      setAlerts(sortAlerts(data))
      setError(null)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }, [statusFilter, severityFilter, ruleFilter])

  useEffect(() => {
    load()
    const t = setInterval(load, REFRESH_INTERVAL)
    return () => clearInterval(t)
  }, [load])

  // Sync filters to URL
  useEffect(() => {
    const next = new URLSearchParams()
    if (statusFilter) next.set('status', statusFilter)
    if (severityFilter) next.set('severity', severityFilter)
    if (ruleFilter) next.set('rule_id', ruleFilter)
    setSearchParams(next, { replace: true })
  }, [statusFilter, severityFilter, ruleFilter, setSearchParams])

  const ruleOptions = useMemo(() => {
    const seen = new Map()
    for (const a of alerts) {
      if (a.rule_id && !seen.has(a.rule_id)) seen.set(a.rule_id, a.rule_name || a.rule_id)
    }
    return [...seen.entries()].sort((a, b) => a[1].localeCompare(b[1]))
  }, [alerts])

  const stats = useMemo(() => ({
    total:        alerts.length,
    new:          alerts.filter(a => a.status === 'new').length,
    acknowledged: alerts.filter(a => a.status === 'acknowledged').length,
    resolved:     alerts.filter(a => a.status === 'resolved').length,
    critical:     alerts.filter(a => a.severity === 'critical').length,
    high:         alerts.filter(a => a.severity === 'high').length,
  }), [alerts])

  const toggleSelected = id => {
    setSelected(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }
  const toggleAll = () => {
    setSelected(prev => prev.size === alerts.length ? new Set() : new Set(alerts.map(a => a._id)))
  }

  const setStatus = async (id, status) => {
    setBusy(true)
    try {
      await updateAlertStatus(id, status)
      await load()
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  const bulkSet = async status => {
    if (selected.size === 0) return
    setBusy(true)
    try {
      await updateAlertsBulk([...selected], status)
      setSelected(new Set())
      await load()
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  if (loading) {
    return (
      <div className="space-y-6 animate-fade-in">
        <div className="skeleton h-8 w-32" />
        <div className="skeleton h-24 rounded-xl" />
        <div className="skeleton h-96 rounded-xl" />
      </div>
    )
  }

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div className="flex items-center gap-3">
          <h1 className="text-xl font-semibold text-text-primary tracking-tight">Alerts</h1>
          <span className="text-[10px] text-text-muted font-mono tracking-wide">
            {stats.total} total · {stats.new} new
          </span>
        </div>
        {selected.size > 0 && (
          <div className="flex items-center gap-2">
            <span className="text-xs text-text-muted">{selected.size} selected</span>
            <button
              disabled={busy}
              onClick={() => bulkSet('acknowledged')}
              className="px-3 py-1.5 text-xs font-semibold rounded-lg bg-verdict-suspicious/15 text-verdict-suspicious hover:bg-verdict-suspicious/25 transition-colors disabled:opacity-50"
            >
              Acknowledge
            </button>
            <button
              disabled={busy}
              onClick={() => bulkSet('resolved')}
              className="px-3 py-1.5 text-xs font-semibold rounded-lg bg-verdict-benign/15 text-verdict-benign hover:bg-verdict-benign/25 transition-colors disabled:opacity-50"
            >
              Resolve
            </button>
            <button
              disabled={busy}
              onClick={() => setSelected(new Set())}
              className="px-3 py-1.5 text-xs text-text-muted hover:text-text-primary transition-colors"
            >
              Clear
            </button>
          </div>
        )}
      </div>

      {error && (
        <div className="glass-card text-verdict-malicious p-4 text-sm border-verdict-malicious/20">
          {error}
        </div>
      )}

      {/* Quick stats */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        <Stat label="Total" value={stats.total} />
        <Stat label="New" value={stats.new} accent="malicious" />
        <Stat label="Acknowledged" value={stats.acknowledged} accent="suspicious" />
        <Stat label="Resolved" value={stats.resolved} accent="benign" />
        <Stat label="Critical" value={stats.critical} accent="malicious" />
        <Stat label="High" value={stats.high} accent="suspicious" />
      </div>

      {/* Filters */}
      <div className="glass-card p-4 flex flex-col lg:flex-row lg:items-center gap-3 flex-wrap">
        <div className="flex items-center gap-1.5">
          <span className="text-[10px] uppercase tracking-widest text-text-muted">Status</span>
          <div className="flex bg-surface-tertiary rounded-lg border border-border overflow-hidden">
            {STATUS_FILTERS.map(s => (
              <button
                key={s.value}
                onClick={() => setStatusFilter(s.value)}
                className={`px-2.5 py-1.5 text-xs font-medium transition-all ${
                  statusFilter === s.value
                    ? 'bg-accent/15 text-accent'
                    : 'text-text-muted hover:text-text-secondary hover:bg-surface-hover/30'
                }`}
              >
                {s.label}
              </button>
            ))}
          </div>
        </div>

        <div className="flex items-center gap-1.5">
          <span className="text-[10px] uppercase tracking-widest text-text-muted">Severity</span>
          <div className="flex bg-surface-tertiary rounded-lg border border-border overflow-hidden">
            {SEVERITY_FILTERS.map(s => (
              <button
                key={s.value || 'all'}
                onClick={() => setSeverityFilter(s.value)}
                className={`px-2.5 py-1.5 text-xs font-medium transition-all ${
                  severityFilter === s.value
                    ? 'bg-accent/15 text-accent'
                    : 'text-text-muted hover:text-text-secondary hover:bg-surface-hover/30'
                }`}
              >
                {s.label}
              </button>
            ))}
          </div>
        </div>

        <div className="flex items-center gap-1.5">
          <span className="text-[10px] uppercase tracking-widest text-text-muted">Rule</span>
          <select
            value={ruleFilter}
            onChange={e => setRuleFilter(e.target.value)}
            className="px-2.5 py-1.5 bg-surface-tertiary border border-border rounded-lg text-text-primary text-xs focus:border-accent outline-none transition-colors"
          >
            <option value="">All rules</option>
            {ruleOptions.map(([id, name]) => (
              <option key={id} value={id}>{name}</option>
            ))}
          </select>
        </div>
      </div>

      {/* Backlog table */}
      <div className="glass-card overflow-hidden">
        {alerts.length === 0 ? (
          <div className="px-6 py-12 text-center text-text-muted text-sm">
            No alerts match the current filters.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border bg-surface-tertiary/50">
                  <th className="px-3 py-2.5 text-left">
                    <input
                      type="checkbox"
                      checked={selected.size > 0 && selected.size === alerts.length}
                      onChange={toggleAll}
                      className="accent-accent"
                    />
                  </th>
                  <th className="px-3 py-2.5 text-left text-[10px] uppercase tracking-widest text-text-muted">When</th>
                  <th className="px-3 py-2.5 text-left text-[10px] uppercase tracking-widest text-text-muted">Severity</th>
                  <th className="px-3 py-2.5 text-left text-[10px] uppercase tracking-widest text-text-muted">Rule</th>
                  <th className="px-3 py-2.5 text-left text-[10px] uppercase tracking-widest text-text-muted">Source IP</th>
                  <th className="px-3 py-2.5 text-left text-[10px] uppercase tracking-widest text-text-muted">Protocol</th>
                  <th className="px-3 py-2.5 text-left text-[10px] uppercase tracking-widest text-text-muted">Action</th>
                  <th className="px-3 py-2.5 text-left text-[10px] uppercase tracking-widest text-text-muted">Status</th>
                  <th className="px-3 py-2.5 text-right text-[10px] uppercase tracking-widest text-text-muted">Manage</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map(a => (
                  <tr key={a._id} className="border-b border-border/40 hover:bg-surface-hover/20 transition-colors">
                    <td className="px-3 py-2.5">
                      <input
                        type="checkbox"
                        checked={selected.has(a._id)}
                        onChange={() => toggleSelected(a._id)}
                        className="accent-accent"
                      />
                    </td>
                    <td className="px-3 py-2.5 text-xs text-text-secondary whitespace-nowrap font-mono">
                      {formatTime(a.created_at)}
                    </td>
                    <td className="px-3 py-2.5"><SeverityTag severity={a.severity} /></td>
                    <td className="px-3 py-2.5">
                      <div className="flex flex-col gap-0.5">
                        <span className="text-xs font-semibold text-text-primary">{a.rule_name || a.rule_id}</span>
                        <span className="text-[10px] text-text-muted font-mono">+{a.score} · {a.rule_id}</span>
                      </div>
                    </td>
                    <td className="px-3 py-2.5">
                      {a.ip ? (
                        <button
                          onClick={() => navigate(`/search?q=${encodeURIComponent(`ip:${a.ip}`)}`)}
                          className="text-xs font-mono text-accent hover:underline"
                        >
                          {a.ip}
                        </button>
                      ) : (
                        <span className="text-xs text-text-muted">—</span>
                      )}
                    </td>
                    <td className="px-3 py-2.5">
                      {a.protocol ? <ProtocolTag protocol={a.protocol} /> : <span className="text-xs text-text-muted">—</span>}
                    </td>
                    <td className="px-3 py-2.5 text-xs text-text-secondary max-w-[260px] truncate" title={a.log?.action}>
                      {a.log?.action || '—'}
                    </td>
                    <td className="px-3 py-2.5"><AlertStatusTag status={a.status} /></td>
                    <td className="px-3 py-2.5 text-right">
                      <div className="flex justify-end gap-1.5">
                        {a.status !== 'acknowledged' && a.status !== 'resolved' && (
                          <button
                            disabled={busy}
                            onClick={() => setStatus(a._id, 'acknowledged')}
                            className="px-2 py-1 text-[10px] font-semibold rounded bg-verdict-suspicious/15 text-verdict-suspicious hover:bg-verdict-suspicious/25 disabled:opacity-50 transition-colors"
                            title="Mark as acknowledged"
                          >
                            ACK
                          </button>
                        )}
                        {a.status !== 'resolved' && (
                          <button
                            disabled={busy}
                            onClick={() => setStatus(a._id, 'resolved')}
                            className="px-2 py-1 text-[10px] font-semibold rounded bg-verdict-benign/15 text-verdict-benign hover:bg-verdict-benign/25 disabled:opacity-50 transition-colors"
                            title="Mark as resolved"
                          >
                            RESOLVE
                          </button>
                        )}
                        {a.status !== 'new' && (
                          <button
                            disabled={busy}
                            onClick={() => setStatus(a._id, 'new')}
                            className="px-2 py-1 text-[10px] font-semibold rounded bg-surface-tertiary text-text-secondary hover:bg-surface-hover disabled:opacity-50 transition-colors"
                            title="Re-open"
                          >
                            REOPEN
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}

function Stat({ label, value, accent }) {
  const accentClass = {
    malicious: 'text-verdict-malicious',
    suspicious: 'text-verdict-suspicious',
    benign: 'text-verdict-benign',
  }[accent] || 'text-text-primary'
  return (
    <div className="glass-card px-4 py-3">
      <div className="text-[10px] uppercase tracking-widest text-text-muted">{label}</div>
      <div className={`text-2xl font-semibold font-mono mt-1 ${accentClass}`}>{value}</div>
    </div>
  )
}
