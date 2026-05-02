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
const VIEW_MODES = [
  { label: 'Grouped', value: 'grouped' },
  { label: 'Flat', value: 'flat' },
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

// Aggregate alerts by (rule_id, ip).
function buildGroups(list) {
  const map = new Map()
  for (const a of list) {
    const key = `${a.rule_id || '_'}|${a.ip || '_'}`
    let g = map.get(key)
    if (!g) {
      g = {
        key,
        rule_id: a.rule_id,
        rule_name: a.rule_name || a.rule_id,
        ip: a.ip || null,
        severity: a.severity,
        score: a.score || 0,
        protocol: a.protocol || null,
        ids: [],
        members: [],
        status_counts: { new: 0, acknowledged: 0, resolved: 0 },
        first_seen: a.created_at,
        last_seen: a.created_at,
      }
      map.set(key, g)
    }
    g.ids.push(a._id)
    g.members.push(a)
    g.status_counts[a.status] = (g.status_counts[a.status] || 0) + 1
    if ((SEVERITY_ORDER[a.severity] ?? 9) < (SEVERITY_ORDER[g.severity] ?? 9)) {
      g.severity = a.severity
    }
    if (g.protocol && a.protocol && a.protocol !== g.protocol) g.protocol = null
    if (String(a.created_at || '') < String(g.first_seen || '')) g.first_seen = a.created_at
    if (String(a.created_at || '') > String(g.last_seen || '')) g.last_seen = a.created_at
  }
  return [...map.values()]
    .sort((a, b) => {
      const aActive = (a.status_counts.new || 0) + (a.status_counts.acknowledged || 0)
      const bActive = (b.status_counts.new || 0) + (b.status_counts.acknowledged || 0)
      const ax = aActive > 0 ? 0 : 1
      const bx = bActive > 0 ? 0 : 1
      if (ax !== bx) return ax - bx
      const sev = (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9)
      if (sev !== 0) return sev
      return String(b.last_seen || '').localeCompare(String(a.last_seen || ''))
    })
    .map(g => ({
      ...g,
      members: g.members.slice().sort((a, b) =>
        String(b.created_at || '').localeCompare(String(a.created_at || ''))
      ),
    }))
}

// Aggregate group status: any "new" -> new, else any "acknowledged" -> acknowledged, else resolved
function groupStatus(g) {
  if ((g.status_counts.new || 0) > 0) return 'new'
  if ((g.status_counts.acknowledged || 0) > 0) return 'acknowledged'
  return 'resolved'
}

function _toDate(iso) {
  if (!iso) return null
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? null : d
}

function _formatDate(d) {
  return d.toLocaleDateString('en-GB', { year: 'numeric', month: 'short', day: '2-digit' })
}

function _formatHMS(d) {
  return d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false })
}

function formatTime(iso) {
  const d = _toDate(iso)
  if (!d) return iso || '—'
  return `${_formatDate(d)}, ${_formatHMS(d)}`
}

function formatRange(first, last) {
  const fDate = _toDate(first)
  const lDate = _toDate(last)
  if (!fDate && !lDate) return '—'
  if (!fDate) return formatTime(last)
  if (!lDate) return formatTime(first)
  if (fDate.getTime() === lDate.getTime()) return formatTime(last)
  if (fDate.toDateString() === lDate.toDateString()) {
    return `${_formatDate(lDate)}, ${_formatHMS(fDate)} → ${_formatHMS(lDate)}`
  }
  return `${formatTime(first)} → ${formatTime(last)}`
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
  const [viewMode, setViewMode] = useState(searchParams.get('view') === 'flat' ? 'flat' : 'grouped')
  const [selected, setSelected] = useState(new Set())
  const [expanded, setExpanded] = useState(new Set())
  const [busy, setBusy] = useState(false)

  const load = useCallback(async () => {
    try {
      const filters = {}
      if (statusFilter) filters.status = statusFilter
      if (severityFilter) filters.severity = severityFilter
      if (ruleFilter) filters.rule_id = ruleFilter
      filters.limit = 5000
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
    if (viewMode !== 'grouped') next.set('view', viewMode)
    setSearchParams(next, { replace: true })
  }, [statusFilter, severityFilter, ruleFilter, viewMode, setSearchParams])

  const ruleOptions = useMemo(() => {
    const seen = new Map()
    for (const a of alerts) {
      if (a.rule_id && !seen.has(a.rule_id)) seen.set(a.rule_id, a.rule_name || a.rule_id)
    }
    return [...seen.entries()].sort((a, b) => a[1].localeCompare(b[1]))
  }, [alerts])

  const groups = useMemo(() => buildGroups(alerts), [alerts])

  const stats = useMemo(() => ({
    total:        alerts.length,
    groups:       groups.length,
    new:          alerts.filter(a => a.status === 'new').length,
    acknowledged: alerts.filter(a => a.status === 'acknowledged').length,
    resolved:     alerts.filter(a => a.status === 'resolved').length,
    critical:     alerts.filter(a => a.severity === 'critical').length,
  }), [alerts, groups])

  const toggleSelected = id => {
    setSelected(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }
  const toggleSelectedMany = ids => {
    setSelected(prev => {
      const next = new Set(prev)
      const allSelected = ids.every(id => next.has(id))
      if (allSelected) ids.forEach(id => next.delete(id))
      else ids.forEach(id => next.add(id))
      return next
    })
  }
  const toggleAllFlat = () => {
    setSelected(prev => prev.size === alerts.length ? new Set() : new Set(alerts.map(a => a._id)))
  }
  const toggleAllGroups = () => {
    const allIds = groups.flatMap(g => g.ids)
    setSelected(prev => prev.size === allIds.length ? new Set() : new Set(allIds))
  }
  const toggleExpanded = key => {
    setExpanded(prev => {
      const next = new Set(prev)
      if (next.has(key)) next.delete(key)
      else next.add(key)
      return next
    })
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

  const bulkSet = async (ids, status) => {
    if (!ids || ids.length === 0) return
    setBusy(true)
    try {
      await updateAlertsBulk(ids, status)
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

  const groupedSelectedAll = selected.size > 0 && selected.size === groups.flatMap(g => g.ids).length
  const flatSelectedAll = selected.size > 0 && selected.size === alerts.length

  const navigateLogsForAlert = alert => {
    if (!alert) return
    if (alert.log_id) {
      navigate(`/search?log_id=${encodeURIComponent(alert.log_id)}`)
      return
    }
    // Fallback when log_id is missing: build a precise MQL query from log fields.
    const log = alert.log || {}
    const parts = []
    const agentId = alert.agent_id || log.agent_id
    if (agentId) parts.push(`agent_id:${agentId}`)
    if (alert.ip || log.ip) parts.push(`ip:${alert.ip || log.ip}`)
    if (alert.protocol || log.protocol) parts.push(`protocol:${alert.protocol || log.protocol}`)
    if (log.date) parts.push(`date:${log.date}`)
    if (log.action && !/\b(AND|OR)\b/i.test(log.action)) {
      parts.push(`action:${log.action}`)
    }
    if (parts.length === 0) return
    navigate(`/search?q=${encodeURIComponent(parts.join(' AND '))}`)
  }

  const navigateLogsForGroup = group => {
    if (!group) return
    const parts = []
    if (group.ip) parts.push(`ip:${group.ip}`)
    if (group.protocol) parts.push(`protocol:${group.protocol}`)
    if (parts.length === 0) return
    navigate(`/search?q=${encodeURIComponent(parts.join(' AND '))}`)
  }

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div className="flex items-center gap-3">
          <h1 className="text-xl font-semibold text-text-primary tracking-tight">Alerts</h1>
          <span className="text-[10px] text-text-muted font-mono tracking-wide">
            {stats.total} total · {stats.groups} groups · {stats.new} new
          </span>
        </div>
        {selected.size > 0 && (
          <div className="flex items-center gap-2">
            <span className="text-xs text-text-muted">{selected.size} selected</span>
            <button
              disabled={busy}
              onClick={() => bulkSet([...selected], 'acknowledged')}
              className="px-3 py-1.5 text-xs font-semibold rounded-lg bg-verdict-suspicious/15 text-verdict-suspicious hover:bg-verdict-suspicious/25 transition-colors disabled:opacity-50"
            >
              Acknowledge
            </button>
            <button
              disabled={busy}
              onClick={() => bulkSet([...selected], 'resolved')}
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
        <Stat label="Groups" value={stats.groups} />
        <Stat label="New" value={stats.new} accent="malicious" />
        <Stat label="Acknowledged" value={stats.acknowledged} accent="suspicious" />
        <Stat label="Resolved" value={stats.resolved} accent="benign" />
        <Stat label="Critical" value={stats.critical} accent="malicious" />
      </div>

      {/* Filters */}
      <div className="glass-card p-4 flex flex-col lg:flex-row lg:items-center gap-3 flex-wrap">
        <FilterPills label="View"     options={VIEW_MODES}        value={viewMode}       onChange={setViewMode} />
        <FilterPills label="Status"   options={STATUS_FILTERS}    value={statusFilter}   onChange={setStatusFilter} />
        <FilterPills label="Severity" options={SEVERITY_FILTERS}  value={severityFilter} onChange={setSeverityFilter} />
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
                  <th className="px-3 py-2.5 text-left w-8">
                    <input
                      type="checkbox"
                      checked={viewMode === 'flat' ? flatSelectedAll : groupedSelectedAll}
                      onChange={viewMode === 'flat' ? toggleAllFlat : toggleAllGroups}
                      className="accent-accent"
                    />
                  </th>
                  {viewMode === 'grouped' && <th className="px-2 py-2.5 w-6" />}
                  <th className="px-3 py-2.5 text-left text-[10px] uppercase tracking-widest text-text-muted">
                    {viewMode === 'grouped' ? 'Last seen' : 'When'}
                  </th>
                  <th className="px-3 py-2.5 text-left text-[10px] uppercase tracking-widest text-text-muted">Severity</th>
                  <th className="px-3 py-2.5 text-left text-[10px] uppercase tracking-widest text-text-muted">Rule</th>
                  <th className="px-3 py-2.5 text-left text-[10px] uppercase tracking-widest text-text-muted">Source IP</th>
                  {viewMode === 'grouped' ? (
                    <th className="px-3 py-2.5 text-left text-[10px] uppercase tracking-widest text-text-muted">Count</th>
                  ) : (
                    <>
                      <th className="px-3 py-2.5 text-left text-[10px] uppercase tracking-widest text-text-muted">Protocol</th>
                      <th className="px-3 py-2.5 text-left text-[10px] uppercase tracking-widest text-text-muted">Action</th>
                    </>
                  )}
                  <th className="px-3 py-2.5 text-left text-[10px] uppercase tracking-widest text-text-muted">Status</th>
                  <th className="px-3 py-2.5 text-right text-[10px] uppercase tracking-widest text-text-muted">Manage</th>
                </tr>
              </thead>
              <tbody>
                {viewMode === 'grouped'
                  ? groups.map(g => (
                      <GroupRows
                        key={g.key}
                        group={g}
                        status={groupStatus(g)}
                        expanded={expanded.has(g.key)}
                        allSelected={g.ids.every(id => selected.has(id))}
                        busy={busy}
                        onToggleExpand={() => toggleExpanded(g.key)}
                        onToggleSelect={() => toggleSelectedMany(g.ids)}
                        onToggleMember={toggleSelected}
                        onNavigateIp={ip => navigate(`/search?q=${encodeURIComponent(`ip:${ip}`)}`)}
                        onNavigateGroupLogs={navigateLogsForGroup}
                        onNavigateAlertLogs={navigateLogsForAlert}
                        onAck={() => bulkSet(g.members.filter(m => m.status === 'new').map(m => m._id), 'acknowledged')}
                        onResolve={() => bulkSet(g.members.filter(m => m.status !== 'resolved').map(m => m._id), 'resolved')}
                        onReopen={() => bulkSet(g.members.filter(m => m.status !== 'new').map(m => m._id), 'new')}
                        memberSelected={selected}
                        onMemberStatus={setStatus}
                      />
                    ))
                  : alerts.map(a => (
                      <FlatRow
                        key={a._id}
                        alert={a}
                        selected={selected.has(a._id)}
                        busy={busy}
                        onToggle={() => toggleSelected(a._id)}
                        onNavigateIp={ip => navigate(`/search?q=${encodeURIComponent(`ip:${ip}`)}`)}
                        onNavigateLogs={navigateLogsForAlert}
                        onStatus={setStatus}
                      />
                    ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}

function FilterPills({ label, options, value, onChange }) {
  return (
    <div className="flex items-center gap-1.5">
      <span className="text-[10px] uppercase tracking-widest text-text-muted">{label}</span>
      <div className="flex bg-surface-tertiary rounded-lg border border-border overflow-hidden">
        {options.map(o => (
          <button
            key={o.value || 'all'}
            onClick={() => onChange(o.value)}
            className={`px-2.5 py-1.5 text-xs font-medium transition-all ${
              value === o.value
                ? 'bg-accent/15 text-accent'
                : 'text-text-muted hover:text-text-secondary hover:bg-surface-hover/30'
            }`}
          >
            {o.label}
          </button>
        ))}
      </div>
    </div>
  )
}

function GroupRows({
  group, status, expanded, allSelected, busy,
  onToggleExpand, onToggleSelect, onToggleMember, onNavigateIp,
  onNavigateGroupLogs, onNavigateAlertLogs,
  onAck, onResolve, onReopen, memberSelected, onMemberStatus,
}) {
  const activeCount = (group.status_counts.new || 0) + (group.status_counts.acknowledged || 0)
  return (
    <>
      <tr className="border-b border-border/40 hover:bg-surface-hover/20 transition-colors">
        <td className="px-3 py-2.5">
          <input
            type="checkbox"
            checked={allSelected}
            onChange={onToggleSelect}
            className="accent-accent"
          />
        </td>
        <td className="px-2 py-2.5">
          <button
            onClick={onToggleExpand}
            className="text-text-muted hover:text-text-primary transition-colors"
            title={expanded ? 'Collapse' : 'Expand'}
          >
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"
              className={`transition-transform ${expanded ? 'rotate-90' : ''}`}>
              <polyline points="9 18 15 12 9 6" />
            </svg>
          </button>
        </td>
        <td className="px-3 py-2.5 text-xs text-text-secondary whitespace-nowrap font-mono">
          {formatRange(group.first_seen, group.last_seen)}
        </td>
        <td className="px-3 py-2.5"><SeverityTag severity={group.severity} /></td>
        <td className="px-3 py-2.5">
          <div className="flex flex-col gap-0.5">
            <span className="text-xs font-semibold text-text-primary">{group.rule_name}</span>
            <span className="text-[10px] text-text-muted font-mono">+{group.score} · {group.rule_id}</span>
          </div>
        </td>
        <td className="px-3 py-2.5">
          {group.ip ? (
            <button
              onClick={() => onNavigateIp(group.ip)}
              className="text-xs font-mono text-accent hover:underline"
            >
              {group.ip}
            </button>
          ) : (
            <span className="text-xs text-text-muted">—</span>
          )}
        </td>
        <td className="px-3 py-2.5">
          <span className="inline-flex items-center gap-1.5">
            <span className="px-2 py-0.5 rounded-md bg-surface-tertiary text-text-primary text-xs font-semibold font-mono border border-border">
              {group.ids.length}
            </span>
            {activeCount > 0 && activeCount !== group.ids.length && (
              <span className="text-[10px] text-text-muted font-mono">{activeCount} active</span>
            )}
          </span>
        </td>
        <td className="px-3 py-2.5"><AlertStatusTag status={status} /></td>
        <td className="px-3 py-2.5 text-right">
          <div className="flex justify-end gap-1.5">
            {group.ip && (
              <button
                onClick={() => onNavigateGroupLogs(group)}
                className="px-2 py-1 text-[10px] font-semibold rounded bg-accent/15 text-accent hover:bg-accent/25 transition-colors"
                title="Show logs for this group"
              >
                LOGS
              </button>
            )}
            {(group.status_counts.new || 0) > 0 && (
              <button
                disabled={busy}
                onClick={onAck}
                className="px-2 py-1 text-[10px] font-semibold rounded bg-verdict-suspicious/15 text-verdict-suspicious hover:bg-verdict-suspicious/25 disabled:opacity-50 transition-colors"
                title="Acknowledge all new alerts in group"
              >
                ACK
              </button>
            )}
            {activeCount > 0 && (
              <button
                disabled={busy}
                onClick={onResolve}
                className="px-2 py-1 text-[10px] font-semibold rounded bg-verdict-benign/15 text-verdict-benign hover:bg-verdict-benign/25 disabled:opacity-50 transition-colors"
                title="Resolve all active alerts in group"
              >
                RESOLVE
              </button>
            )}
            {activeCount === 0 && (
              <button
                disabled={busy}
                onClick={onReopen}
                className="px-2 py-1 text-[10px] font-semibold rounded bg-surface-tertiary text-text-secondary hover:bg-surface-hover disabled:opacity-50 transition-colors"
                title="Re-open all alerts in group"
              >
                REOPEN
              </button>
            )}
          </div>
        </td>
      </tr>
      {expanded && group.members.map(m => (
        <tr key={m._id} className="border-b border-border/20 bg-surface-tertiary/20 hover:bg-surface-hover/20 transition-colors">
          <td className="px-3 py-2 pl-6">
            <input
              type="checkbox"
              checked={memberSelected.has(m._id)}
              onChange={() => onToggleMember(m._id)}
              className="accent-accent"
            />
          </td>
          <td colSpan={2} className="px-3 py-2 text-[11px] text-text-secondary font-mono whitespace-nowrap">
            └ {formatTime(m.created_at)}
          </td>
          <td className="px-3 py-2">
            {m.protocol ? <ProtocolTag protocol={m.protocol} /> : <span className="text-[11px] text-text-muted">—</span>}
          </td>
          <td colSpan={2} className="px-3 py-2 text-[11px] text-text-secondary truncate max-w-[280px]" title={m.log?.action}>
            {m.log?.action || '—'}
          </td>
          <td className="px-3 py-2 text-[10px] text-text-muted font-mono">
            {m.log?.user || ''}
          </td>
          <td className="px-3 py-2"><AlertStatusTag status={m.status} /></td>
          <td className="px-3 py-2 text-right">
            <div className="flex justify-end gap-1.5">
              {m.ip && (
                <button
                  onClick={() => onNavigateAlertLogs(m)}
                  className="px-1.5 py-0.5 text-[10px] font-semibold rounded bg-accent/15 text-accent hover:bg-accent/25 transition-colors"
                  title="Show the log that triggered this alert"
                >LOG</button>
              )}
              {m.status === 'new' && (
                <button
                  disabled={busy}
                  onClick={() => onMemberStatus(m._id, 'acknowledged')}
                  className="px-1.5 py-0.5 text-[10px] font-semibold rounded bg-verdict-suspicious/15 text-verdict-suspicious hover:bg-verdict-suspicious/25 disabled:opacity-50 transition-colors"
                >ACK</button>
              )}
              {m.status !== 'resolved' && (
                <button
                  disabled={busy}
                  onClick={() => onMemberStatus(m._id, 'resolved')}
                  className="px-1.5 py-0.5 text-[10px] font-semibold rounded bg-verdict-benign/15 text-verdict-benign hover:bg-verdict-benign/25 disabled:opacity-50 transition-colors"
                >RESOLVE</button>
              )}
              {m.status !== 'new' && (
                <button
                  disabled={busy}
                  onClick={() => onMemberStatus(m._id, 'new')}
                  className="px-1.5 py-0.5 text-[10px] font-semibold rounded bg-surface-tertiary text-text-secondary hover:bg-surface-hover disabled:opacity-50 transition-colors"
                >REOPEN</button>
              )}
            </div>
          </td>
        </tr>
      ))}
    </>
  )
}

function FlatRow({ alert: a, selected, busy, onToggle, onNavigateIp, onNavigateLogs, onStatus }) {
  return (
    <tr className="border-b border-border/40 hover:bg-surface-hover/20 transition-colors">
      <td className="px-3 py-2.5">
        <input
          type="checkbox"
          checked={selected}
          onChange={onToggle}
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
            onClick={() => onNavigateIp(a.ip)}
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
          {a.ip && (
            <button
              onClick={() => onNavigateLogs(a)}
              className="px-2 py-1 text-[10px] font-semibold rounded bg-accent/15 text-accent hover:bg-accent/25 transition-colors"
              title="Show the log that triggered this alert"
            >LOG</button>
          )}
          {a.status !== 'acknowledged' && a.status !== 'resolved' && (
            <button
              disabled={busy}
              onClick={() => onStatus(a._id, 'acknowledged')}
              className="px-2 py-1 text-[10px] font-semibold rounded bg-verdict-suspicious/15 text-verdict-suspicious hover:bg-verdict-suspicious/25 disabled:opacity-50 transition-colors"
            >ACK</button>
          )}
          {a.status !== 'resolved' && (
            <button
              disabled={busy}
              onClick={() => onStatus(a._id, 'resolved')}
              className="px-2 py-1 text-[10px] font-semibold rounded bg-verdict-benign/15 text-verdict-benign hover:bg-verdict-benign/25 disabled:opacity-50 transition-colors"
            >RESOLVE</button>
          )}
          {a.status !== 'new' && (
            <button
              disabled={busy}
              onClick={() => onStatus(a._id, 'new')}
              className="px-2 py-1 text-[10px] font-semibold rounded bg-surface-tertiary text-text-secondary hover:bg-surface-hover disabled:opacity-50 transition-colors"
            >REOPEN</button>
          )}
        </div>
      </td>
    </tr>
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
