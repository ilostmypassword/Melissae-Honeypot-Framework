import { useState, useEffect, useMemo, useCallback, useRef } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { fetchLogs, fetchAgents, fetchAlerts } from '../api'
import StatCard from '../components/StatCard'
import { SeverityTag } from '../components/Tags'
import { DailyChart, ProtocolChart, ProtocolTimelineChart } from '../components/charts'
import { formatNumber, filterByDateRange, computeStats, computeTrend } from '../utils'

const REFRESH_INTERVAL = 30_000
const DATE_RANGES = [
  { label: 'Today', value: 'today' },
  { label: '7 days', value: '7d' },
  { label: '30 days', value: '30d' },
  { label: 'All', value: 'all' },
]

// Main dashboard page with stats and charts
export default function Dashboard() {
  const [logs, setLogs] = useState([])
  const [agents, setAgents] = useState([])
  const [recentAlerts, setRecentAlerts] = useState([])
  const [selectedAgent, setSelectedAgent] = useState('')
  const [dateRange, setDateRange] = useState('all')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [lastRefresh, setLastRefresh] = useState(null)
  const [secondsAgo, setSecondsAgo] = useState(0)
  const navigate = useNavigate()
  const refreshTimer = useRef(null)

  const loadData = useCallback(async (showLoading = false) => {
    if (showLoading) setLoading(true)
    try {
      const [logsData, agentsData, alertsData] = await Promise.all([
        fetchLogs(),
        fetchAgents().catch(() => []),
        fetchAlerts({ status: 'new', limit: 5 }).catch(() => []),
      ])
      setLogs(logsData)
      setAgents(agentsData)
      setRecentAlerts(Array.isArray(alertsData) ? alertsData.slice(0, 5) : [])
      setLastRefresh(Date.now())
      setError(null)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    loadData(true)
    refreshTimer.current = setInterval(() => loadData(false), REFRESH_INTERVAL)
    return () => clearInterval(refreshTimer.current)
  }, [loadData])

  useEffect(() => {
    const t = setInterval(() => {
      if (lastRefresh) setSecondsAgo(Math.floor((Date.now() - lastRefresh) / 1000))
    }, 1000)
    return () => clearInterval(t)
  }, [lastRefresh])

  const agentIds = useMemo(() => [...new Set(logs.map(l => l.agent_id).filter(Boolean))].sort(), [logs])

  const dateFilteredLogs = useMemo(() => filterByDateRange(logs, dateRange), [logs, dateRange])

  const filteredLogs = useMemo(() => (
    selectedAgent ? dateFilteredLogs.filter(l => l.agent_id === selectedAgent) : dateFilteredLogs
  ), [dateFilteredLogs, selectedAgent])

  const goSearch = term => {
    const agentParam = selectedAgent ? `&agent=${encodeURIComponent(selectedAgent)}` : ''
    navigate(`/search?q=${encodeURIComponent(term)}${agentParam}`)
  }

  if (loading) return <LoadingState />
  if (error) return <ErrorState message={error} />

  const s = computeStats(filteredLogs)
  const prevS = computeTrend(logs, selectedAgent)
  const healthyAgents = agents.filter(a => a.status === 'healthy').length

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <h1 className="text-xl font-semibold text-text-primary tracking-tight">Dashboard</h1>
          <select
            value={selectedAgent}
            onChange={e => setSelectedAgent(e.target.value)}
            className="px-3 py-1.5 bg-surface-tertiary border border-border rounded-lg text-text-primary text-sm focus:border-accent outline-none transition-colors"
          >
            <option value="">All agents</option>
            {agentIds.map(id => (
              <option key={id} value={id}>{id}</option>
            ))}
          </select>
          {selectedAgent && (
            <button onClick={() => setSelectedAgent('')} className="text-xs text-text-muted hover:text-text-primary transition-colors">✕</button>
          )}
          <div className="flex bg-surface-tertiary rounded-lg border border-border overflow-hidden">
            {DATE_RANGES.map(r => (
              <button
                key={r.value}
                onClick={() => setDateRange(r.value)}
                className={`px-2.5 py-1.5 text-xs font-medium transition-all duration-200 ${
                  dateRange === r.value
                    ? 'bg-accent/15 text-accent'
                    : 'text-text-muted hover:text-text-secondary hover:bg-surface-hover/30'
                }`}
              >
                {r.label}
              </button>
            ))}
          </div>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-[10px] text-text-muted font-mono tracking-wide">
            {formatNumber(filteredLogs.length)} logs
          </span>
          <span className="text-[10px] text-text-muted flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 bg-green-500 rounded-full animate-pulse-slow" />
            {secondsAgo < 5 ? 'Just now' : `${secondsAgo}s ago`}
          </span>
        </div>
      </div>

      {/* Recent alerts widget */}
      {recentAlerts.length > 0 && (
        <div className="glass-card p-4">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-verdict-malicious opacity-60" />
                <span className="relative inline-flex rounded-full h-2 w-2 bg-verdict-malicious" />
              </span>
              <span className="text-xs font-bold uppercase tracking-widest text-text-secondary">
                Recent alerts
              </span>
            </div>
            <Link
              to="/alerts"
              className="text-[11px] font-semibold text-accent hover:text-accent-hover transition-colors"
            >
              View all →
            </Link>
          </div>
          <div className="flex flex-col divide-y divide-border/40">
            {recentAlerts.map(a => (
              <Link
                key={a._id}
                to="/alerts"
                className="flex items-center gap-3 py-2 hover:bg-surface-hover/30 -mx-2 px-2 rounded-md transition-colors"
              >
                <SeverityTag severity={a.severity} />
                <span className="text-xs font-semibold text-text-primary truncate flex-1">
                  {a.rule_name || a.rule_id}
                </span>
                {a.ip && (
                  <code className="text-[11px] font-mono text-text-secondary shrink-0">{a.ip}</code>
                )}
                <span className="text-[10px] text-text-muted shrink-0 font-mono">+{a.score}</span>
              </Link>
            ))}
          </div>
        </div>
      )}

      {/* Key Metrics */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        <StatCard value={s.totalLogs} label="Total Logs" trend={prevS.totalTrend} />
        <StatCard value={s.uniqueIPs} label="Unique IPs" trend={prevS.ipTrend} />
        <StatCard value={`${healthyAgents}/${agents.length}`} label="Agents Online" />
        <StatCard value={s.protocols.ssh} label="SSH" onClick={() => goSearch('protocol:ssh')} trend={prevS.sshTrend} />
        <StatCard value={s.protocols.http} label="HTTP" onClick={() => goSearch('protocol:http')} trend={prevS.httpTrend} />
        <StatCard value={s.protocols.ftp + s.protocols.modbus + s.protocols.mqtt + s.protocols.telnet} label="Other" onClick={() => goSearch('protocol:ftp OR protocol:modbus OR protocol:mqtt OR protocol:telnet')} />
      </div>

      {/* Daily Activity + Protocol Breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2 glass-card p-5">
          <h3 className="section-title mb-4">Daily Activity</h3>
          <div className="h-[240px]">
            <DailyChart logs={filteredLogs} onDayClick={d => goSearch(`date:${d}`)} />
          </div>
        </div>
        <div className="glass-card p-5">
          <h3 className="section-title mb-4">Protocols</h3>
          <div className="max-w-[220px] mx-auto">
            <ProtocolChart logs={filteredLogs} onClick={p => goSearch(`protocol:${p}`)} />
          </div>
        </div>
      </div>

      {/* Protocol Timeline */}
      <div className="glass-card p-5">
        <h3 className="section-title mb-4">Protocol Timeline</h3>
        <div className="h-[220px]">
          <ProtocolTimelineChart logs={filteredLogs} />
        </div>
      </div>
    </div>
  )
}

// Loading skeleton
function LoadingState() {
  return (
    <div className="space-y-6 animate-fade-in">
      <div className="flex items-center gap-3">
        <div className="skeleton h-7 w-32" />
        <div className="skeleton h-8 w-28" />
      </div>
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        {Array.from({ length: 6 }, (_, i) => (
          <div key={i} className="skeleton h-24 rounded-xl" />
        ))}
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2 skeleton h-72 rounded-xl" />
        <div className="skeleton h-72 rounded-xl" />
      </div>
    </div>
  )
}

// Error message display
function ErrorState({ message }) {
  return (
    <div className="glass-card text-verdict-malicious p-6 text-center border-verdict-malicious/20 animate-fade-in">
      <div className="text-2xl mb-2 opacity-60">&diams;</div>
      <div className="font-medium">Unable to load data</div>
      <div className="text-sm mt-1 opacity-60">{message}</div>
    </div>
  )
}

