import { useState, useEffect, useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import { fetchLogs, fetchGeoIP } from '../api'
import StatCard from '../components/StatCard'
import { ProtocolChart, TopAttackersList, TopCredentials, TopHTTPTable } from '../components/charts'
import { filterByDateRange, computeStats, formatNumber } from '../utils'

const DATE_RANGES = [
  { label: 'Today', value: 'today' },
  { label: '7 days', value: '7d' },
  { label: '30 days', value: '30d' },
  { label: 'All', value: 'all' },
]

// Attacker statistics: security events, protocol breakdown, top IPs, credentials
export default function AttackerStats() {
  const [logs, setLogs] = useState([])
  const [geoData, setGeoData] = useState({})
  const [selectedAgent, setSelectedAgent] = useState('')
  const [dateRange, setDateRange] = useState('all')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const navigate = useNavigate()

  useEffect(() => {
    fetchLogs()
      .then(data => {
        setLogs(data)
        const uniqueIPs = [...new Set(data.map(l => l.ip).filter(Boolean))]
        fetchGeoIP(uniqueIPs).then(setGeoData).catch(() => {})
      })
      .catch(err => setError(err.message))
      .finally(() => setLoading(false))
  }, [])

  const agentIds = useMemo(() => [...new Set(logs.map(l => l.agent_id).filter(Boolean))].sort(), [logs])
  const dateFilteredLogs = useMemo(() => filterByDateRange(logs, dateRange), [logs, dateRange])
  const filteredLogs = useMemo(() => (
    selectedAgent ? dateFilteredLogs.filter(l => l.agent_id === selectedAgent) : dateFilteredLogs
  ), [dateFilteredLogs, selectedAgent])

  const s = useMemo(() => computeStats(filteredLogs), [filteredLogs])

  const goSearch = term => navigate(`/search?q=${encodeURIComponent(term)}`)

  if (loading) return <LoadingState />
  if (error) return (
    <div className="glass-card text-verdict-malicious p-6 text-center border-verdict-malicious/20 animate-fade-in">
      <div className="font-medium">Unable to load data</div>
      <div className="text-sm mt-1 opacity-60">{error}</div>
    </div>
  )

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <h1 className="text-xl font-semibold text-text-primary tracking-tight">Threats</h1>
          <select
            value={selectedAgent}
            onChange={e => setSelectedAgent(e.target.value)}
            className="px-3 py-1.5 bg-surface-tertiary border border-border rounded-lg text-text-primary text-sm focus:border-accent outline-none transition-colors"
          >
            <option value="">All agents</option>
            {agentIds.map(id => <option key={id} value={id}>{id}</option>)}
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
                  dateRange === r.value ? 'bg-accent/15 text-accent' : 'text-text-muted hover:text-text-secondary hover:bg-surface-hover/30'
                }`}
              >
                {r.label}
              </button>
            ))}
          </div>
        </div>
        <span className="text-[10px] text-text-muted font-mono">{formatNumber(s.uniqueIPs)} unique IPs</span>
      </div>

      {/* Security events summary */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
        <StatCard value={s.uniqueIPs} label="Unique IPs" />
        <StatCard value={s.cveLogs} label="CVE Exploits" variant={s.cveLogs > 0 ? 'alert' : 'default'} onClick={s.cveLogs > 0 ? () => goSearch('cve:CVE') : undefined} />
        <StatCard value={s.successSSH} label="SSH Logins" variant={s.successSSH > 0 ? 'warning' : 'default'} onClick={s.successSSH > 0 ? () => goSearch('action:successful AND protocol:ssh') : undefined} />
        <StatCard value={s.successFTP} label="FTP Logins" variant={s.successFTP > 0 ? 'warning' : 'default'} onClick={s.successFTP > 0 ? () => goSearch('action:successful AND protocol:ftp') : undefined} />
        <StatCard value={s.modbusWrites} label="Modbus Writes" variant={s.modbusWrites > 0 ? 'warning' : 'default'} onClick={s.modbusWrites > 0 ? () => goSearch('action:write AND protocol:modbus') : undefined} />
      </div>

      {/* Protocol breakdown + Top Attackers */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="glass-card p-5">
          <h3 className="section-title mb-4">Protocol Distribution</h3>
          <div className="max-w-[220px] mx-auto">
            <ProtocolChart logs={filteredLogs} onClick={p => goSearch(`protocol:${p}`)} />
          </div>
        </div>
        <div className="lg:col-span-2 glass-card p-5">
          <h3 className="section-title mb-4">Top Attackers</h3>
          <TopAttackersList logs={filteredLogs} geoData={geoData} onIPClick={ip => goSearch(`ip:${ip}`)} limit={15} />
        </div>
      </div>

      {/* Top Credentials */}
      <div className="glass-card p-5">
        <h3 className="section-title mb-4">Top Attempted Credentials</h3>
        <TopCredentials logs={filteredLogs} limit={20} />
      </div>

      {/* HTTP Analysis */}
      {s.protocols.http > 0 && (
        <div className="space-y-4">
          <h2 className="text-sm font-semibold text-text-secondary uppercase tracking-widest">HTTP Analysis</h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="glass-card p-5">
              <h3 className="section-title mb-4">Top User Agents</h3>
              <TopHTTPTable
                logs={filteredLogs}
                fieldFn={l => l['user-agent']}
                emptyLabel="user agent"
                accent="#86efac"
                onItemClick={ua => goSearch(`user-agent:${ua}`)}
                limit={10}
              />
            </div>
            <div className="glass-card p-5">
              <h3 className="section-title mb-4">Top HTTP Paths</h3>
              <TopHTTPTable
                logs={filteredLogs}
                fieldFn={l => l.path}
                emptyLabel="path"
                accent="#6366f1"
                onItemClick={path => goSearch(`path:${path}`)}
                limit={10}
              />
            </div>
            <div className="glass-card p-5">
              <h3 className="section-title mb-4">HTTP Methods</h3>
              <TopHTTPTable
                logs={filteredLogs}
                fieldFn={l => l.action}
                emptyLabel="method"
                accent="#fdba74"
                onItemClick={method => goSearch(`action:${method} AND protocol:http`)}
                limit={8}
              />
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

function LoadingState() {
  return (
    <div className="space-y-6 animate-fade-in">
      <div className="skeleton h-7 w-40" />
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
        {Array.from({ length: 5 }, (_, i) => <div key={i} className="skeleton h-24 rounded-xl" />)}
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="skeleton h-72 rounded-xl" />
        <div className="lg:col-span-2 skeleton h-72 rounded-xl" />
      </div>
      <div className="skeleton h-60 rounded-xl" />
    </div>
  )
}
