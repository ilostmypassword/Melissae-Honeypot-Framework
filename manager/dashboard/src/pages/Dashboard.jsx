import { useState, useEffect, useMemo, useCallback, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  Tooltip,
  Legend,
  Filler,
} from 'chart.js'
import { Line, Doughnut, Bar } from 'react-chartjs-2'
import { fetchLogs, fetchAgents, fetchGeoIP } from '../api'
import StatCard from '../components/StatCard'
import { ProtocolTag } from '../components/Tags'
import DataTable from '../components/DataTable'

ChartJS.register(
  CategoryScale, LinearScale, PointElement,
  LineElement, BarElement, ArcElement, Tooltip, Legend, Filler
)

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
  const [selectedAgent, setSelectedAgent] = useState('')
  const [dateRange, setDateRange] = useState('all')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [lastRefresh, setLastRefresh] = useState(null)
  const [secondsAgo, setSecondsAgo] = useState(0)
  const [geoData, setGeoData] = useState({})
  const navigate = useNavigate()
  const refreshTimer = useRef(null)

  const loadData = useCallback(async (showLoading = false) => {
    if (showLoading) setLoading(true)
    try {
      const [logsData, agentsData] = await Promise.all([
        fetchLogs(),
        fetchAgents().catch(() => []),
      ])
      setLogs(logsData)
      setAgents(agentsData)
      setLastRefresh(Date.now())
      setError(null)
      const uniqueIPs = [...new Set(logsData.map(l => l.ip).filter(Boolean))]
      fetchGeoIP(uniqueIPs).then(setGeoData).catch(() => {})
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

  const agentIds = useMemo(() => {
    const ids = [...new Set(logs.map(l => l.agent_id).filter(Boolean))]
    return ids.sort()
  }, [logs])

  const dateFilteredLogs = useMemo(() => {
    if (dateRange === 'all') return logs
    const now = new Date()
    const pad = n => String(n).padStart(2, '0')
    const todayStr = `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}`
    let cutoffDate
    if (dateRange === 'today') {
      cutoffDate = todayStr
    } else {
      const cutoff = new Date(now)
      if (dateRange === '7d') cutoff.setDate(cutoff.getDate() - 7)
      else if (dateRange === '30d') cutoff.setDate(cutoff.getDate() - 30)
      cutoffDate = `${cutoff.getFullYear()}-${pad(cutoff.getMonth() + 1)}-${pad(cutoff.getDate())}`
    }
    return logs.filter(l => l.date && l.date >= cutoffDate)
  }, [logs, dateRange])

  const filteredLogs = useMemo(() => {
    return selectedAgent ? dateFilteredLogs.filter(l => l.agent_id === selectedAgent) : dateFilteredLogs
  }, [dateFilteredLogs, selectedAgent])

  const goSearch = term => {
    const agentParam = selectedAgent ? `&agent=${encodeURIComponent(selectedAgent)}` : ''
    navigate(`/search?q=${encodeURIComponent(term)}${agentParam}`)
  }

  if (loading) return <LoadingState />
  if (error) return <ErrorState message={error} />

  const s = computeStats(filteredLogs)
  const prevS = computeTrend(logs, selectedAgent)
  const recentLogs = filteredLogs.slice(-50).reverse()
  const healthyAgents = agents.filter(a => a.status === 'healthy').length

  const alerts = []
  if (s.cveLogs > 0) alerts.push({ label: 'CVE Exploits', value: s.cveLogs, query: 'cve:CVE' })
  if (s.successSSH > 0) alerts.push({ label: 'SSH Logins', value: s.successSSH, query: 'action:successful AND protocol:ssh' })
  if (s.successFTP > 0) alerts.push({ label: 'FTP Logins', value: s.successFTP, query: 'action:successful AND protocol:ftp' })
  if (s.successTelnet > 0) alerts.push({ label: 'Telnet Logins', value: s.successTelnet, query: 'action:session AND protocol:telnet' })
  if (s.modbusWrites > 0) alerts.push({ label: 'Modbus Writes', value: s.modbusWrites, query: 'action:write AND protocol:modbus' })

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header Row: agent selector + date range + refresh */}
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
            {filteredLogs.length.toLocaleString()} logs
          </span>
          <span className="text-[10px] text-text-muted flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 bg-green-500 rounded-full animate-pulse-slow" />
            {secondsAgo < 5 ? 'Just now' : `${secondsAgo}s ago`}
          </span>
        </div>
      </div>

      {/* Key Metrics with Trends */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        <StatCard value={s.totalLogs} label="Total Logs" trend={prevS.totalTrend} />
        <StatCard value={s.uniqueIPs} label="Unique IPs" trend={prevS.ipTrend} />
        <StatCard value={`${healthyAgents}/${agents.length}`} label="Agents Online" />
        <StatCard value={s.protocols.ssh} label="SSH" onClick={() => goSearch('protocol:ssh')} trend={prevS.sshTrend} />
        <StatCard value={s.protocols.http} label="HTTP" onClick={() => goSearch('protocol:http')} trend={prevS.httpTrend} />
        <StatCard value={s.protocols.ftp + s.protocols.modbus + s.protocols.mqtt + s.protocols.telnet} label="Other" onClick={() => goSearch('protocol:ftp OR protocol:modbus OR protocol:mqtt OR protocol:telnet')} />
      </div>

      {/* Alerts Banner */}
      {alerts.length > 0 && (
        <div className="bg-verdict-malicious/[0.06] border border-verdict-malicious/20 rounded-xl p-4">
          <h3 className="section-title text-verdict-malicious mb-3">Critical Events</h3>
          <div className="flex flex-wrap gap-2">
            {alerts.map(a => (
              <button key={a.label} onClick={() => goSearch(a.query)} className="px-3 py-1.5 bg-verdict-malicious/10 hover:bg-verdict-malicious/20 text-verdict-malicious rounded-lg text-xs font-semibold transition-all duration-200 border border-verdict-malicious/15 hover:border-verdict-malicious/30">
                {a.value} {a.label}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Multi-day Timeline + Protocol Breakdown */}
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

      {/* Hourly Activity + Heatmap */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="glass-card p-5">
          <h3 className="section-title mb-4">Hourly Activity</h3>
          <div className="h-[200px]">
            <ActivityChart logs={filteredLogs} onHourClick={h => goSearch(`hour:${h}`)} />
          </div>
        </div>
        <div className="glass-card p-5">
          <h3 className="section-title mb-4">Activity Heatmap</h3>
          <Heatmap logs={filteredLogs} />
        </div>
      </div>

      {/* Agent Breakdown + Top Attackers */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {!selectedAgent && agentIds.length > 1 && (
          <div className="glass-card p-5">
            <h3 className="section-title mb-4">Logs per Agent</h3>
            <div className="h-[220px]">
              <AgentBarChart logs={dateFilteredLogs} agentIds={agentIds} onAgentClick={setSelectedAgent} />
            </div>
          </div>
        )}
        <div className={`glass-card p-5 ${!selectedAgent && agentIds.length > 1 ? '' : 'md:col-span-2'}`}>
          <h3 className="section-title mb-4">Top Attackers</h3>
          <TopAttackersList logs={filteredLogs} geoData={geoData} onIPClick={ip => goSearch(`ip:${ip}`)} />
        </div>
      </div>

      {/* Top Credentials */}
      <div className="glass-card p-5">
        <h3 className="section-title mb-4">Top Attempted Credentials</h3>
        <TopCredentials logs={filteredLogs} />
      </div>

      {/* Recent Logs */}
      <div className="glass-card p-5">
        <div className="flex items-center justify-between mb-4">
          <h3 className="section-title">Recent Logs</h3>
          <button onClick={() => navigate('/search')} className="text-xs text-accent hover:text-accent-hover transition-colors font-medium">View all →</button>
        </div>
        <DataTable
          columns={[
            ...(!selectedAgent ? [{ key: 'agent_id', label: 'Agent' }] : []),
            { key: 'protocol', label: 'Protocol' },
            { key: 'date', label: 'Date' },
            { key: 'hour', label: 'Hour' },
            { key: 'ip', label: 'IP' },
            { key: 'action', label: 'Action' },
          ]}
          data={recentLogs}
          emptyMessage="No logs received yet"
          maxHeight="320px"
          renderCell={(key, value) => {
            if (key === 'agent_id') return (
              <button onClick={e => { e.stopPropagation(); setSelectedAgent(value) }} className="text-xs font-medium px-2 py-1 rounded bg-surface-tertiary text-accent hover:bg-accent/15 transition-colors">{value || '—'}</button>
            )
            if (key === 'protocol') return <ProtocolTag protocol={value} />
            if (key === 'date' || key === 'hour') return <code className="text-xs font-mono text-text-secondary">{value}</code>
            if (key === 'ip') return <code className="text-xs font-mono text-accent">{value}</code>
            return <span className="truncate max-w-[200px] block">{value || '—'}</span>
          }}
        />
      </div>
    </div>
  )
}

// Daily event count line chart
function DailyChart({ logs, onDayClick }) {
  const { labels, data } = useMemo(() => {
    const dayCounts = {}
    for (const l of logs) {
      if (l.date) dayCounts[l.date] = (dayCounts[l.date] || 0) + 1
    }
    const sorted = Object.entries(dayCounts).sort((a, b) => a[0].localeCompare(b[0]))
    if (sorted.length >= 2) {
      const start = new Date(sorted[0][0] + 'T00:00:00')
      const end = new Date(sorted[sorted.length - 1][0] + 'T00:00:00')
      const filled = []
      for (let d = new Date(start); d <= end; d.setDate(d.getDate() + 1)) {
        const key = d.toISOString().slice(0, 10)
        filled.push([key, dayCounts[key] || 0])
      }
      return { labels: filled.map(f => f[0].slice(5)), data: filled.map(f => f[1]) }
    }
    return { labels: sorted.map(s => s[0].slice(5)), data: sorted.map(s => s[1]) }
  }, [logs])

  return (
    <Line
      data={{
        labels,
        datasets: [{
          label: 'Logs',
          data,
          borderColor: '#6366f1',
          backgroundColor: 'rgba(99, 102, 241, 0.06)',
          borderWidth: 2,
          fill: true,
          tension: 0.4,
          pointRadius: data.length > 30 ? 0 : 3,
          pointBackgroundColor: '#6366f1',
          pointBorderColor: '#111820',
          pointBorderWidth: 2,
          pointHoverRadius: 5,
        }],
      }}
      options={{
        responsive: true,
        maintainAspectRatio: false,
        onClick: (_, elements) => {
          if (elements.length > 0) {
            const idx = elements[0].index
            const fullDate = logs.find(l => l.date)?.date ? Object.keys(
              logs.reduce((acc, l) => { if (l.date) acc[l.date] = 1; return acc }, {})
            ).sort()[idx] : null
            if (fullDate) onDayClick(fullDate)
          }
        },
        scales: {
          y: { beginAtZero: true, grid: { color: '#151d28' }, ticks: { color: '#5a6370' } },
          x: { grid: { display: false }, ticks: { color: '#5a6370', maxRotation: 0, autoSkip: true, maxTicksLimit: 15 } },
        },
        plugins: { legend: { display: false } },
      }}
    />
  )
}

// Hourly activity sparkline chart
function ActivityChart({ logs, onHourClick }) {
  const hours = Array.from({ length: 24 }, (_, i) => `${String(i).padStart(2, '0')}h`)
  const data = new Array(24).fill(0)
  logs.forEach(log => {
    const h = parseInt(log.hour?.split(':')[0]) || 0
    if (h >= 0 && h < 24) data[h]++
  })

  return (
    <Bar
      data={{
        labels: hours,
        datasets: [{
          data,
          backgroundColor: 'rgba(99, 102, 241, 0.20)',
          borderColor: '#6366f1',
          borderWidth: 1,
          borderRadius: 4,
        }],
      }}
      options={{
        responsive: true,
        maintainAspectRatio: false,
        onClick: (_, elements) => {
          if (elements.length > 0) onHourClick(String(elements[0].index).padStart(2, '0'))
        },
        scales: {
          y: { beginAtZero: true, grid: { color: '#151d28' }, ticks: { color: '#5a6370' } },
          x: { grid: { display: false }, ticks: { color: '#5a6370' } },
        },
        plugins: { legend: { display: false } },
      }}
    />
  )
}

// Day/hour event heatmap grid
function Heatmap({ logs }) {
  const grid = useMemo(() => {
    const data = Array.from({ length: 7 }, () => new Array(24).fill(0))
    for (const l of logs) {
      if (!l.date || !l.hour) continue
      const dow = new Date(l.date + 'T00:00:00').getDay()
      if (isNaN(dow)) continue
      const h = parseInt(l.hour.split(':')[0]) || 0
      if (h >= 0 && h < 24) data[dow][h]++
    }
    return data
  }, [logs])

  const max = Math.max(1, ...grid.flat())
  const days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat']

  return (
    <div className="overflow-x-auto">
      <div className="min-w-[500px]">
        {/* Hour labels */}
        <div className="flex ml-10 mb-1">
          {Array.from({ length: 24 }, (_, i) => (
            <div key={i} className="flex-1 text-center text-[9px] text-text-muted font-mono">
              {i % 3 === 0 ? `${String(i).padStart(2, '0')}` : ''}
            </div>
          ))}
        </div>
        {grid.map((row, dow) => (
          <div key={dow} className="flex items-center gap-1 mb-0.5">
            <span className="w-9 text-[10px] text-text-muted font-medium text-right shrink-0">{days[dow]}</span>
            <div className="flex flex-1 gap-[1px]">
              {row.map((val, h) => {
                const intensity = val / max
                return (
                  <div
                    key={h}
                    className="flex-1 h-[18px] rounded-[2px] transition-colors"
                    style={{ backgroundColor: val === 0 ? 'rgba(255,255,255,0.02)' : `rgba(99, 102, 241, ${0.12 + intensity * 0.65})` }}
                    title={`${days[dow]} ${String(h).padStart(2, '0')}:00 — ${val} logs`}
                  />
                )
              })}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

// Protocol distribution doughnut chart
function ProtocolChart({ logs, onClick }) {
  const protocols = ['ssh', 'ftp', 'http', 'modbus', 'mqtt', 'telnet']
  const counts = protocols.map(p => logs.filter(l => l.protocol === p).length)
  const colors = ['#38bdf8', '#f9a8d4', '#86efac', '#a78bfa', '#fdba74', '#fda4af']

  return (
    <Doughnut
      data={{
        labels: protocols.map(p => p.toUpperCase()),
        datasets: [{ data: counts, backgroundColor: colors, borderColor: '#111820', borderWidth: 2 }],
      }}
      options={{
        responsive: true,
        onClick: (_, elements) => { if (elements.length > 0) onClick(protocols[elements[0].index]) },
        plugins: { legend: { position: 'bottom', labels: { padding: 10, color: '#5a6370', font: { size: 10, weight: '500' }, usePointStyle: true, pointStyle: 'circle' } } },
      }}
    />
  )
}

// Events per agent bar chart
function AgentBarChart({ logs, agentIds, onAgentClick }) {
  const counts = agentIds.map(id => logs.filter(l => l.agent_id === id).length)
  const colors = ['#38bdf8', '#f9a8d4', '#86efac', '#a78bfa', '#fdba74', '#fda4af', '#818cf8', '#6ee7b7']

  return (
    <Bar
      data={{
        labels: agentIds,
        datasets: [{
          data: counts,
          backgroundColor: agentIds.map((_, i) => colors[i % colors.length] + '40'),
          borderColor: agentIds.map((_, i) => colors[i % colors.length]),
          borderWidth: 1, borderRadius: 6,
        }],
      }}
      options={{
        responsive: true,
        maintainAspectRatio: false,
        onClick: (_, elements) => { if (elements.length > 0) onAgentClick(agentIds[elements[0].index]) },
        scales: {
          y: { beginAtZero: true, grid: { color: '#151d28' }, ticks: { color: '#5a6370' } },
          x: { grid: { display: false }, ticks: { color: '#5a6370', font: { size: 11 } } },
        },
        plugins: { legend: { display: false } },
      }}
    />
  )
}

// Top attacker IPs ranked by event count
function TopAttackersList({ logs, geoData = {}, onIPClick }) {
  const ipCounts = logs.reduce((acc, l) => {
    const ip = l.ip || 'Unknown'
    acc[ip] = (acc[ip] || 0) + 1
    return acc
  }, {})

  const sorted = Object.entries(ipCounts).sort((a, b) => b[1] - a[1]).slice(0, 8)
  if (sorted.length === 0) return <div className="text-text-muted text-sm italic py-4 text-center">No data</div>
  const max = sorted[0][1]

  return (
    <div className="space-y-2">
      {sorted.map(([ip, count]) => {
        const cc = geoData[ip]
        const flag = cc && cc !== '??' ? countryFlag(cc) : null
        return (
          <button key={ip} onClick={() => onIPClick(ip)} className="w-full flex items-center gap-3 group hover:bg-surface-hover/50 rounded-lg px-2 py-1.5 transition-colors">
            {flag ? (
              <span className="text-sm w-6 text-center shrink-0" title={cc}>{flag}</span>
            ) : (
              <span className="w-6 text-center text-[10px] text-text-muted shrink-0">—</span>
            )}
            <code className="text-xs font-mono text-accent group-hover:text-accent-hover w-[120px] text-left shrink-0">{ip}</code>
            <div className="flex-1 bg-surface-tertiary rounded-full h-2 overflow-hidden">
              <div className="bg-red-500/60 h-full rounded-full transition-all" style={{ width: `${(count / max) * 100}%` }} />
            </div>
            <span className="text-xs font-mono text-text-secondary w-[50px] text-right shrink-0">{count}</span>
          </button>
        )
      })}
    </div>
  )
}

// Convert country code to flag emoji
function countryFlag(cc) {
  if (!cc || cc.length !== 2) return null
  const points = [...cc.toUpperCase()].map(c => 0x1F1E6 - 65 + c.charCodeAt(0))
  return String.fromCodePoint(...points)
}

// Most frequent credentials used by attackers
function TopCredentials({ logs }) {
  const creds = useMemo(() => {
    const counts = {}
    for (const l of logs) {
      if (!l.user || !['ssh', 'ftp', 'telnet'].includes(l.protocol)) continue
      const user = l.user.trim()
      if (!user) continue
      counts[user] = (counts[user] || 0) + 1
    }
    return Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 10)
  }, [logs])

  if (creds.length === 0) return <div className="text-text-muted text-sm italic py-4 text-center">No credential data available</div>

  const max = creds[0][1]

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-x-6 gap-y-1.5">
      {creds.map(([user, count]) => (
        <div key={user} className="flex items-center gap-3 py-1">
          <code className="text-xs font-mono text-text-primary w-[140px] truncate shrink-0">{user}</code>
          <div className="flex-1 bg-surface-tertiary rounded-full h-1.5 overflow-hidden">
            <div className="bg-amber-500/50 h-full rounded-full" style={{ width: `${(count / max) * 100}%` }} />
          </div>
          <span className="text-xs font-mono text-text-muted w-[40px] text-right shrink-0">{count}</span>
        </div>
      ))}
    </div>
  )
}

// Compute dashboard statistics from logs
function computeStats(logs) {
  const protocols = { ssh: 0, ftp: 0, http: 0, modbus: 0, mqtt: 0, telnet: 0 }
  const uniqueIPs = new Set()
  let cveLogs = 0, successSSH = 0, successFTP = 0, successTelnet = 0, modbusWrites = 0

  for (const l of logs) {
    if (l.protocol && protocols[l.protocol] !== undefined) protocols[l.protocol]++
    if (l.ip) uniqueIPs.add(l.ip)
    if (l.cve) cveLogs++
    const action = l.action?.toLowerCase() || ''
    if (l.protocol === 'ssh' && (action.includes('accepted') || action.includes('successful'))) successSSH++
    if (l.protocol === 'ftp' && action.includes('successful')) successFTP++
    if (l.protocol === 'telnet' && action.includes('session opened')) successTelnet++
    if (l.protocol === 'modbus' && action.includes('write')) modbusWrites++
  }

  return { totalLogs: logs.length, uniqueIPs: uniqueIPs.size, protocols, cveLogs, successSSH, successFTP, successTelnet, modbusWrites }
}

// Compute event trend compared to yesterday
function computeTrend(allLogs, selectedAgent) {
  const now = new Date()
  const h24 = new Date(now - 86400_000)
  const h48 = new Date(now - 172800_000)

  const inRange = (l, from, to) => {
    if (!l.date) return false
    const d = new Date(l.date + 'T' + (l.hour || '00:00:00'))
    return d >= from && d < to
  }

  const logs = selectedAgent ? allLogs.filter(l => l.agent_id === selectedAgent) : allLogs
  const last24 = logs.filter(l => inRange(l, h24, now))
  const prev24 = logs.filter(l => inRange(l, h48, h24))

  const trend = (curr, prev) => {
    if (prev === 0) return curr > 0 ? 100 : 0
    return Math.round(((curr - prev) / prev) * 100)
  }

  return {
    totalTrend: trend(last24.length, prev24.length),
    ipTrend: trend(new Set(last24.map(l => l.ip)).size, new Set(prev24.map(l => l.ip)).size),
    sshTrend: trend(last24.filter(l => l.protocol === 'ssh').length, prev24.filter(l => l.protocol === 'ssh').length),
    httpTrend: trend(last24.filter(l => l.protocol === 'http').length, prev24.filter(l => l.protocol === 'http').length),
  }
}

// Loading spinner placeholder
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
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="skeleton h-56 rounded-xl" />
        <div className="skeleton h-56 rounded-xl" />
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
