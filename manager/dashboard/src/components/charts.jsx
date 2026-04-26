import { useMemo } from 'react'
import { Line, Bar, Doughnut } from 'react-chartjs-2'
import { formatNumber } from '../utils'

// ─── Daily event count line chart ────────────────────────────────────────────
export function DailyChart({ logs, onDayClick }) {
  const { labels, data, fullDates } = useMemo(() => {
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
      return {
        labels: filled.map(f => f[0].slice(5)),
        data: filled.map(f => f[1]),
        fullDates: filled.map(f => f[0]),
      }
    }
    return {
      labels: sorted.map(s => s[0].slice(5)),
      data: sorted.map(s => s[1]),
      fullDates: sorted.map(s => s[0]),
    }
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
          if (elements.length > 0 && onDayClick) onDayClick(fullDates[elements[0].index])
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

// ─── Hourly activity bar chart ────────────────────────────────────────────────
export function ActivityChart({ logs, onHourClick }) {
  const hours = Array.from({ length: 24 }, (_, i) => `${String(i).padStart(2, '0')}h`)
  const data = useMemo(() => {
    const counts = new Array(24).fill(0)
    logs.forEach(l => {
      const h = parseInt(l.hour?.split(':')[0]) || 0
      if (h >= 0 && h < 24) counts[h]++
    })
    return counts
  }, [logs])

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
          if (elements.length > 0 && onHourClick) onHourClick(String(elements[0].index).padStart(2, '0'))
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

// ─── Day × hour event heatmap ─────────────────────────────────────────────────
export function Heatmap({ logs }) {
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

// ─── Protocol distribution doughnut ──────────────────────────────────────────
export function ProtocolChart({ logs, onClick }) {
  const protocols = ['ssh', 'ftp', 'http', 'modbus', 'mqtt', 'telnet']
  const counts = useMemo(
    () => protocols.map(p => logs.filter(l => l.protocol === p).length),
    [logs]
  )
  const colors = ['#38bdf8', '#f9a8d4', '#86efac', '#a78bfa', '#fdba74', '#fda4af']

  return (
    <Doughnut
      data={{
        labels: protocols.map(p => p.toUpperCase()),
        datasets: [{ data: counts, backgroundColor: colors, borderColor: '#111820', borderWidth: 2 }],
      }}
      options={{
        responsive: true,
        onClick: (_, elements) => { if (elements.length > 0 && onClick) onClick(protocols[elements[0].index]) },
        plugins: {
          legend: {
            position: 'bottom',
            labels: { padding: 10, color: '#5a6370', font: { size: 10, weight: '500' }, usePointStyle: true, pointStyle: 'circle' },
          },
        },
      }}
    />
  )
}

// ─── Logs per agent bar chart ─────────────────────────────────────────────────
export function AgentBarChart({ logs, agentIds, onAgentClick }) {
  const counts = useMemo(
    () => agentIds.map(id => logs.filter(l => l.agent_id === id).length),
    [logs, agentIds]
  )
  const colors = ['#38bdf8', '#f9a8d4', '#86efac', '#a78bfa', '#fdba74', '#fda4af', '#818cf8', '#6ee7b7']

  return (
    <Bar
      data={{
        labels: agentIds,
        datasets: [{
          data: counts,
          backgroundColor: agentIds.map((_, i) => colors[i % colors.length] + '40'),
          borderColor: agentIds.map((_, i) => colors[i % colors.length]),
          borderWidth: 1,
          borderRadius: 6,
        }],
      }}
      options={{
        responsive: true,
        maintainAspectRatio: false,
        onClick: (_, elements) => { if (elements.length > 0 && onAgentClick) onAgentClick(agentIds[elements[0].index]) },
        scales: {
          y: { beginAtZero: true, grid: { color: '#151d28' }, ticks: { color: '#5a6370' } },
          x: { grid: { display: false }, ticks: { color: '#5a6370', font: { size: 11 } } },
        },
        plugins: { legend: { display: false } },
      }}
    />
  )
}

// ─── Top attacker IPs ranked by event count ───────────────────────────────────
export function TopAttackersList({ logs, geoData = {}, onIPClick, limit = 10 }) {
  const sorted = useMemo(() => {
    const ipCounts = logs.reduce((acc, l) => {
      const ip = l.ip || 'Unknown'
      acc[ip] = (acc[ip] || 0) + 1
      return acc
    }, {})
    return Object.entries(ipCounts).sort((a, b) => b[1] - a[1]).slice(0, limit)
  }, [logs, limit])

  if (sorted.length === 0) return <div className="text-text-muted text-sm italic py-4 text-center">No data</div>
  const max = sorted[0][1]

  return (
    <div className="space-y-2">
      {sorted.map(([ip, count]) => {
        const cc = geoData[ip]
        const flag = cc && cc !== '??' ? countryFlag(cc) : null
        return (
          <button key={ip} onClick={() => onIPClick?.(ip)} className="w-full flex items-center gap-3 group hover:bg-surface-hover/50 rounded-lg px-2 py-1.5 transition-colors">
            {flag ? (
              <span className="text-sm w-6 text-center shrink-0" title={cc}>{flag}</span>
            ) : (
              <span className="w-6 text-center text-[10px] text-text-muted shrink-0">—</span>
            )}
            <code className="text-xs font-mono text-accent group-hover:text-accent-hover w-[120px] text-left shrink-0">{ip}</code>
            <div className="flex-1 bg-surface-tertiary rounded-full h-2 overflow-hidden">
              <div className="bg-red-500/60 h-full rounded-full transition-all" style={{ width: `${(count / max) * 100}%` }} />
            </div>
            <span className="text-xs font-mono text-text-secondary w-[50px] text-right shrink-0">{formatNumber(count)}</span>
          </button>
        )
      })}
    </div>
  )
}

// ─── Top attempted credentials ────────────────────────────────────────────────
export function TopCredentials({ logs, limit = 10 }) {
  const creds = useMemo(() => {
    const counts = {}
    for (const l of logs) {
      if (!l.user || !['ssh', 'ftp', 'telnet'].includes(l.protocol)) continue
      const user = l.user.trim()
      if (!user) continue
      counts[user] = (counts[user] || 0) + 1
    }
    return Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, limit)
  }, [logs, limit])

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

// ─── Internal helper ──────────────────────────────────────────────────────────
function countryFlag(cc) {
  if (!cc || cc.length !== 2) return null
  const points = [...cc.toUpperCase()].map(c => 0x1F1E6 - 65 + c.charCodeAt(0))
  return String.fromCodePoint(...points)
}
