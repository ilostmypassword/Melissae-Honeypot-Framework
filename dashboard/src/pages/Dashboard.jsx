import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  ArcElement,
  Tooltip,
  Legend,
  Filler,
} from 'chart.js'
import { Line, Doughnut } from 'react-chartjs-2'
import { fetchLogs } from '../api'
import StatCard from '../components/StatCard'

ChartJS.register(
  CategoryScale, LinearScale, PointElement,
  LineElement, ArcElement, Tooltip, Legend, Filler
)

export default function Dashboard() {
  const [logs, setLogs] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const navigate = useNavigate()

  useEffect(() => {
    fetchLogs()
      .then(setLogs)
      .catch(err => setError(err.message))
      .finally(() => setLoading(false))
  }, [])

  const goSearch = term => navigate(`/search?q=${encodeURIComponent(term)}`)

  if (loading) return <LoadingState />
  if (error) return <ErrorState message={error} />

  const s = computeStats(logs)

  return (
    <div className="space-y-6">
      {/* Stat Cards - including critical events inline */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 xl:grid-cols-5 gap-4">
        <StatCard value={s.totalLogs} label="Total Logs" />
        <StatCard value={s.uniqueIPs} label="Unique IPs" />
        <StatCard value={s.httpLogs} label="HTTP Logs" onClick={() => goSearch('protocol:http')} />
        <StatCard value={s.sshLogs} label="SSH Logs" onClick={() => goSearch('protocol:ssh')} />
        <StatCard value={s.ftpLogs} label="FTP Logs" onClick={() => goSearch('protocol:ftp')} />
        <StatCard value={s.modbusLogs} label="Modbus Logs" onClick={() => goSearch('protocol:modbus')} />
        <StatCard value={s.mqttLogs} label="MQTT Logs" onClick={() => goSearch('protocol:mqtt')} />
        <StatCard value={s.telnetLogs} label="Telnet Logs" onClick={() => goSearch('protocol:telnet')} />
        <StatCard value={s.failedSSH} label="Failed SSH Logins" onClick={() => goSearch('action:failed and protocol:ssh')} />
        <StatCard value={s.failedFTP} label="Failed FTP Logins" onClick={() => goSearch('action:failed and protocol:ftp')} />
        <StatCard value={s.modbusReads} label="Modbus Reads" onClick={() => goSearch('action:read and protocol:modbus')} />
        {/* Critical events - shown inline with red styling when > 0 */}
        {s.cveLogs > 0 && (
          <StatCard value={s.cveLogs} label="CVE Exploits" variant="critical" onClick={() => goSearch('cve:CVE')} />
        )}
        {s.successTelnet > 0 && (
          <StatCard value={s.successTelnet} label="Telnet Logins" variant="critical" onClick={() => goSearch('action:successful and protocol:telnet')} />
        )}
        {s.successSSH > 0 && (
          <StatCard value={s.successSSH} label="SSH Logins" variant="critical" onClick={() => goSearch('action:successful and protocol:ssh')} />
        )}
        {s.successFTP > 0 && (
          <StatCard value={s.successFTP} label="FTP Logins" variant="critical" onClick={() => goSearch('action:successful and protocol:ftp')} />
        )}
        {s.modbusWrites > 0 && (
          <StatCard value={s.modbusWrites} label="Modbus Writes" variant="critical" onClick={() => goSearch('action:write and protocol:modbus')} />
        )}
      </div>

      {/* Activity Chart */}
      <div className="bg-surface-secondary rounded-xl border border-border p-5">
        <h3 className="text-sm uppercase tracking-wider text-text-secondary font-semibold mb-4">
          Activity
        </h3>
        <div className="h-[300px]">
          <ActivityChart logs={logs} onHourClick={h => goSearch(`hour:${h}`)} />
        </div>
      </div>

      {/* Protocol & IP Charts */}
      <div className="bg-surface-secondary rounded-xl border border-border p-5">
        <h3 className="text-sm uppercase tracking-wider text-text-secondary font-semibold mb-4">
          Statistics
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <ChartCard title="Targeted Protocols">
            <ProtocolChart logs={logs} onClick={p => goSearch(`protocol:${p}`)} />
          </ChartCard>
          <ChartCard title="Top Threats">
            <TopIPsChart logs={logs} onClick={ip => goSearch(`ip:${ip}`)} />
          </ChartCard>
        </div>
      </div>
    </div>
  )
}

function ChartCard({ title, children }) {
  return (
    <div className="bg-surface-tertiary rounded-xl border border-border p-4">
      <h4 className="text-sm text-text-secondary text-center mb-4 font-medium">
        {title}
      </h4>
      {children}
    </div>
  )
}

function ActivityChart({ logs, onHourClick }) {
  const hours = Array.from({ length: 24 }, (_, i) => `${String(i).padStart(2, '0')}h`)
  const data = new Array(24).fill(0)

  logs.forEach(log => {
    const h = parseInt(log.hour?.split(':')[0]) || 0
    if (h >= 0 && h < 24) data[h]++
  })

  return (
    <Line
      data={{
        labels: hours,
        datasets: [{
          label: 'Activity',
          data,
          borderColor: '#ef4444',
          backgroundColor: 'rgba(239, 68, 68, 0.06)',
          borderWidth: 2,
          fill: true,
          tension: 0.4,
          pointRadius: 3,
          pointBackgroundColor: '#ef4444',
          pointBorderColor: '#161b22',
          pointBorderWidth: 2,
          pointHoverRadius: 6,
        }],
      }}
      options={{
        responsive: true,
        maintainAspectRatio: false,
        onClick: (_, elements) => {
          if (elements.length > 0) {
            onHourClick(String(elements[0].index).padStart(2, '0'))
          }
        },
        scales: {
          y: {
            beginAtZero: true,
            grid: { color: '#1e2332' },
            ticks: { color: '#656d76' },
          },
          x: {
            grid: { display: false },
            ticks: { color: '#656d76' },
          },
        },
        plugins: { legend: { display: false } },
      }}
    />
  )
}

function ProtocolChart({ logs, onClick }) {
  const protocols = ['ssh', 'ftp', 'http', 'modbus', 'mqtt', 'telnet']
  const counts = protocols.map(p => logs.filter(l => l.protocol === p).length)
  const colors = ['#22d3ee', '#f472b6', '#a3e635', '#c084fc', '#fb923c', '#f43f5e']

  return (
    <div className="max-w-[260px] mx-auto">
      <Doughnut
        data={{
          labels: protocols.map(p => p.toUpperCase()),
          datasets: [{
            data: counts,
            backgroundColor: colors,
            borderColor: '#161b22',
            borderWidth: 2,
          }],
        }}
        options={{
          responsive: true,
          onClick: (_, elements) => {
            if (elements.length > 0) onClick(protocols[elements[0].index])
          },
          plugins: {
            legend: {
              position: 'bottom',
              labels: { padding: 12, color: '#8b949e', font: { size: 12 } },
            },
          },
        }}
      />
    </div>
  )
}

function TopIPsChart({ logs, onClick }) {
  const ipCounts = logs.reduce((acc, l) => {
    const ip = l.ip || 'Unknown'
    acc[ip] = (acc[ip] || 0) + 1
    return acc
  }, {})

  const sorted = Object.entries(ipCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)

  const colors = ['#ef4444', '#f87171', '#fca5a5', '#dc2626', '#991b1b']

  return (
    <div className="max-w-[260px] mx-auto">
      <Doughnut
        data={{
          labels: sorted.map(s => s[0]),
          datasets: [{
            data: sorted.map(s => s[1]),
            backgroundColor: colors,
            borderColor: '#161b22',
            borderWidth: 2,
          }],
        }}
        options={{
          responsive: true,
          onClick: (_, elements) => {
            if (elements.length > 0) onClick(sorted[elements[0].index][0])
          },
          plugins: {
            legend: {
              position: 'bottom',
              labels: { padding: 12, color: '#8b949e', font: { size: 11 } },
            },
          },
        }}
      />
    </div>
  )
}

function computeStats(logs) {
  return {
    totalLogs: logs.length,
    uniqueIPs: new Set(logs.map(l => l.ip)).size,
    httpLogs: logs.filter(l => l.protocol === 'http').length,
    sshLogs: logs.filter(l => l.protocol === 'ssh').length,
    ftpLogs: logs.filter(l => l.protocol === 'ftp').length,
    modbusLogs: logs.filter(l => l.protocol === 'modbus').length,
    mqttLogs: logs.filter(l => l.protocol === 'mqtt').length,
    telnetLogs: logs.filter(l => l.protocol === 'telnet').length,
    cveLogs: logs.filter(l => l.cve).length,
    failedSSH: logs.filter(l => l.action?.toLowerCase().includes('failed') && l.protocol === 'ssh').length,
    failedFTP: logs.filter(l => l.action?.toLowerCase().includes('failed') && l.protocol === 'ftp').length,
    successSSH: logs.filter(l => l.action?.toLowerCase().includes('successful') && l.protocol === 'ssh').length,
    successFTP: logs.filter(l => l.action?.toLowerCase().includes('successful') && l.protocol === 'ftp').length,
    modbusReads: logs.filter(l => l.protocol === 'modbus' && l.action?.toLowerCase().includes('read')).length,
    modbusWrites: logs.filter(l => l.protocol === 'modbus' && l.action?.toLowerCase().includes('write')).length,
    successTelnet: logs.filter(l => l.action?.toLowerCase().includes('successful') && l.protocol === 'telnet').length,
  }
}

function LoadingState() {
  return (
    <div className="flex items-center justify-center h-64">
      <div className="text-text-muted text-lg flex items-center gap-3">
        <div className="w-5 h-5 border-2 border-accent border-t-transparent rounded-full animate-spin" />
        Loading...
      </div>
    </div>
  )
}

function ErrorState({ message }) {
  return (
    <div className="bg-verdict-malicious/10 border border-verdict-malicious/30 text-verdict-malicious rounded-xl p-6 text-center">
      <div className="text-2xl mb-2">&diams;</div>
      <div className="font-medium">Unable to load data</div>
      <div className="text-sm mt-1 opacity-75">{message}</div>
    </div>
  )
}
