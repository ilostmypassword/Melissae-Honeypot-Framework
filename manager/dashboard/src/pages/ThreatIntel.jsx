import { useState, useEffect, useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import { Bar } from 'react-chartjs-2'
import { fetchThreats } from '../api'
import StatCard from '../components/StatCard'
import { VerdictTag } from '../components/Tags'
import DataTable from '../components/DataTable'
import KillchainPanel from '../components/KillchainPanel'
import ThreatDetailModal from '../components/ThreatDetailModal'
import { buildStixBundle, downloadJson } from '../stix'

function getSeverityScore(t) {
  if (Number.isFinite(t['protocol-score'])) return t['protocol-score']
  const rank = { malicious: 85, suspicious: 50, benign: 15 }
  return rank[t.verdict?.toLowerCase()] || 0
}

function getConfidence(t) {
  const c = Number(t?.confidence)
  return Number.isFinite(c) ? c : 0
}

function sortThreats(list) {
  return [...list].sort((a, b) => {
    const diff = getSeverityScore(b) - getSeverityScore(a)
    if (diff !== 0) return diff
    const conf = getConfidence(b) - getConfidence(a)
    if (conf !== 0) return conf
    return String(a.ip).localeCompare(String(b.ip))
  })
}

// Threat intelligence page with scoring details
export default function ThreatIntel() {
  const [threats, setThreats] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [filter, setFilter] = useState('all')
  const [killchainIP, setKillchainIP] = useState(null)
  const [detailThreat, setDetailThreat] = useState(null)
  const navigate = useNavigate()

  useEffect(() => {
    fetchThreats()
      .then(data => setThreats(sortThreats(data)))
      .catch(err => setError(err.message))
      .finally(() => setLoading(false))
  }, [])

  const filteredThreats = useMemo(() => {
    if (filter === 'all') return threats
    return threats.filter(t => t.verdict?.toLowerCase() === filter)
  }, [threats, filter])

  const stats = useMemo(() => ({
    total: threats.length,
    benign: threats.filter(t => t.verdict?.toLowerCase() === 'benign').length,
    suspicious: threats.filter(t => t.verdict?.toLowerCase() === 'suspicious').length,
    malicious: threats.filter(t => t.verdict?.toLowerCase() === 'malicious').length,
  }), [threats])

  const goSearch = term => navigate(`/search?q=${encodeURIComponent(term)}`)

  const handleExportStix = () => {
    if (threats.length === 0) return
    const bundle = buildStixBundle(threats)
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5)
    downloadJson(bundle, `melissae-iocs_stix_${timestamp}.json`)
  }

  const columns = [
    { key: 'type', label: 'Type' },
    { key: 'ip', label: 'IP Address' },
    { key: 'verdict', label: 'Verdict' },
    { key: 'score', label: 'Score' },
    { key: 'confidence', label: 'Confidence' },
    { key: 'details', label: 'Details' },
    { key: 'actions', label: 'Actions' },
  ]

  const renderCell = (key, _value, row) => {
    switch (key) {
      case 'type':
        return (
          <span className="text-xs font-semibold uppercase text-text-secondary">
            {(row.type || 'IP').toUpperCase()}
          </span>
        )
      case 'ip':
        return (
          <code className="text-sm font-mono text-text-primary">{row.ip}</code>
        )
      case 'verdict':
        return <VerdictTag verdict={row.verdict} />
      case 'score':
        return (
          <code className="text-sm font-mono text-text-secondary">
            {Number.isFinite(row['protocol-score']) ? `${row['protocol-score']}/100` : 'N/A'}
          </code>
        )
      case 'confidence':
        return (
          <code className="text-sm font-mono text-text-secondary">
            {Number.isFinite(row.confidence)
              ? `${Math.round(row.confidence * 100)}%`
              : 'N/A'}
          </code>
        )
      case 'details':
        return (
          <button
            onClick={() => setDetailThreat(row)}
            className="px-3 py-1.5 text-xs font-semibold bg-surface-tertiary hover:bg-surface-hover border border-border rounded-lg transition-colors"
          >
            DETAILS
          </button>
        )
      case 'actions':
        return (
          <div className="flex gap-2">
            <button
              onClick={() => setKillchainIP(row.ip)}
              className="px-3 py-1.5 text-xs font-semibold bg-accent/10 text-accent hover:bg-accent/20 border border-accent/20 rounded-lg transition-colors"
            >
              KILLCHAIN
            </button>
            <button
              onClick={() => goSearch(`ip:${row.ip}`)}
              className="px-3 py-1.5 text-xs font-semibold bg-verdict-benign/10 text-verdict-benign hover:bg-verdict-benign/20 border border-verdict-benign/20 rounded-lg transition-colors"
            >
              LOGS
            </button>
          </div>
        )
      default:
        return _value
    }
  }

  if (loading) return <LoadingState />
  if (error) return <ErrorState message={error} />

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Stats */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard value={stats.total} label="Total Threats" />
        <StatCard value={stats.benign} label="Benign" />
        <StatCard value={stats.suspicious} label="Suspicious" />
        <StatCard value={stats.malicious} label="Malicious" />
      </div>

      {/* Killchain Panel */}
      {killchainIP && (
        <KillchainPanel
          ip={killchainIP}
          onClose={() => setKillchainIP(null)}
        />
      )}

      {/* Threat List */}
      <div className="glass-card p-5">
        <div className="flex items-center justify-between mb-4 flex-wrap gap-3">
          <h3 className="section-title">Threat List</h3>
          <div className="flex items-center gap-3 flex-wrap">
            <div className="flex items-center gap-2">
              <label className="text-sm text-text-muted font-medium">
                Filter
              </label>
              <select
                value={filter}
                onChange={e => setFilter(e.target.value)}
                className="bg-surface-tertiary border border-border text-text-primary rounded-lg px-3 py-1.5 text-sm outline-none focus:border-accent transition-colors"
              >
                <option value="all">All</option>
                <option value="benign">Benign</option>
                <option value="suspicious">Suspicious</option>
                <option value="malicious">Malicious</option>
              </select>
            </div>
            <button
              onClick={handleExportStix}
              className="px-3 py-1.5 bg-surface-tertiary hover:bg-surface-hover text-text-secondary hover:text-text-primary border border-border rounded-lg text-[11px] font-semibold transition-colors uppercase tracking-wide"
            >
              Export STIX 2
            </button>
          </div>
        </div>

        <DataTable
          columns={columns}
          data={filteredThreats}
          emptyMessage="No threats found"
          renderCell={renderCell}
        />
      </div>

      {/* Threat Chart */}
      <div className="glass-card p-5">
        <h3 className="section-title mb-4">Threat Statistics</h3>
        <div className="h-[250px]">
          <ThreatChart stats={stats} />
        </div>
      </div>

      {/* Detail Modal */}
      {detailThreat && (
        <ThreatDetailModal
          threat={detailThreat}
          onClose={() => setDetailThreat(null)}
        />
      )}
    </div>
  )
}

function ThreatChart({ stats }) {
  const verdicts = ['benign', 'suspicious', 'malicious']
  const data = [stats.benign, stats.suspicious, stats.malicious]
  const colors = ['#4ade80', '#fbbf24', '#f87171']

  return (
    <Bar
      data={{
        labels: verdicts.map(v => v.charAt(0).toUpperCase() + v.slice(1)),
        datasets: [{
          label: 'Threats',
          data,
          backgroundColor: colors,
          borderRadius: 6,
          borderWidth: 0,
        }],
      }}
      options={{
        responsive: true,
        maintainAspectRatio: false,
        indexAxis: 'y',
        scales: {
          y: { grid: { display: false }, ticks: { color: '#8b949e' } },
          x: {
            beginAtZero: true,
            grid: { color: '#151d28' },
            ticks: { color: '#5a6370' },
          },
        },
        plugins: { legend: { display: false } },
      }}
    />
  )
}

function LoadingState() {
  return (
    <div className="space-y-6 animate-fade-in">
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {Array.from({ length: 4 }, (_, i) => (
          <div key={i} className="skeleton h-20 rounded-xl" />
        ))}
      </div>
      <div className="skeleton h-64 rounded-xl" />
    </div>
  )
}

function ErrorState({ message }) {
  return (
    <div className="glass-card text-verdict-malicious p-6 text-center border-verdict-malicious/20 animate-fade-in">
      <div className="font-medium">Unable to load threats</div>
      <div className="text-sm mt-1 opacity-60">{message}</div>
    </div>
  )
}

