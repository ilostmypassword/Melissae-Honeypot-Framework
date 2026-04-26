import { useState, useEffect, useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import { fetchLogs, fetchAgents } from '../api'
import { DailyChart, ActivityChart, Heatmap, AgentBarChart } from '../components/charts'
import { filterByDateRange, formatNumber } from '../utils'

const DATE_RANGES = [
  { label: 'Today', value: 'today' },
  { label: '7 days', value: '7d' },
  { label: '30 days', value: '30d' },
  { label: 'All', value: 'all' },
]

// Activity statistics: timeline, hourly distribution, heatmap, per-agent breakdown
export default function ActivityStats() {
  const [logs, setLogs] = useState([])
  const [selectedAgent, setSelectedAgent] = useState('')
  const [dateRange, setDateRange] = useState('all')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const navigate = useNavigate()

  useEffect(() => {
    Promise.all([fetchLogs(), fetchAgents().catch(() => [])])
      .then(([logsData]) => setLogs(logsData))
      .catch(err => setError(err.message))
      .finally(() => setLoading(false))
  }, [])

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
          <h1 className="text-xl font-semibold text-text-primary tracking-tight">Activity</h1>
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
        <span className="text-[10px] text-text-muted font-mono tracking-wide">
          {formatNumber(filteredLogs.length)} logs
        </span>
      </div>

      {/* Daily Timeline (full width) */}
      <div className="glass-card p-5">
        <h3 className="section-title mb-4">Daily Timeline</h3>
        <div className="h-[260px]">
          <DailyChart logs={filteredLogs} onDayClick={d => goSearch(`date:${d}`)} />
        </div>
      </div>

      {/* Hourly Distribution + Heatmap */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="glass-card p-5">
          <h3 className="section-title mb-4">Hourly Distribution</h3>
          <div className="h-[220px]">
            <ActivityChart logs={filteredLogs} onHourClick={h => goSearch(`hour:${h}`)} />
          </div>
        </div>
        <div className="glass-card p-5">
          <h3 className="section-title mb-4">Day × Hour Heatmap</h3>
          <Heatmap logs={filteredLogs} />
        </div>
      </div>

      {/* Logs per Agent (only shown when multiple agents exist) */}
      {agentIds.length > 1 && (
        <div className="glass-card p-5">
          <h3 className="section-title mb-4">Logs per Agent</h3>
          <div className="h-[220px]">
            <AgentBarChart logs={dateFilteredLogs} agentIds={agentIds} onAgentClick={setSelectedAgent} />
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
      <div className="skeleton h-72 rounded-xl" />
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="skeleton h-60 rounded-xl" />
        <div className="skeleton h-60 rounded-xl" />
      </div>
    </div>
  )
}
