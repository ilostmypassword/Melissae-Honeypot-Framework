import { useState, useEffect, useRef } from 'react'
import { fetchAgents } from '../api'

const REFRESH_INTERVAL = 15_000

const statusColors = {
  healthy: 'bg-green-500',
  degraded: 'bg-yellow-500',
  unreachable: 'bg-red-500',
  pending: 'bg-blue-500',
  enrolled: 'bg-blue-400',
}

const statusText = {
  healthy: 'text-green-400',
  degraded: 'text-yellow-400',
  unreachable: 'text-red-400',
  pending: 'text-blue-400',
  enrolled: 'text-blue-300',
}

function formatTime(val) {
  if (!val || val === 'never') return '—'
  try {
    const d = new Date(val)
    if (isNaN(d)) return val
    return d.toLocaleString()
  } catch {
    return val
  }
}

// Registered agents list with health status
export default function Agents() {
  const [agents, setAgents] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [lastRefresh, setLastRefresh] = useState(null)
  const [secondsAgo, setSecondsAgo] = useState(0)
  const timer = useRef(null)

  const load = async (showLoader = false) => {
    if (showLoader) setLoading(true)
    try {
      const data = await fetchAgents()
      setAgents(data)
      setLastRefresh(Date.now())
      setError(null)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load(true)
    timer.current = setInterval(() => load(false), REFRESH_INTERVAL)
    return () => clearInterval(timer.current)
  }, [])

  useEffect(() => {
    const t = setInterval(() => {
      if (lastRefresh) setSecondsAgo(Math.floor((Date.now() - lastRefresh) / 1000))
    }, 1000)
    return () => clearInterval(t)
  }, [lastRefresh])

  if (loading) {
    return (
      <div className="space-y-6 animate-fade-in">
        <div className="skeleton h-7 w-32" />
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {Array.from({ length: 3 }, (_, i) => (
            <div key={i} className="skeleton h-52 rounded-xl" />
          ))}
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="glass-card text-verdict-malicious p-6 text-center border-verdict-malicious/20 animate-fade-in">
        <div className="font-medium">Unable to load agents</div>
        <div className="text-sm mt-1 opacity-60">{error}</div>
      </div>
    )
  }

  const healthy = agents.filter(a => a.status === 'healthy').length
  const total = agents.length

  const reachableAgents = agents.filter(a => a.status !== 'unreachable')
  const allModules = reachableAgents.flatMap(a => a.last_health?.modules || [])
  const modulesRunning = allModules.filter(m => m.status === 'running').length
  const modulesTotal = allModules.length

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-xl font-semibold text-text-primary tracking-tight">Agents</h1>
          <p className="text-xs text-text-secondary mt-1">
            {total} registered — {healthy} healthy
            {modulesTotal > 0 && (
              <span className="ml-3 text-text-muted">
                Modules: <span className={modulesRunning === modulesTotal ? 'text-green-400' : 'text-yellow-400'}>{modulesRunning}/{modulesTotal}</span> running
              </span>
            )}
          </p>
        </div>
        <span className="text-[10px] text-text-muted flex items-center gap-1.5">
          <span className="w-1.5 h-1.5 bg-green-500 rounded-full animate-pulse-slow" />
          {secondsAgo < 5 ? 'Just now' : `${secondsAgo}s ago`}
        </span>
      </div>

      {/* Agent Cards */}
      {agents.length === 0 ? (
        <div className="glass-card p-12 text-center">
          <div className="text-3xl mb-3 opacity-30">⬡</div>
          <p className="text-text-secondary">No agents registered yet</p>
          <p className="text-sm text-text-muted mt-1">
            Use <code className="text-accent">melissae-manager.sh enroll</code> to add an agent
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {agents.map(agent => (
            <AgentCard key={agent.agent_id} agent={agent} />
          ))}
        </div>
      )}
    </div>
  )
}

function AgentCard({ agent }) {
  const status = agent.status || 'unknown'
  const dotColor = statusColors[status] || 'bg-gray-500'
  const txtColor = statusText[status] || 'text-gray-400'
  const isUnreachable = status === 'unreachable'

  const health = agent.last_health || {}
  const modules = health.modules || []
  const uptime = health.uptime_seconds
  const version = health.version
  const pending = health.buffer?.pending_logs
  const lastPush = health.last_push || agent.last_push

  const running = modules.filter(m => m.status === 'running')
  const stopped = modules.filter(m => m.status !== 'running')

  return (
    <div className={`glass-card-hover p-5 space-y-4 ${isUnreachable ? 'opacity-70' : ''}`}>
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <span className={`w-2.5 h-2.5 rounded-full ${dotColor}`} />
          <span className="font-medium text-text-primary">{agent.agent_id}</span>
        </div>
        <span className={`text-[10px] font-semibold uppercase tracking-[0.12em] ${txtColor}`}>
          {status}
        </span>
      </div>

      {/* Unreachable notice */}
      {isUnreachable && (
        <div className="flex items-center gap-1.5 text-[10px] text-red-400/80 bg-red-500/5 border border-red-500/15 rounded-md px-2.5 py-1.5">
          <span>⚠</span>
          <span>Agent unreachable, data below is from last known check</span>
        </div>
      )}

      {/* Info rows */}
      <div className="space-y-2 text-sm">
        <Row label="Host" value={agent.host || '—'} />
        {version && <Row label="Version" value={version} />}
        {agent.registered_at && <Row label="Registered" value={formatTime(agent.registered_at)} />}
        <Row label="Last Push" value={formatTime(lastPush)} />
        <Row label="Last Check" value={formatTime(agent.last_check)} />
        {!isUnreachable && uptime != null && <Row label="Uptime" value={formatUptime(uptime)} />}
        {!isUnreachable && pending != null && (
          <Row
            label="Buffer Pending"
            value={String(pending)}
            highlight={pending > 500}
          />
        )}
      </div>

      {/* Services summary */}
      {modules.length > 0 && (
        <div>
          <div className="flex items-center justify-between mb-2">
            <p className="section-title">Services</p>
            {!isUnreachable && (
              <span className="text-[10px] text-text-muted font-mono">
                <span className={running.length === modules.length ? 'text-green-400' : 'text-yellow-400'}>
                  {running.length}
                </span>
                /{modules.length} running
              </span>
            )}
          </div>
          <div className="flex flex-wrap gap-1.5">
            {modules.map(m => (
              <span
                key={m.name}
                title={isUnreachable ? `${m.container || m.name} — unknown (agent unreachable)` : `${m.container || m.name} — ${m.status}`}
                className={`px-2 py-0.5 rounded-md text-[10px] font-semibold ${
                  isUnreachable
                    ? 'bg-gray-500/10 text-gray-400 border border-gray-500/20'
                    : m.status === 'running'
                    ? 'bg-green-500/10 text-green-400 border border-green-500/20'
                    : 'bg-red-500/10 text-red-400 border border-red-500/20'
                }`}
              >
                {m.name}
              </span>
            ))}
          </div>
          {!isUnreachable && stopped.length > 0 && (
            <p className="text-[10px] text-red-400/70 mt-2">
              ⚠ {stopped.length} stopped: {stopped.map(m => m.name).join(', ')}
            </p>
          )}
        </div>
      )}

      {/* No modules fallback */}
      {modules.length === 0 && status !== 'enrolled' && status !== 'pending' && !isUnreachable && (
        <div className="text-[10px] text-text-muted italic">
          No module data — waiting for health check
        </div>
      )}
    </div>
  )
}

function Row({ label, value, highlight }) {
  return (
    <div className="flex justify-between">
      <span className="text-text-muted">{label}</span>
      <span className={`font-mono text-xs ${highlight ? 'text-yellow-400' : 'text-text-secondary'}`}>{value}</span>
    </div>
  )
}

function formatUptime(seconds) {
  if (!seconds || seconds <= 0) return '—'
  const d = Math.floor(seconds / 86400)
  const h = Math.floor((seconds % 86400) / 3600)
  const m = Math.floor((seconds % 3600) / 60)
  if (d > 0) return `${d}d ${h}h`
  if (h > 0) return `${h}h ${m}m`
  return `${m}m`
}

