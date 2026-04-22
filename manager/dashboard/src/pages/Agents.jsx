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
    <div className={`glass-card-hover p-5 flex flex-col gap-4 ${isUnreachable ? 'opacity-60' : ''}`}>
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2.5">
          <span className={`w-2 h-2 rounded-full shrink-0 ${dotColor} ${status === 'healthy' ? 'shadow-[0_0_6px_1px] shadow-green-500/50' : ''}`} />
          <span className="font-semibold text-sm text-text-primary truncate">{agent.agent_id}</span>
        </div>
        <span className={`text-[10px] font-bold uppercase tracking-widest px-2 py-0.5 rounded-full border ${
          status === 'healthy'    ? 'border-green-500/30 bg-green-500/10 text-green-400' :
          status === 'degraded'   ? 'border-yellow-500/30 bg-yellow-500/10 text-yellow-400' :
          status === 'unreachable'? 'border-red-500/30 bg-red-500/10 text-red-400' :
          'border-gray-500/30 bg-gray-500/10 text-gray-400'
        }`}>
          {status}
        </span>
      </div>

      {/* Unreachable notice */}
      {isUnreachable && (
        <div className="flex items-center gap-2 text-[10px] text-red-400/80 bg-red-500/5 border border-red-500/15 rounded-lg px-3 py-2">
          <span className="shrink-0">⚠</span>
          <span>Agent unreachable — data below is from last known check</span>
        </div>
      )}

      {/* Info grid */}
      <div className="grid grid-cols-2 gap-x-4 gap-y-1.5 text-xs">
        <InfoCell label="Host" value={agent.host || '—'} />
        {version && <InfoCell label="Version" value={version} />}
        <InfoCell label="Last check" value={formatTime(agent.last_check)} />
        <InfoCell label="Last push" value={formatTime(lastPush)} />
        {agent.registered_at && <InfoCell label="Registered" value={formatTime(agent.registered_at)} />}
        {!isUnreachable && uptime != null && <InfoCell label="Uptime" value={formatUptime(uptime)} />}
        {!isUnreachable && pending != null && (
          <InfoCell label="Buffer" value={String(pending)} highlight={pending > 500} />
        )}
      </div>

      {/* Services */}
      {modules.length > 0 && (
        <div className="border-t border-white/5 pt-3 space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-semibold uppercase tracking-widest text-text-muted">Services</span>
            {!isUnreachable && (
              <span className={`text-[10px] font-mono font-semibold ${
                stopped.length === 0 ? 'text-green-400' : 'text-yellow-400'
              }`}>
                {running.length}/{modules.length}
              </span>
            )}
          </div>
          <div className="flex flex-wrap gap-1.5">
            {modules.map(m => {
              const isRunning = m.status === 'running'
              return (
                <span
                  key={m.name}
                  title={isUnreachable ? `${m.container || m.name} — unknown (agent unreachable)` : `${m.container || m.name} — ${m.status}`}
                  className={`px-2 py-0.5 rounded-md text-[10px] font-semibold border transition-colors ${
                    isUnreachable
                      ? 'bg-gray-500/8 text-gray-500 border-gray-500/15'
                      : isRunning
                      ? 'bg-green-500/10 text-green-400 border-green-500/20'
                      : 'bg-gray-500/10 text-gray-500 border-gray-500/20 line-through decoration-gray-600'
                  }`}
                >
                  {m.name}
                </span>
              )
            })}
          </div>
          {!isUnreachable && stopped.length > 0 && (
            <p className="text-[10px] text-yellow-400/70">
              {stopped.length} stopped: {stopped.map(m => m.name).join(', ')}
            </p>
          )}
        </div>
      )}

      {/* No modules fallback */}
      {modules.length === 0 && status !== 'enrolled' && status !== 'pending' && !isUnreachable && (
        <div className="text-[10px] text-text-muted italic border-t border-white/5 pt-3">
          No module data — waiting for health check
        </div>
      )}
    </div>
  )
}

function InfoCell({ label, value, highlight }) {
  return (
    <div className="flex flex-col gap-0.5 min-w-0">
      <span className="text-[9px] uppercase tracking-wider text-text-muted font-medium">{label}</span>
      <span className={`font-mono text-[11px] truncate ${highlight ? 'text-yellow-400' : 'text-text-secondary'}`}>{value}</span>
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

