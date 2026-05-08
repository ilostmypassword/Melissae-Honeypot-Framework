import { useEffect, useRef, useState, useMemo } from 'react'

const PROTOCOL_COLORS = {
  ssh:    'border-protocol-ssh/40    text-protocol-ssh',
  http:   'border-protocol-http/40   text-protocol-http',
  ftp:    'border-protocol-ftp/40    text-protocol-ftp',
  modbus: 'border-protocol-modbus/40 text-protocol-modbus',
  mqtt:   'border-protocol-mqtt/40   text-protocol-mqtt',
  telnet: 'border-protocol-telnet/40 text-protocol-telnet',
}

// Map a module/container name to the protocol field used in logs.
function moduleProtocol(name) {
  const n = String(name || '').toLowerCase()
  if (n.includes('ssh'))    return 'ssh'
  if (n.includes('ftp'))    return 'ftp'
  if (n.includes('modbus')) return 'modbus'
  if (n.includes('mqtt'))   return 'mqtt'
  if (n.includes('telnet')) return 'telnet'
  if (n.includes('web') || n.includes('http') || n.includes('apache') || n.includes('nginx')) return 'http'
  if (n.includes('cve'))    return 'http'
  return n
}

function logSig(l) {
  return `${l.agent_id || ''}|${l.protocol || ''}|${l.timestamp || ''}|${l.date || ''}|${l.hour || ''}|${l.ip || ''}|${l.action || ''}|${l.path || ''}`
}

// Live attack topology: agents with their honeypot modules; modules flash red
// as attacks land on them. New logs since the previous refresh are replayed
// over a short window to give a continuous "live" feel between polls.
export default function AgentTopology({ agents = [], logs = [], onModuleClick }) {
  const [tick, setTick] = useState(0)
  const flashesRef = useRef(new Map()) // key -> expiry epoch ms
  const seenRef = useRef(null)         // Set of log signatures from the last fetch
  const timersRef = useRef(new Set())  // pending setTimeout handles, pruned on fire

  // Replay newly-arrived logs as flashes, spread over a short window.
  useEffect(() => {
    const sigs = new Set(logs.map(logSig))

    if (seenRef.current === null) {
      seenRef.current = sigs
      return
    }

    const newLogs = logs.filter(l => !seenRef.current.has(logSig(l)))
    seenRef.current = sigs

    if (newLogs.length === 0) return

    // Sort oldest → newest so the replay matches arrival order.
    newLogs.sort((a, b) => String(a.timestamp || '').localeCompare(String(b.timestamp || '')))

    const SPREAD_MS = Math.min(12000, Math.max(800, newLogs.length * 250))
    const FLASH_MS  = 1400
    const step = SPREAD_MS / newLogs.length

    newLogs.forEach((log, i) => {
      const t = setTimeout(() => {
        timersRef.current.delete(t)
        const key = `${log.agent_id}:${log.protocol}`
        flashesRef.current.set(key, Date.now() + FLASH_MS)
        setTick(x => x + 1)
        const t2 = setTimeout(() => {
          timersRef.current.delete(t2)
          const exp = flashesRef.current.get(key)
          if (exp != null && exp <= Date.now()) {
            flashesRef.current.delete(key)
            setTick(x => x + 1)
          }
        }, FLASH_MS + 50)
        timersRef.current.add(t2)
      }, i * step)
      timersRef.current.add(t)
    })
  }, [logs])

  useEffect(() => () => {
    timersRef.current.forEach(clearTimeout)
    timersRef.current.clear()
  }, [])

  // Aggregate active flashes count for the header indicator
  const activeFlashes = useMemo(() => {
    let n = 0
    const now = Date.now()
    flashesRef.current.forEach(exp => { if (exp > now) n++ })
    return n
  }, [tick])

  const visibleAgents = agents.filter(a => a.status !== 'enrolled' && a.status !== 'pending')

  return (
    <div className="glass-card p-5">
      <div className="flex items-center justify-between mb-4">
        <h3 className="section-title flex items-center gap-2">
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-verdict-malicious opacity-60" />
            <span className="relative inline-flex rounded-full h-2 w-2 bg-verdict-malicious" />
          </span>
          Live Attack Map
        </h3>
        <span className="text-[10px] font-mono text-text-muted">
          {activeFlashes > 0 ? `${activeFlashes} active` : 'idle'}
        </span>
      </div>

      {visibleAgents.length === 0 ? (
        <div className="text-center text-xs text-text-muted italic py-6">
          No active agents to display
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {visibleAgents.map(a => (
            <AgentNode
              key={a.agent_id}
              agent={a}
              flashes={flashesRef.current}
              tick={tick}
              onModuleClick={onModuleClick}
            />
          ))}
        </div>
      )}
    </div>
  )
}

function AgentNode({ agent, flashes, tick, onModuleClick }) {
  const status = agent.status || 'unknown'
  const isUnreachable = status === 'unreachable'
  const modules = agent.last_health?.modules || []
  const dotColor =
    status === 'healthy'    ? 'bg-green-500 shadow-[0_0_6px_1px] shadow-green-500/50' :
    status === 'degraded'   ? 'bg-yellow-500' :
    status === 'unreachable'? 'bg-red-500' :
                              'bg-gray-500'

  // tick consumed via parent re-render; reading the ref each render gives current state
  void tick

  return (
    <div className={`rounded-xl border border-border bg-surface-tertiary/40 p-3 ${isUnreachable ? 'opacity-50' : ''}`}>
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2 min-w-0">
          <span className={`w-2 h-2 rounded-full shrink-0 ${dotColor}`} />
          <span className="text-xs font-semibold text-text-primary truncate">{agent.agent_id}</span>
        </div>
        <span className="text-[9px] font-mono text-text-muted truncate ml-2">{agent.host || ''}</span>
      </div>

      {modules.length === 0 ? (
        <div className="text-[10px] text-text-muted italic py-2">no modules</div>
      ) : (
        <div className="flex flex-wrap gap-1.5">
          {modules.map(m => (
            <ModulePill
              key={m.name}
              module={m}
              agentId={agent.agent_id}
              isUnreachable={isUnreachable}
              flashes={flashes}
              onModuleClick={onModuleClick}
            />
          ))}
        </div>
      )}
    </div>
  )
}

function ModulePill({ module, agentId, isUnreachable, flashes, onModuleClick }) {
  const protocol = moduleProtocol(module.name)
  const isRunning = module.status === 'running'
  const key = `${agentId}:${protocol}`
  const exp = flashes.get(key)
  const isFlashing = exp != null && exp > Date.now()
  const colorClass = PROTOCOL_COLORS[protocol] || 'border-border text-text-secondary'

  const baseClass = isUnreachable
    ? 'border-gray-500/15 text-gray-500 bg-gray-500/5'
    : isRunning
      ? `bg-surface-secondary ${colorClass}`
      : 'border-gray-500/20 text-gray-500 bg-gray-500/5 line-through decoration-gray-600'

  const handleClick = () => {
    if (isUnreachable || !onModuleClick) return
    onModuleClick(protocol, agentId)
  }

  return (
    <button
      type="button"
      onClick={handleClick}
      title={`${module.name} — ${module.status}${isFlashing ? ' (under attack)' : ''}`}
      className={`relative px-2 py-1 rounded-md text-[10px] font-semibold border transition-colors ${baseClass} ${
        onModuleClick && !isUnreachable ? 'cursor-pointer hover:border-border-light' : 'cursor-default'
      } ${isFlashing ? 'animate-attack-flash' : ''}`}
    >
      {module.name}
    </button>
  )
}
