import { useEffect, useRef, useState, useMemo } from 'react'

const PROTOCOL_COLOR = {
  ssh:    '#38bdf8',
  http:   '#86efac',
  ftp:    '#f9a8d4',
  modbus: '#a78bfa',
  mqtt:   '#fdba74',
  telnet: '#fda4af',
}

// Map a module/container name to the protocol field used in logs.
function moduleProtocol(name) {
  const n = String(name || '').toLowerCase()
  if (n.includes('ssh'))    return 'ssh'
  if (n.includes('ftp'))    return 'ftp'
  if (n.includes('modbus')) return 'modbus'
  if (n.includes('mqtt'))   return 'mqtt'
  if (n.includes('telnet')) return 'telnet'
  if (n.includes('web') || n.includes('http') || n.includes('apache') || n.includes('nginx') || n.includes('cve')) return 'http'
  return n
}

function logSig(l) {
  return `${l.agent_id || ''}|${l.protocol || ''}|${l.timestamp || ''}|${l.date || ''}|${l.hour || ''}|${l.ip || ''}|${l.action || ''}|${l.path || ''}`
}

// Live attack topology: a real schematic with the Manager at the top,
// connected by curves to each Agent, and each Agent connected to its modules.
// Every incoming log triggers a discrete red flash on the targeted module
// (Web Animations API — multiple logs cause repeated flashes that overlap).
export default function AgentTopology({ agents = [], logs = [], onModuleClick }) {
  const containerRef = useRef(null)
  const managerRef = useRef(null)
  const agentRefs = useRef(new Map())   // agent_id -> DOM element
  const moduleRefs = useRef(new Map())  // 'agent_id:protocol' -> DOM element

  const [paths, setPaths] = useState({ manager: [], modules: [] })
  const [packets, setPackets] = useState([]) // [{ id, d, color }]
  const pathsRef = useRef(paths)
  const seenRef = useRef(null)
  const timersRef = useRef(new Set())
  const packetIdRef = useRef(0)

  useEffect(() => { pathsRef.current = paths }, [paths])

  const visibleAgents = useMemo(
    () => agents.filter(a => a.status !== 'enrolled' && a.status !== 'pending'),
    [agents]
  )

  // Recompute connection paths from current DOM positions
  useEffect(() => {
    const compute = () => {
      const container = containerRef.current
      const manager = managerRef.current
      if (!container || !manager) return
      const cRect = container.getBoundingClientRect()
      const point = (el, edge) => {
        const r = el.getBoundingClientRect()
        const x = r.left - cRect.left + r.width / 2
        const y = (edge === 'top' ? r.top : r.bottom) - cRect.top
        return { x, y }
      }

      const mPt = point(manager, 'bottom')
      const managerPaths = []
      const modulePaths = []

      visibleAgents.forEach(a => {
        const aEl = agentRefs.current.get(a.agent_id)
        if (!aEl) return
        const aTop = point(aEl, 'top')
        const aBot = point(aEl, 'bottom')
        const dy = (aTop.y - mPt.y) / 2
        managerPaths.push({
          id: `m-${a.agent_id}`,
          d: `M ${mPt.x} ${mPt.y} C ${mPt.x} ${mPt.y + dy}, ${aTop.x} ${aTop.y - dy}, ${aTop.x} ${aTop.y}`,
        })

        const modules = a.last_health?.modules || []
        modules.forEach(m => {
          const proto = moduleProtocol(m.name)
          const key = `${a.agent_id}:${proto}`
          const mEl = moduleRefs.current.get(key)
          if (!mEl) return
          const moduleLeft = (() => {
            const r = mEl.getBoundingClientRect()
            return { x: r.left - cRect.left, y: r.top - cRect.top + r.height / 2 }
          })()
          // Bezier from agent bottom-center to module left-center
          const cx1 = aBot.x
          const cy1 = (aBot.y + moduleLeft.y) / 2
          const cx2 = moduleLeft.x - 20
          const cy2 = moduleLeft.y
          modulePaths.push({
            id: `mod-${key}`,
            key,
            color: PROTOCOL_COLOR[proto] || '#30363d',
            d: `M ${aBot.x} ${aBot.y} C ${cx1} ${cy1}, ${cx2} ${cy2}, ${moduleLeft.x} ${moduleLeft.y}`,
          })
        })
      })

      setPaths({ manager: managerPaths, modules: modulePaths })
    }

    compute()
    const ro = new ResizeObserver(compute)
    if (containerRef.current) ro.observe(containerRef.current)
    window.addEventListener('resize', compute)
    return () => {
      ro.disconnect()
      window.removeEventListener('resize', compute)
    }
  }, [visibleAgents])

  // Detect new logs and fire one flash per log, replayed over a short window
  useEffect(() => {
    const sigs = new Set(logs.map(logSig))

    if (seenRef.current === null) {
      seenRef.current = sigs
      return
    }

    const newLogs = logs.filter(l => !seenRef.current.has(logSig(l)))
    seenRef.current = sigs
    if (newLogs.length === 0) return

    newLogs.sort((a, b) => String(a.timestamp || '').localeCompare(String(b.timestamp || '')))
    const SPREAD = Math.min(15000, Math.max(1000, newLogs.length * 250))
    const step = SPREAD / newLogs.length

    newLogs.forEach((log, i) => {
      const t = setTimeout(() => {
        timersRef.current.delete(t)
        flashLog(log)
      }, i * step)
      timersRef.current.add(t)
    })
  }, [logs])

  // Cleanup on unmount
  useEffect(() => () => {
    timersRef.current.forEach(clearTimeout)
    timersRef.current.clear()
  }, [])

  function flashLog(log) {
    const proto = String(log.protocol || '').toLowerCase()
    const key = `${log.agent_id}:${proto}`
    const el = moduleRefs.current.get(key)
    if (el && el.animate) {
      el.animate(
        [
          { boxShadow: '0 0 0 0 rgba(248, 113, 113, 0)',          backgroundColor: 'rgba(22, 27, 34, 1)',         borderColor: 'rgba(48, 54, 61, 1)',          transform: 'scale(1)' },
          { boxShadow: '0 0 16px 4px rgba(248, 113, 113, 0.95)',  backgroundColor: 'rgba(248, 113, 113, 0.75)',   borderColor: 'rgba(252, 165, 165, 1)',       transform: 'scale(1.12)', offset: 0.18 },
          { boxShadow: '0 0 8px 2px rgba(248, 113, 113, 0.45)',   backgroundColor: 'rgba(248, 113, 113, 0.30)',   borderColor: 'rgba(248, 113, 113, 0.65)',    transform: 'scale(1.04)', offset: 0.55 },
          { boxShadow: '0 0 0 0 rgba(248, 113, 113, 0)',          backgroundColor: 'rgba(22, 27, 34, 1)',         borderColor: 'rgba(48, 54, 61, 1)',          transform: 'scale(1)' },
        ],
        { duration: 1800, easing: 'ease-out', composite: 'replace' }
      )
    }

    // Animate a packet along the agent→module connection
    const path = pathsRef.current.modules.find(p => p.key === key)
    if (path) {
      const id = ++packetIdRef.current
      setPackets(prev => [...prev, { id, d: path.d, color: path.color }])
      const t = setTimeout(() => {
        timersRef.current.delete(t)
        setPackets(prev => prev.filter(p => p.id !== id))
      }, 900)
      timersRef.current.add(t)
    }
  }

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
          {visibleAgents.length} agent{visibleAgents.length !== 1 ? 's' : ''}
        </span>
      </div>

      {visibleAgents.length === 0 ? (
        <div className="text-center text-xs text-text-muted italic py-8">
          No active agents to display
        </div>
      ) : (
        <div ref={containerRef} className="relative">
          {/* SVG connection layer */}
          <svg className="absolute inset-0 w-full h-full pointer-events-none" style={{ zIndex: 0 }}>
            {paths.manager.map(p => (
              <path key={p.id} d={p.d} stroke="#30363d" strokeWidth="1.2" fill="none" />
            ))}
            {paths.modules.map(p => (
              <path key={p.id} d={p.d} stroke="#30363d" strokeWidth="1" fill="none" strokeDasharray="3 3" opacity="0.7" />
            ))}
            {packets.map(pk => (
              <circle key={pk.id} r="3.5" fill="#f87171" stroke="#fca5a5" strokeWidth="1">
                <animateMotion dur="0.85s" repeatCount="1" fill="freeze" path={pk.d} />
                <animate attributeName="opacity" from="1" to="0" dur="0.85s" fill="freeze" />
              </circle>
            ))}
          </svg>

          {/* Manager node */}
          <div className="flex justify-center mb-12 relative" style={{ zIndex: 1 }}>
            <div
              ref={managerRef}
              className="px-4 py-2 rounded-lg bg-accent/10 border border-accent/40 text-accent text-xs font-bold uppercase tracking-[0.2em] shadow-[0_0_12px_rgba(99,102,241,0.25)]"
            >
              Manager
            </div>
          </div>

          {/* Agent columns */}
          <div
            className="grid gap-6 relative"
            style={{ zIndex: 1, gridTemplateColumns: `repeat(${Math.max(1, visibleAgents.length)}, minmax(0, 1fr))` }}
          >
            {visibleAgents.map(a => (
              <AgentColumn
                key={a.agent_id}
                agent={a}
                registerAgent={el => {
                  if (el) agentRefs.current.set(a.agent_id, el)
                  else agentRefs.current.delete(a.agent_id)
                }}
                registerModule={(k, el) => {
                  if (el) moduleRefs.current.set(k, el)
                  else moduleRefs.current.delete(k)
                }}
                onModuleClick={onModuleClick}
              />
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

function AgentColumn({ agent, registerAgent, registerModule, onModuleClick }) {
  const status = agent.status || 'unknown'
  const isUnreachable = status === 'unreachable'
  const modules = agent.last_health?.modules || []
  const dotColor =
    status === 'healthy'    ? 'bg-green-500' :
    status === 'degraded'   ? 'bg-yellow-500' :
    status === 'unreachable'? 'bg-red-500' :
                              'bg-gray-500'
  const borderColor =
    status === 'healthy'    ? 'border-green-500/30' :
    status === 'degraded'   ? 'border-yellow-500/30' :
    status === 'unreachable'? 'border-red-500/30' :
                              'border-border'

  return (
    <div className={`flex flex-col items-center ${isUnreachable ? 'opacity-50' : ''}`}>
      <div
        ref={registerAgent}
        className={`px-3 py-1.5 rounded-md border bg-surface-tertiary text-text-primary text-xs font-semibold mb-6 shadow-card ${borderColor}`}
      >
        <span className={`inline-block w-1.5 h-1.5 rounded-full mr-2 align-middle ${dotColor}`} />
        {agent.agent_id}
      </div>

      {modules.length === 0 ? (
        <div className="text-[10px] text-text-muted italic">no modules</div>
      ) : (
        <div className="flex flex-col gap-2 items-stretch w-full max-w-[150px]">
          {modules.map(m => (
            <ModulePill
              key={m.name}
              module={m}
              agentId={agent.agent_id}
              isUnreachable={isUnreachable}
              registerModule={registerModule}
              onModuleClick={onModuleClick}
            />
          ))}
        </div>
      )}
    </div>
  )
}

function ModulePill({ module, agentId, isUnreachable, registerModule, onModuleClick }) {
  const proto = moduleProtocol(module.name)
  const key = `${agentId}:${proto}`
  const isRunning = module.status === 'running'
  const color = PROTOCOL_COLOR[proto]

  const handleRef = el => {
    if (el) registerModule(key, el)
    else registerModule(key, null)
  }

  return (
    <button
      ref={handleRef}
      type="button"
      onClick={() => { if (!isUnreachable && onModuleClick) onModuleClick(proto, agentId) }}
      title={`${module.name} — ${module.status}`}
      style={isRunning && !isUnreachable && color ? { color } : undefined}
      className={`px-2.5 py-1 rounded-md text-[10px] font-semibold border bg-surface-secondary transition-colors ${
        isUnreachable
          ? 'border-gray-500/15 text-gray-500'
          : isRunning
            ? 'border-border hover:border-border-light cursor-pointer'
            : 'border-gray-500/20 text-gray-500 line-through decoration-gray-600 cursor-default'
      }`}
    >
      {module.name}
    </button>
  )
}
