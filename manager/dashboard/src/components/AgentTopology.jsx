import { useCallback, useEffect, useMemo, useRef, useState } from 'react'

const PROTOCOL_COLOR = {
  ssh:    '#38bdf8',
  http:   '#86efac',
  ftp:    '#f9a8d4',
  modbus: '#a78bfa',
  mqtt:   '#fdba74',
  telnet: '#fda4af',
}

// SVG world dimensions — the viewBox the user pans/zooms inside.
const CANVAS_W = 1600
const CANVAS_H = 540

// Node shapes (SVG units).
const NODE = {
  manager: { w: 180, h: 44, rx: 10 },
  agent:   { w: 180, h: 38, rx: 8 },
  module:  { w: 150, h: 30, rx: 6 },
}

const ZOOM_MIN = 0.35
const ZOOM_MAX = 2.5
const ZOOM_STEP = 1.18

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

function clamp(v, lo, hi) {
  return Math.max(lo, Math.min(hi, v))
}

function truncate(str, n) {
  const s = String(str || '')
  return s.length > n ? s.slice(0, n - 1) + '…' : s
}

// Aggregate raw module list into one entry per protocol.
function agentProtocols(agent) {
  const map = new Map()
  for (const m of agent.last_health?.modules || []) {
    const proto = moduleProtocol(m.name)
    if (proto === 'proxy') continue  
    const isRunning = m.status === 'running'
    const entry = map.get(proto) || { protocol: proto, running: false, names: [] }
    entry.running = entry.running || isRunning
    entry.names.push(m.name)
    map.set(proto, entry)
  }
  // Stable ordering for layout determinism.
  return [...map.values()].sort((a, b) => a.protocol.localeCompare(b.protocol))
}

function buildDefaultLayout(agents) {
  const pos = {}
  pos['manager'] = { x: CANVAS_W / 2, y: 60 }
  const n = Math.max(1, agents.length)
  const agentY = 210
  // Protocols fan out around each agent on a circular arc, like tree branches.
  const radius = 140
  const maxSpread = (110 * Math.PI) / 180  // total angular spread, capped at 110°
  agents.forEach((a, i) => {
    const x = (CANVAS_W * (i + 1)) / (n + 1)
    pos[`agent:${a.agent_id}`] = { x, y: agentY }

    const protos = agentProtocols(a)
    const k = protos.length
    if (k === 0) return
    // Tighten the spread for few branches so they stay close to the parent.
    const spread = k === 1 ? 0 : Math.min(maxSpread, (k - 1) * (28 * Math.PI / 180))
    protos.forEach((p, j) => {
      const t = k === 1 ? 0 : j / (k - 1) - 0.5  // -0.5 … +0.5
      const angle = t * spread  // 0 = straight down
      const px = x + Math.sin(angle) * radius
      const py = agentY + Math.cos(angle) * radius + 30
      pos[`mod:${a.agent_id}:${p.protocol}`] = { x: px, y: py }
    })
  })
  return pos
}

// ---- Persistence -----------------------------------------------------------

const LS_POSITIONS = 'melissae:topology:positions:v2'
const LS_VIEW = 'melissae:topology:view:v2'

function loadJSON(key, fallback) {
  try {
    const raw = localStorage.getItem(key)
    if (!raw) return fallback
    const parsed = JSON.parse(raw)
    return parsed && typeof parsed === 'object' ? parsed : fallback
  } catch {
    return fallback
  }
}

function saveJSON(key, value) {
  try { localStorage.setItem(key, JSON.stringify(value)) } catch { /* quota / disabled */ }
}

// Vertical-leaning Bezier curve.
function curvePath(p1, p2) {
  const dy = (p2.y - p1.y) / 2
  return `M ${p1.x} ${p1.y} C ${p1.x} ${p1.y + dy}, ${p2.x} ${p2.y - dy}, ${p2.x} ${p2.y}`
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function AgentTopology({ agents = [], logs = [], onModuleClick }) {
  const svgRef = useRef(null)

  const visibleAgents = useMemo(
    () => agents.filter(a => a.status !== 'enrolled' && a.status !== 'pending'),
    [agents]
  )

  // ---- Node positions (persisted across re-renders / sessions) -----------
  const [positions, setPositions] = useState(() => {
    const stored = loadJSON(LS_POSITIONS, {})
    return { ...buildDefaultLayout(visibleAgents), ...stored }
  })

  useEffect(() => {
    setPositions(prev => {
      const desired = buildDefaultLayout(visibleAgents)
      const next = {}
      for (const id of Object.keys(desired)) {
        next[id] = prev[id] || desired[id]
      }
      return next
    })
  }, [visibleAgents])

  // Persist position changes (debounced via rAF batching from React).
  useEffect(() => { saveJSON(LS_POSITIONS, positions) }, [positions])

  // ---- View transform (pan / zoom), persisted ---------------------------
  const [view, setView] = useState(() => {
    const v = loadJSON(LS_VIEW, null)
    if (v && Number.isFinite(v.tx) && Number.isFinite(v.ty) && Number.isFinite(v.s)) {
      return { tx: v.tx, ty: v.ty, s: clamp(v.s, ZOOM_MIN, ZOOM_MAX) }
    }
    return { tx: 0, ty: 0, s: 1 }
  })
  useEffect(() => { saveJSON(LS_VIEW, view) }, [view])

  // ---- Interaction state ------------------------------------------------
  const dragRef = useRef(null)
  const [draggingId, setDraggingId] = useState(null)
  const [hoveringId, setHoveringId] = useState(null)
  const [isPanning, setIsPanning] = useState(false)

  const screenToSvg = useCallback((clientX, clientY) => {
    const svg = svgRef.current
    if (!svg) return { x: 0, y: 0 }
    const r = svg.getBoundingClientRect()
    return {
      x: ((clientX - r.left) / r.width) * CANVAS_W,
      y: ((clientY - r.top) / r.height) * CANVAS_H,
    }
  }, [])

  const svgToWorld = useCallback((sx, sy) => ({
    x: (sx - view.tx) / view.s,
    y: (sy - view.ty) / view.s,
  }), [view])

  // ---- Pointer handlers -------------------------------------------------
  const onPointerDownNode = (e, id) => {
    e.stopPropagation()
    if (e.button !== undefined && e.button !== 0) return
    const svgPt = screenToSvg(e.clientX, e.clientY)
    const world = svgToWorld(svgPt.x, svgPt.y)
    const cur = positions[id]
    if (!cur) return
    dragRef.current = {
      kind: 'node',
      id,
      moved: false,
      offX: world.x - cur.x,
      offY: world.y - cur.y,
    }
    setDraggingId(id)
    e.currentTarget.setPointerCapture?.(e.pointerId)
  }

  const onPointerDownBackground = e => {
    if (e.button !== undefined && e.button !== 0) return
    dragRef.current = {
      kind: 'pan',
      startX: e.clientX,
      startY: e.clientY,
      origTx: view.tx,
      origTy: view.ty,
    }
    setIsPanning(true)
    e.currentTarget.setPointerCapture?.(e.pointerId)
  }

  const onPointerMove = e => {
    const drag = dragRef.current
    if (!drag) return

    if (drag.kind === 'node') {
      const svgPt = screenToSvg(e.clientX, e.clientY)
      const world = svgToWorld(svgPt.x, svgPt.y)
      drag.moved = true
      setPositions(prev => ({
        ...prev,
        [drag.id]: {
          x: clamp(world.x - drag.offX, 0, CANVAS_W),
          y: clamp(world.y - drag.offY, 0, CANVAS_H),
        },
      }))
    } else if (drag.kind === 'pan') {
      const svg = svgRef.current
      if (!svg) return
      const r = svg.getBoundingClientRect()
      const dx = ((e.clientX - drag.startX) / r.width) * CANVAS_W
      const dy = ((e.clientY - drag.startY) / r.height) * CANVAS_H
      setView(v => ({ ...v, tx: drag.origTx + dx, ty: drag.origTy + dy }))
    }
  }

  const onPointerUp = e => {
    const drag = dragRef.current
    dragRef.current = null
    setDraggingId(null)
    setIsPanning(false)
    e.currentTarget.releasePointerCapture?.(e.pointerId)

    // Click (no drag) on a module node → invoke parent callback.
    if (drag && drag.kind === 'node' && !drag.moved) {
      const id = drag.id
      if (id.startsWith('mod:')) {
        const [, agentId, proto] = id.split(':')
        if (onModuleClick) onModuleClick(proto, agentId)
      }
    }
  }

  const onWheel = e => {
    e.preventDefault()
    const svgPt = screenToSvg(e.clientX, e.clientY)
    setView(v => {
      const factor = e.deltaY < 0 ? ZOOM_STEP : 1 / ZOOM_STEP
      const newS = clamp(v.s * factor, ZOOM_MIN, ZOOM_MAX)
      const wx = (svgPt.x - v.tx) / v.s
      const wy = (svgPt.y - v.ty) / v.s
      return { s: newS, tx: svgPt.x - wx * newS, ty: svgPt.y - wy * newS }
    })
  }

  // ---- Toolbar actions --------------------------------------------------
  const zoomBy = useCallback(factor => {
    setView(v => {
      const newS = clamp(v.s * factor, ZOOM_MIN, ZOOM_MAX)
      const cx = CANVAS_W / 2
      const cy = CANVAS_H / 2
      const wx = (cx - v.tx) / v.s
      const wy = (cy - v.ty) / v.s
      return { s: newS, tx: cx - wx * newS, ty: cy - wy * newS }
    })
  }, [])

  const resetView = useCallback(() => {
    setView({ tx: 0, ty: 0, s: 1 })
  }, [])

  const resetLayout = useCallback(() => {
    const fresh = buildDefaultLayout(visibleAgents)
    setPositions(fresh)
    setView({ tx: 0, ty: 0, s: 1 })
    try {
      localStorage.removeItem(LS_POSITIONS)
      localStorage.removeItem(LS_VIEW)
    } catch { /* ignore */ }
  }, [visibleAgents])

  // ---- Connections -------------------------------------------------------
  const connections = useMemo(() => {
    const lines = { manager: [], modules: [] }
    const mPos = positions['manager']
    if (!mPos) return lines
    const mBottom = { x: mPos.x, y: mPos.y + NODE.manager.h / 2 }

    visibleAgents.forEach(a => {
      const aPos = positions[`agent:${a.agent_id}`]
      if (!aPos) return
      const aTop = { x: aPos.x, y: aPos.y - NODE.agent.h / 2 }
      const aBot = { x: aPos.x, y: aPos.y + NODE.agent.h / 2 }
      lines.manager.push({ id: `link-m-${a.agent_id}`, d: curvePath(mBottom, aTop) })

      agentProtocols(a).forEach(p => {
        const id = `mod:${a.agent_id}:${p.protocol}`
        const modPos = positions[id]
        if (!modPos) return
        const modTop = { x: modPos.x, y: modPos.y - NODE.module.h / 2 }
        lines.modules.push({
          id: `link-${id}`,
          key: `${a.agent_id}:${p.protocol}`,
          color: PROTOCOL_COLOR[p.protocol] || '#30363d',
          d: curvePath(aBot, modTop),
        })
      })
    })
    return lines
  }, [visibleAgents, positions])

  // ---- Live attack effects (flashes + packets) --------------------------
  const seenRef = useRef(null)
  const timersRef = useRef(new Set())
  const idCounterRef = useRef(0)
  const [flashes, setFlashes] = useState([])
  const [packets, setPackets] = useState([])
  const connectionsRef = useRef(connections)
  useEffect(() => { connectionsRef.current = connections }, [connections])

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
        triggerFlash(log)
      }, i * step)
      timersRef.current.add(t)
    })
  }, [logs])

  useEffect(() => () => {
    timersRef.current.forEach(clearTimeout)
    timersRef.current.clear()
  }, [])

  function triggerFlash(log) {
    const proto = String(log.protocol || '').toLowerCase()
    const nodeId = `mod:${log.agent_id}:${proto}`
    const fid = ++idCounterRef.current
    setFlashes(prev => [...prev, { id: fid, nodeId }])
    const t1 = setTimeout(() => {
      timersRef.current.delete(t1)
      setFlashes(prev => prev.filter(f => f.id !== fid))
    }, 1500)
    timersRef.current.add(t1)

    const link = connectionsRef.current.modules.find(p => p.key === `${log.agent_id}:${proto}`)
    if (link) {
      const pid = ++idCounterRef.current
      setPackets(prev => [...prev, { id: pid, d: link.d, color: link.color }])
      const t2 = setTimeout(() => {
        timersRef.current.delete(t2)
        setPackets(prev => prev.filter(p => p.id !== pid))
      }, 950)
      timersRef.current.add(t2)
    }
  }

  // ---- Render ------------------------------------------------------------
  const cursor = isPanning ? 'grabbing' : draggingId ? 'grabbing' : 'grab'

  return (
    <div className="glass-card p-5">
      <div className="flex items-center justify-between mb-3 flex-wrap gap-2">
        <h3 className="section-title flex items-center gap-2">
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-verdict-malicious opacity-60" />
            <span className="relative inline-flex rounded-full h-2 w-2 bg-verdict-malicious" />
          </span>
          Live Attack Map
        </h3>
        <div className="flex items-center gap-2">
          <span className="text-[10px] font-mono text-text-muted mr-1">
            {visibleAgents.length} agent{visibleAgents.length !== 1 ? 's' : ''} · {Math.round(view.s * 100)}%
          </span>
          <ToolbarBtn label="−" title="Zoom out" onClick={() => zoomBy(1 / ZOOM_STEP)} />
          <ToolbarBtn label="+" title="Zoom in" onClick={() => zoomBy(ZOOM_STEP)} />
          <ToolbarBtn label="Fit" title="Reset view" onClick={resetView} />
          <ToolbarBtn label="Auto" title="Re-arrange nodes" onClick={resetLayout} />
        </div>
      </div>

      {visibleAgents.length === 0 ? (
        <div className="text-center text-xs text-text-muted italic py-8">
          No active agents to display
        </div>
      ) : (
        <div className="relative rounded-lg overflow-hidden border border-border bg-surface-tertiary/40">
          <svg
            ref={svgRef}
            viewBox={`0 0 ${CANVAS_W} ${CANVAS_H}`}
            preserveAspectRatio="xMidYMid slice"
            className="block w-full h-full select-none"
            style={{ aspectRatio: `${CANVAS_W} / ${CANVAS_H}`, cursor, touchAction: 'none' }}
            onPointerDown={onPointerDownBackground}
            onPointerMove={onPointerMove}
            onPointerUp={onPointerUp}
            onPointerCancel={onPointerUp}
            onWheel={onWheel}
          >
            <defs>
              <pattern id="topo-grid" width="40" height="40" patternUnits="userSpaceOnUse">
                <path d="M 40 0 L 0 0 0 40" fill="none" stroke="#1f2630" strokeWidth="1" />
              </pattern>
            </defs>
            <rect width={CANVAS_W} height={CANVAS_H} fill="#0d1117" />
            <rect width={CANVAS_W} height={CANVAS_H} fill="url(#topo-grid)" opacity="0.4" />

            <g transform={`translate(${view.tx} ${view.ty}) scale(${view.s})`}>
              {/* Connections */}
              {connections.manager.map(p => (
                <path key={p.id} d={p.d} stroke="#30363d" strokeWidth="1.4" fill="none" />
              ))}
              {connections.modules.map(p => (
                <path
                  key={p.id}
                  d={p.d}
                  stroke={p.color}
                  strokeOpacity="0.55"
                  strokeWidth="1.2"
                  fill="none"
                  strokeDasharray="4 4"
                />
              ))}

              {/* Packets */}
              {packets.map(pk => (
                <g key={pk.id}>
                  <circle r="5" fill={pk.color} fillOpacity="0.25">
                    <animateMotion dur="0.9s" repeatCount="1" fill="freeze" path={pk.d} />
                  </circle>
                  <circle r="3" fill={pk.color}>
                    <animateMotion dur="0.9s" repeatCount="1" fill="freeze" path={pk.d} />
                    <animate attributeName="opacity" from="1" to="0.1" dur="0.9s" fill="freeze" />
                  </circle>
                </g>
              ))}

              {/* Manager node */}
              {positions['manager'] && (
                <ManagerNode
                  pos={positions['manager']}
                  hovered={hoveringId === 'manager'}
                  dragging={draggingId === 'manager'}
                  onPointerDown={e => onPointerDownNode(e, 'manager')}
                  onMouseEnter={() => setHoveringId('manager')}
                  onMouseLeave={() => setHoveringId(null)}
                />
              )}

              {/* Agents + their protocols */}
              {visibleAgents.map(a => {
                const aId = `agent:${a.agent_id}`
                const aPos = positions[aId]
                if (!aPos) return null
                const protos = agentProtocols(a)
                return (
                  <g key={a.agent_id}>
                    <AgentNode
                      agent={a}
                      pos={aPos}
                      hovered={hoveringId === aId}
                      dragging={draggingId === aId}
                      onPointerDown={e => onPointerDownNode(e, aId)}
                      onMouseEnter={() => setHoveringId(aId)}
                      onMouseLeave={() => setHoveringId(null)}
                    />
                    {protos.map(p => {
                      const mId = `mod:${a.agent_id}:${p.protocol}`
                      const mPos = positions[mId]
                      if (!mPos) return null
                      const flashing = flashes.some(f => f.nodeId === mId)
                      return (
                        <ProtocolNode
                          key={mId}
                          proto={p}
                          pos={mPos}
                          unreachable={a.status === 'unreachable'}
                          hovered={hoveringId === mId}
                          dragging={draggingId === mId}
                          flashing={flashing}
                          onPointerDown={e => onPointerDownNode(e, mId)}
                          onMouseEnter={() => setHoveringId(mId)}
                          onMouseLeave={() => setHoveringId(null)}
                        />
                      )
                    })}
                  </g>
                )
              })}
            </g>
          </svg>

          {/* Legend */}
          <div className="absolute bottom-2 left-2 flex flex-wrap gap-1.5 text-[10px] font-mono pointer-events-none">
            {Object.entries(PROTOCOL_COLOR).map(([p, c]) => (
              <span
                key={p}
                className="px-1.5 py-0.5 rounded bg-surface-secondary/80 border border-border/50"
                style={{ color: c }}
              >
                {p}
              </span>
            ))}
          </div>
          <div className="absolute bottom-2 right-2 text-[10px] font-mono text-text-muted pointer-events-none">
            drag · wheel zoom · click module
          </div>
        </div>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// SVG node components
// ---------------------------------------------------------------------------

function ToolbarBtn({ label, title, onClick }) {
  return (
    <button
      type="button"
      onClick={onClick}
      title={title}
      className="px-2 py-1 text-[10px] font-mono font-semibold uppercase tracking-wider bg-surface-tertiary hover:bg-surface-hover border border-border rounded transition-colors text-text-secondary hover:text-text-primary"
    >
      {label}
    </button>
  )
}

function ManagerNode({ pos, hovered, dragging, onPointerDown, onMouseEnter, onMouseLeave }) {
  const { w, h, rx } = NODE.manager
  return (
    <g
      transform={`translate(${pos.x - w / 2} ${pos.y - h / 2})`}
      style={{ cursor: dragging ? 'grabbing' : 'grab' }}
      onPointerDown={onPointerDown}
      onMouseEnter={onMouseEnter}
      onMouseLeave={onMouseLeave}
    >
      <rect
        width={w} height={h} rx={rx} ry={rx}
        fill="rgba(99,102,241,0.12)"
        stroke="rgba(129,140,248,0.6)"
        strokeWidth={hovered || dragging ? 2 : 1.4}
      />
      <text
        x={w / 2} y={h / 2 + 4}
        textAnchor="middle"
        fontSize="13"
        fontWeight="700"
        letterSpacing="3"
        fill="#a5b4fc"
        style={{ pointerEvents: 'none' }}
      >
        MANAGER
      </text>
    </g>
  )
}

function AgentNode({ agent, pos, hovered, dragging, onPointerDown, onMouseEnter, onMouseLeave }) {
  const { w, h, rx } = NODE.agent
  const status = agent.status || 'unknown'
  const dot =
    status === 'healthy'     ? '#22c55e' :
    status === 'degraded'    ? '#eab308' :
    status === 'unreachable' ? '#ef4444' :
                               '#6b7280'
  const stroke =
    status === 'healthy'     ? 'rgba(34,197,94,0.45)' :
    status === 'degraded'    ? 'rgba(234,179,8,0.45)' :
    status === 'unreachable' ? 'rgba(239,68,68,0.45)' :
                               '#30363d'
  const opacity = status === 'unreachable' ? 0.55 : 1
  return (
    <g
      transform={`translate(${pos.x - w / 2} ${pos.y - h / 2})`}
      style={{ cursor: dragging ? 'grabbing' : 'grab', opacity }}
      onPointerDown={onPointerDown}
      onMouseEnter={onMouseEnter}
      onMouseLeave={onMouseLeave}
    >
      <rect
        width={w} height={h} rx={rx} ry={rx}
        fill="#161b22"
        stroke={stroke}
        strokeWidth={hovered || dragging ? 2 : 1.2}
      />
      <circle cx={14} cy={h / 2} r={4} fill={dot} />
      <text
        x={26} y={h / 2 + 4}
        fontSize="12"
        fontWeight="600"
        fill="#e6edf3"
        style={{ pointerEvents: 'none' }}
      >
        {truncate(agent.agent_id, 20)}
      </text>
    </g>
  )
}

function ProtocolNode({ proto, pos, unreachable, hovered, dragging, flashing, onPointerDown, onMouseEnter, onMouseLeave }) {
  const { w, h, rx } = NODE.module
  const color = PROTOCOL_COLOR[proto.protocol] || '#8b949e'
  const isRunning = proto.running
  const opacity = unreachable ? 0.45 : isRunning ? 1 : 0.55
  const fill = flashing ? 'rgba(248,113,113,0.85)' : 'rgba(22,27,34,1)'
  const stroke = flashing ? '#fca5a5' : isRunning ? color : '#4b5563'
  const titleAttr = proto.names.length > 0 ? proto.names.join(', ') : proto.protocol

  return (
    <g
      transform={`translate(${pos.x - w / 2} ${pos.y - h / 2})`}
      style={{ cursor: unreachable ? 'default' : (dragging ? 'grabbing' : 'grab'), opacity }}
      onPointerDown={unreachable ? undefined : onPointerDown}
      onMouseEnter={onMouseEnter}
      onMouseLeave={onMouseLeave}
    >
      <title>{titleAttr}</title>
      {flashing && (
        <rect
          x={-6} y={-6} width={w + 12} height={h + 12} rx={rx + 4} ry={rx + 4}
          fill="none" stroke="#f87171" strokeWidth="2" opacity="0.9"
        >
          <animate attributeName="opacity" values="0.9;0" dur="1.4s" fill="freeze" />
          <animate attributeName="stroke-width" values="2;10" dur="1.4s" fill="freeze" />
        </rect>
      )}
      <rect
        width={w} height={h} rx={rx} ry={rx}
        fill={fill}
        stroke={stroke}
        strokeWidth={hovered || dragging || flashing ? 2 : 1.2}
        style={{ transition: 'fill 180ms, stroke 180ms' }}
      />
      <text
        x={w / 2} y={h / 2 + 4}
        textAnchor="middle"
        fontSize="12"
        fontWeight="700"
        letterSpacing="2"
        fill={flashing ? '#1a0a0a' : (isRunning ? color : '#9ca3af')}
        style={{ pointerEvents: 'none', textDecoration: isRunning ? 'none' : 'line-through' }}
      >
        {String(proto.protocol).toUpperCase()}
      </text>
    </g>
  )
}
