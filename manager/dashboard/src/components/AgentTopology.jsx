import { useCallback, useEffect, useMemo, useReducer, useRef, useState } from 'react'

const PROTOCOL_COLOR = {
  ssh:    '#5b8db8',
  http:   '#7aa886',
  ftp:    '#b08aa0',
  modbus: '#8a82b0',
  mqtt:   '#c0926a',
  telnet: '#b08585',
}

const CANVAS_W = 1600
const CANVAS_H = 540

const NODE_DIMS = {
  manager: { w: 220, h: 54, rx: 12, font: 14 },
  agent:   { w: 180, h: 42, rx: 9,  font: 12 },
  module:  { w: 116, h: 30, rx: 7,  font: 11 },
}

const LS_POSITIONS = 'melissae:topology:positions:v3'

const ZOOM_MIN = 0.3
const ZOOM_MAX = 3.0
const ZOOM_STEP = 1.18

const SIM = {
  springK: 0.022,
  agentRest: 200,
  moduleRest: 130,
  repelPad: 22,
  repelStrength: 0.55,
  damping: 0.78,
  depthGravity: 0.018,
  centerPullX: 0.0008,
  settleEpsilon: 0.04,
  settleFrames: 45,
  maxStepDelta: 22,
}

const FIT_PADDING = 40

// Map a module/container name to its protocol bucket
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

function clamp(v, lo, hi) { return Math.max(lo, Math.min(hi, v)) }

function truncate(str, n) {
  const s = String(str || '')
  return s.length > n ? s.slice(0, n - 1) + '…' : s
}

// Aggregate the agent's modules into one entry per protocol
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
  return [...map.values()].sort((a, b) => a.protocol.localeCompare(b.protocol))
}

// Vertical-leaning Bezier curve used for connection paths
function curvePath(p1, p2) {
  const dy = (p2.y - p1.y) / 2
  return `M ${p1.x} ${p1.y} C ${p1.x} ${p1.y + dy}, ${p2.x} ${p2.y - dy}, ${p2.x} ${p2.y}`
}

function loadJSON(key, fallback) {
  try {
    const raw = localStorage.getItem(key)
    if (!raw) return fallback
    const parsed = JSON.parse(raw)
    return parsed && typeof parsed === 'object' ? parsed : fallback
  } catch { return fallback }
}

function saveJSON(key, value) {
  try { localStorage.setItem(key, JSON.stringify(value)) } catch { /* ignore */ }
}

// Build the node graph keyed by id
function buildGraph(agents) {
  const graph = {
    'manager': { id: 'manager', kind: 'manager', parent: null, dims: NODE_DIMS.manager },
  }
  agents.forEach(a => {
    const aId = `agent:${a.agent_id}`
    graph[aId] = { id: aId, kind: 'agent', parent: 'manager', dims: NODE_DIMS.agent, agent: a }
    agentProtocols(a).forEach(p => {
      const mId = `mod:${a.agent_id}:${p.protocol}`
      graph[mId] = { id: mId, kind: 'module', parent: aId, dims: NODE_DIMS.module, agentId: a.agent_id, proto: p }
    })
  })
  return graph
}

// Initial layout seed: manager at top, agents in a centered grid, modules around them
function seedPositions(graph) {
  const pos = {}
  const agentIds = Object.values(graph).filter(n => n.kind === 'agent').map(n => n.id)
  const n = Math.max(1, agentIds.length)

  const cols = Math.max(1, Math.min(n, Math.ceil(Math.sqrt(n * 2.4))))
  const rows = Math.ceil(n / cols)
  const colSpacing = 320
  const rowSpacing = 360

  const gridW = (cols - 1) * colSpacing
  const gridStartX = CANVAS_W / 2 - gridW / 2

  pos['manager'] = { x: CANVAS_W / 2, y: 70 }

  agentIds.forEach((aId, i) => {
    const row = Math.floor(i / cols)
    const col = i % cols
    const isLastRow = row === rows - 1
    const lastRowCount = n - row * cols
    const offset = isLastRow && lastRowCount < cols
      ? ((cols - lastRowCount) * colSpacing) / 2
      : 0
    const x = gridStartX + col * colSpacing + offset
    const y = 230 + row * rowSpacing
    pos[aId] = { x, y }

    const children = Object.values(graph).filter(c => c.parent === aId)
    const k = children.length
    const spread = Math.min(140, (k - 1) * 32) * Math.PI / 180
    children.forEach((c, j) => {
      const t = k <= 1 ? 0 : j / (k - 1) - 0.5
      const angle = t * spread
      pos[c.id] = {
        x: x + Math.sin(angle) * 130,
        y: y + Math.cos(angle) * 130 + 30,
      }
    })
  })
  return pos
}

// Live attack topology with force-directed layout, pan/zoom and per-log flashes
export default function AgentTopology({ agents = [], logs = [], onModuleClick }) {
  const svgRef = useRef(null)

  const visibleAgents = useMemo(
    () => agents.filter(a => a.status !== 'enrolled' && a.status !== 'pending'),
    [agents]
  )

  const graph = useMemo(() => buildGraph(visibleAgents), [visibleAgents])

  const physRef = useRef({ nodes: {}, settledFrames: 0, running: false, rafId: null })
  const [, forceRender] = useReducer(x => x + 1, 0)

  useEffect(() => {
    const stored = loadJSON(LS_POSITIONS, {})
    const seed = seedPositions(graph)
    const prevNodes = physRef.current.nodes
    const nextNodes = {}
    for (const id of Object.keys(graph)) {
      const meta = graph[id]
      const prev = prevNodes[id]
      const start = prev || stored[id] || seed[id] || { x: CANVAS_W / 2, y: CANVAS_H / 2 }
      nextNodes[id] = {
        id,
        kind: meta.kind,
        parent: meta.parent,
        dims: meta.dims,
        x: start.x,
        y: start.y,
        vx: prev?.vx || 0,
        vy: prev?.vy || 0,
        fx: 0,
        fy: 0,
        pinned: prev?.pinned || false,
      }
    }
    physRef.current.nodes = nextNodes
    physRef.current.settledFrames = 0
    kickSimulation()
    forceRender()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [graph])

  const [view, setView] = useState({ tx: 0, ty: 0, s: 1 })
  const [autoFit, setAutoFit] = useState(true)
  const viewRef = useRef(view)
  useEffect(() => { viewRef.current = view }, [view])
  const autoFitRef = useRef(autoFit)
  useEffect(() => { autoFitRef.current = autoFit }, [autoFit])

  // Run the physics loop until the layout settles, then persist
  const kickSimulation = useCallback(() => {
    const phys = physRef.current
    if (phys.running) {
      phys.settledFrames = 0
      return
    }
    phys.running = true
    phys.settledFrames = 0
    const tick = () => {
      const maxKE = stepPhysics(phys.nodes)
      if (autoFitRef.current) {
        const next = computeFitView(phys.nodes)
        if (next) setView(next)
      }
      forceRender()
      if (maxKE < SIM.settleEpsilon) phys.settledFrames++
      else phys.settledFrames = 0

      if (phys.settledFrames >= SIM.settleFrames) {
        phys.running = false
        phys.rafId = null
        const snapshot = {}
        for (const n of Object.values(phys.nodes)) snapshot[n.id] = { x: n.x, y: n.y }
        saveJSON(LS_POSITIONS, snapshot)
        return
      }
      phys.rafId = requestAnimationFrame(tick)
    }
    phys.rafId = requestAnimationFrame(tick)
  }, [])

  useEffect(() => () => {
    const phys = physRef.current
    if (phys.rafId) cancelAnimationFrame(phys.rafId)
    phys.running = false
  }, [])

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
    x: (sx - viewRef.current.tx) / viewRef.current.s,
    y: (sy - viewRef.current.ty) / viewRef.current.s,
  }), [])

  const onPointerDownNode = (e, id) => {
    e.stopPropagation()
    if (e.button !== undefined && e.button !== 0) return
    const node = physRef.current.nodes[id]
    if (!node) return
    const svgPt = screenToSvg(e.clientX, e.clientY)
    const world = svgToWorld(svgPt.x, svgPt.y)
    dragRef.current = {
      kind: 'node',
      id,
      moved: false,
      offX: world.x - node.x,
      offY: world.y - node.y,
    }
    node.pinned = true
    node.vx = 0
    node.vy = 0
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
    setAutoFit(false)
    e.currentTarget.setPointerCapture?.(e.pointerId)
  }

  const onPointerMove = e => {
    const drag = dragRef.current
    if (!drag) return

    if (drag.kind === 'node') {
      const svgPt = screenToSvg(e.clientX, e.clientY)
      const world = svgToWorld(svgPt.x, svgPt.y)
      drag.moved = true
      const node = physRef.current.nodes[drag.id]
      if (node) {
        node.x = world.x - drag.offX
        node.y = world.y - drag.offY
        node.vx = 0
        node.vy = 0
      }
      kickSimulation()
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

    if (drag && drag.kind === 'node') {
      if (!drag.moved && drag.id.startsWith('mod:')) {
        const node = physRef.current.nodes[drag.id]
        if (node) {
          const [, agentId, proto] = drag.id.split(':')
          if (onModuleClick) onModuleClick(proto, agentId)
        }
      }
      kickSimulation()
    }
  }

  const onWheel = e => {
    e.preventDefault()
    setAutoFit(false)
    const svgPt = screenToSvg(e.clientX, e.clientY)
    setView(v => {
      const factor = e.deltaY < 0 ? ZOOM_STEP : 1 / ZOOM_STEP
      const newS = clamp(v.s * factor, ZOOM_MIN, ZOOM_MAX)
      const wx = (svgPt.x - v.tx) / v.s
      const wy = (svgPt.y - v.ty) / v.s
      return { s: newS, tx: svgPt.x - wx * newS, ty: svgPt.y - wy * newS }
    })
  }

  const zoomBy = useCallback(factor => {
    setAutoFit(false)
    setView(v => {
      const newS = clamp(v.s * factor, ZOOM_MIN, ZOOM_MAX)
      const cx = CANVAS_W / 2
      const cy = CANVAS_H / 2
      const wx = (cx - v.tx) / v.s
      const wy = (cy - v.ty) / v.s
      return { s: newS, tx: cx - wx * newS, ty: cy - wy * newS }
    })
  }, [])

  const fitNow = useCallback(() => {
    setAutoFit(true)
    const next = computeFitView(physRef.current.nodes)
    if (next) setView(next)
  }, [])

  const resetLayout = useCallback(() => {
    const seed = seedPositions(graph)
    for (const id of Object.keys(physRef.current.nodes)) {
      const n = physRef.current.nodes[id]
      const s = seed[id]
      if (s) { n.x = s.x; n.y = s.y; n.vx = 0; n.vy = 0; n.pinned = false }
    }
    try { localStorage.removeItem(LS_POSITIONS) } catch { /* ignore */ }
    setAutoFit(true)
    kickSimulation()
    forceRender()
  }, [graph, kickSimulation])

  const connections = useMemo(() => {
    const lines = { manager: [], modules: [] }
    const nodes = physRef.current.nodes
    const m = nodes['manager']
    if (!m) return lines
    const mBottom = { x: m.x, y: m.y + m.dims.h / 2 }

    for (const node of Object.values(nodes)) {
      if (node.kind === 'agent') {
        const aTop = { x: node.x, y: node.y - node.dims.h / 2 }
        lines.manager.push({ id: `link-m-${node.id}`, d: curvePath(mBottom, aTop) })
      } else if (node.kind === 'module') {
        const parent = nodes[node.parent]
        if (!parent) continue
        const aBot = { x: parent.x, y: parent.y + parent.dims.h / 2 }
        const modTop = { x: node.x, y: node.y - node.dims.h / 2 }
        const proto = node.id.split(':')[2]
        const agentId = node.id.split(':')[1]
        lines.modules.push({
          id: `link-${node.id}`,
          key: `${agentId}:${proto}`,
          color: PROTOCOL_COLOR[proto] || '#30363d',
          d: curvePath(aBot, modTop),
        })
      }
    }
    return lines
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [graph, view])

  const seenRef = useRef(null)
  const timersRef = useRef(new Set())
  const idCounterRef = useRef(0)
  const [flashes, setFlashes] = useState([])
  const [packets, setPackets] = useState([])
  const connectionsRef = useRef(connections)
  useEffect(() => { connectionsRef.current = connections }, [connections])

  useEffect(() => {
    const sigs = new Set(logs.map(logSig))
    if (seenRef.current === null) { seenRef.current = sigs; return }
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

  // Flash a module node and animate a packet along the agent→module link
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

  const cursor = isPanning ? 'grabbing' : draggingId ? 'grabbing' : 'grab'
  const nodes = physRef.current.nodes

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
            {autoFit && <span className="ml-1 text-accent">· auto</span>}
          </span>
          <ToolbarBtn label="−" title="Zoom out" onClick={() => zoomBy(1 / ZOOM_STEP)} />
          <ToolbarBtn label="+" title="Zoom in" onClick={() => zoomBy(ZOOM_STEP)} />
          <ToolbarBtn label="Fit" title="Fit all nodes (re-enable auto-fit)" onClick={fitNow} />
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
                <path key={p.id} d={p.d} stroke={p.color} strokeOpacity="0.55" strokeWidth="1.2" fill="none" strokeDasharray="4 4" />
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

              {/* Nodes */}
              {Object.values(nodes).map(node => {
                const common = {
                  pos: { x: node.x, y: node.y },
                  dims: node.dims,
                  hovered: hoveringId === node.id,
                  dragging: draggingId === node.id,
                  pinned: node.pinned && draggingId !== node.id,
                  onPointerDown: e => onPointerDownNode(e, node.id),
                  onMouseEnter: () => setHoveringId(node.id),
                  onMouseLeave: () => setHoveringId(null),
                }
                if (node.kind === 'manager') return <ManagerNode key={node.id} {...common} />
                if (node.kind === 'agent') {
                  const a = graph[node.id]?.agent
                  return a ? <AgentNode key={node.id} agent={a} {...common} /> : null
                }
                const meta = graph[node.id]
                if (!meta) return null
                const flashing = flashes.some(f => f.nodeId === node.id)
                const a = visibleAgents.find(x => x.agent_id === meta.agentId)
                return (
                  <ProtocolNode
                    key={node.id}
                    proto={meta.proto}
                    flashing={flashing}
                    unreachable={a?.status === 'unreachable'}
                    {...common}
                  />
                )
              })}
            </g>
          </svg>

          {/* Legend */}
          <div className="absolute bottom-2 left-2 flex flex-wrap gap-1.5 text-[10px] font-mono pointer-events-none">
            {Object.entries(PROTOCOL_COLOR).map(([p, c]) => (
              <span key={p} className="px-1.5 py-0.5 rounded bg-surface-secondary/80 border border-border/50" style={{ color: c }}>
                {p}
              </span>
            ))}
          </div>
          <div className="absolute bottom-2 right-2 text-[10px] font-mono text-text-muted pointer-events-none">
            drag · wheel zoom · click protocol
          </div>
        </div>
      )}
    </div>
  )
}

// Force-directed integration step; returns max per-node kinetic energy
function stepPhysics(nodes) {
  const list = Object.values(nodes)
  if (list.length === 0) return 0

  for (const n of list) { n.fx = 0; n.fy = 0 }

  for (const n of list) {
    if (!n.parent) continue
    const p = nodes[n.parent]
    if (!p) continue
    const dx = n.x - p.x
    const dy = n.y - p.y
    const dist = Math.hypot(dx, dy) || 0.0001
    const rest = n.kind === 'agent' ? SIM.agentRest : SIM.moduleRest
    const force = SIM.springK * (dist - rest)
    const ux = dx / dist
    const uy = dy / dist
    n.fx -= ux * force
    n.fy -= uy * force
    p.fx += ux * force * 0.3
    p.fy += uy * force * 0.3

    if (n.y < p.y + rest * 0.35) {
      n.fy += SIM.depthGravity * (p.y + rest * 0.35 - n.y)
    }
  }

  const mgr = nodes['manager']
  if (mgr) {
    mgr.fx += (CANVAS_W / 2 - mgr.x) * SIM.centerPullX
    mgr.fy += (80 - mgr.y) * SIM.centerPullX * 4
  }

  for (let i = 0; i < list.length; i++) {
    for (let j = i + 1; j < list.length; j++) {
      const a = list[i], b = list[j]
      const minDX = (a.dims.w + b.dims.w) / 2 + SIM.repelPad
      const minDY = (a.dims.h + b.dims.h) / 2 + SIM.repelPad
      const dx = b.x - a.x
      const dy = b.y - a.y
      const overlapX = minDX - Math.abs(dx)
      const overlapY = minDY - Math.abs(dy)
      if (overlapX > 0 && overlapY > 0) {
        if (overlapX < overlapY) {
          const push = overlapX * SIM.repelStrength
          const sign = dx === 0 ? (a.id < b.id ? 1 : -1) : (dx > 0 ? 1 : -1)
          a.fx -= push * sign
          b.fx += push * sign
        } else {
          const push = overlapY * SIM.repelStrength
          const sign = dy === 0 ? (a.id < b.id ? 1 : -1) : (dy > 0 ? 1 : -1)
          a.fy -= push * sign
          b.fy += push * sign
        }
      }
    }
  }

  let maxKE = 0
  for (const n of list) {
    if (n.pinned) {
      n.vx = 0; n.vy = 0
      continue
    }
    n.vx = (n.vx + n.fx) * SIM.damping
    n.vy = (n.vy + n.fy) * SIM.damping
    if (n.vx > SIM.maxStepDelta) n.vx = SIM.maxStepDelta
    else if (n.vx < -SIM.maxStepDelta) n.vx = -SIM.maxStepDelta
    if (n.vy > SIM.maxStepDelta) n.vy = SIM.maxStepDelta
    else if (n.vy < -SIM.maxStepDelta) n.vy = -SIM.maxStepDelta

    n.x += n.vx
    n.y += n.vy

    if (!Number.isFinite(n.x)) n.x = CANVAS_W / 2
    if (!Number.isFinite(n.y)) n.y = CANVAS_H / 2

    const ke = Math.abs(n.vx) + Math.abs(n.vy)
    if (ke > maxKE) maxKE = ke
  }
  return maxKE
}

// Compute a {tx, ty, s} that fits all nodes inside the canvas with padding
function computeFitView(nodes) {
  const list = Object.values(nodes)
  if (list.length === 0) return null
  let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity
  for (const n of list) {
    minX = Math.min(minX, n.x - n.dims.w / 2)
    minY = Math.min(minY, n.y - n.dims.h / 2)
    maxX = Math.max(maxX, n.x + n.dims.w / 2)
    maxY = Math.max(maxY, n.y + n.dims.h / 2)
  }
  const bboxW = (maxX - minX) + FIT_PADDING * 2
  const bboxH = (maxY - minY) + FIT_PADDING * 2
  if (bboxW <= 0 || bboxH <= 0) return null
  const s = clamp(Math.min(CANVAS_W / bboxW, CANVAS_H / bboxH), ZOOM_MIN, ZOOM_MAX)
  const cx = (minX + maxX) / 2
  const cy = (minY + maxY) / 2
  const tx = CANVAS_W / 2 - cx * s
  const ty = CANVAS_H / 2 - cy * s
  return { tx, ty, s }
}

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

function ManagerNode({ pos, dims, hovered, dragging, pinned, onPointerDown, onMouseEnter, onMouseLeave }) {
  const { w, h, rx, font } = dims
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
        fill="rgba(99,102,141,0.10)"
        stroke="rgba(129,140,168,0.55)"
        strokeWidth={hovered || dragging ? 2.2 : 1.4}
      />
      {pinned && <PinIndicator x={w - 10} y={10} />}
      <text
        x={w / 2} y={h / 2 + 4}
        textAnchor="middle"
        fontSize={font}
        fontWeight="800"
        letterSpacing="3"
        fill="#9ca3b8"
        style={{ pointerEvents: 'none' }}
      >
        MANAGER
      </text>
    </g>
  )
}

function AgentNode({ agent, pos, dims, hovered, dragging, pinned, onPointerDown, onMouseEnter, onMouseLeave }) {
  const { w, h, rx, font } = dims
  const status = agent.status || 'unknown'
  const dot =
    status === 'healthy'     ? '#5a9d6a' :
    status === 'degraded'    ? '#b89a4a' :
    status === 'unreachable' ? '#b06060' :
                               '#6b7280'
  const stroke =
    status === 'healthy'     ? 'rgba(90,157,106,0.45)' :
    status === 'degraded'    ? 'rgba(184,154,74,0.45)' :
    status === 'unreachable' ? 'rgba(176,96,96,0.45)' :
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
        strokeWidth={hovered || dragging ? 2 : 1.3}
      />
      {pinned && <PinIndicator x={w - 10} y={9} />}
      <circle cx={14} cy={h / 2} r={4} fill={dot} />
      <text
        x={26} y={h / 2 + 4}
        fontSize={font}
        fontWeight="600"
        fill="#e6edf3"
        style={{ pointerEvents: 'none' }}
      >
        {truncate(agent.agent_id, 20)}
      </text>
    </g>
  )
}

function ProtocolNode({ proto, pos, dims, unreachable, hovered, dragging, pinned, flashing, onPointerDown, onMouseEnter, onMouseLeave }) {
  const { w, h, rx, font } = dims
  const color = PROTOCOL_COLOR[proto.protocol] || '#8b949e'
  const isRunning = proto.running
  const opacity = unreachable ? 0.45 : isRunning ? 1 : 0.55
  const fill = flashing ? 'rgba(180,90,90,0.78)' : 'rgba(22,27,34,1)'
  const stroke = flashing ? '#c97878' : isRunning ? color : '#4b5563'
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
      {pinned && <PinIndicator x={w - 8} y={7} />}
      <text
        x={w / 2} y={h / 2 + 4}
        textAnchor="middle"
        fontSize={font}
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

function PinIndicator({ x, y }) {
  return (
    <g transform={`translate(${x - 4} ${y - 4})`} style={{ pointerEvents: 'none' }}>
      <circle cx={4} cy={4} r={3.2} fill="#facc15" stroke="#0d1117" strokeWidth="0.8" />
    </g>
  )
}
