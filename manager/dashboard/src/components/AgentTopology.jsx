import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { compareLogTimestampsDesc } from '../utils'

const PROTOCOL_COLOR = {
  ssh:    '#6f96ad',
  http:   '#8fa88f',
  ftp:    '#b18aa0',
  modbus: '#958bb0',
  mqtt:   '#b59a75',
  telnet: '#ad8582',
}

const CANVAS_W = 1800
const CANVAS_H = 480

const NODE_DIMS = {
  manager: { w: 240, h: 56, rx: 12, font: 14 },
  agent:   { w: 200, h: 44, rx: 10, font: 12 },
  module:  { w: 130, h: 32, rx: 7,  font: 11 },
}

const SPACING = {
  agentGapX:        90,
  moduleGapX:       18,
  moduleGapY:       12,
  moduleColsMax:    3,
  rowVSpace:        140,
  managerY:         80,
  firstAgentY:      260,
  agentToModuleY:   100,
}

const LS_POSITIONS = 'melissae:topology:positions:v5'

const ZOOM_MIN = 0.3
const ZOOM_MAX = 2.5
const ZOOM_STEP = 1.2
const FIT_PADDING = 60

// Map an arbitrary container/log name to its canonical protocol bucket.
function moduleProtocol(name) {
  const n = String(name || '').toLowerCase()
  if (n.includes('cve'))    return 'telnet'
  if (n.includes('ssh'))    return 'ssh'
  if (n.includes('telnet')) return 'telnet'
  if (n.includes('ftp'))    return 'ftp'
  if (n.includes('modbus')) return 'modbus'
  if (n.includes('mqtt'))   return 'mqtt'
  if (n.includes('web') || n.includes('http') || n.includes('apache') || n.includes('nginx')) return 'http'
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

// Aggregate the agent's modules into one entry per protocol.
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

// Vertical-leaning Bezier curve for connection paths.
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

// Build the node graph keyed by id.
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

// Static hierarchical layout: manager → agents grid → 2D module grid per agent.
function computeLayout(graph) {
  const pos = {}
  const agentEntries = Object.values(graph)
    .filter(n => n.kind === 'agent')
    .sort((a, b) => a.id.localeCompare(b.id))

  pos['manager'] = { x: CANVAS_W / 2, y: SPACING.managerY }

  if (agentEntries.length === 0) return pos

  const moduleW = NODE_DIMS.module.w
  const moduleH = NODE_DIMS.module.h
  const colsMax = SPACING.moduleColsMax

  const footprints = agentEntries.map(a => {
    const children = Object.values(graph).filter(c => c.parent === a.id)
    const n = children.length
    const cols = n > 0 ? Math.min(n, colsMax) : 0
    const gridRows = n > 0 ? Math.ceil(n / colsMax) : 0
    const childGridW = cols > 0 ? cols * moduleW + (cols - 1) * SPACING.moduleGapX : 0
    const childGridH = gridRows > 0 ? gridRows * moduleH + (gridRows - 1) * SPACING.moduleGapY : 0
    const footprint = Math.max(NODE_DIMS.agent.w, childGridW)
    return { agent: a, children, footprint, cols, gridRows, childGridH }
  })

  const maxRowW = CANVAS_W - 2 * FIT_PADDING
  const rows = []
  let curRow = []
  let curRowW = 0
  for (const fp of footprints) {
    const addW = (curRow.length === 0 ? 0 : SPACING.agentGapX) + fp.footprint
    if (curRow.length > 0 && curRowW + addW > maxRowW) {
      rows.push(curRow)
      curRow = []
      curRowW = 0
    }
    curRow.push(fp)
    curRowW += (curRow.length === 1 ? fp.footprint : addW)
  }
  if (curRow.length > 0) rows.push(curRow)

  let cursorY = SPACING.firstAgentY
  rows.forEach(row => {
    const rowW = row.reduce((sum, fp, i) => sum + fp.footprint + (i > 0 ? SPACING.agentGapX : 0), 0)
    let cursorX = CANVAS_W / 2 - rowW / 2
    const agentY = cursorY
    const firstModuleRowY = agentY + SPACING.agentToModuleY

    for (const fp of row) {
      const agentX = cursorX + fp.footprint / 2
      pos[fp.agent.id] = { x: agentX, y: agentY }

      const { children, cols, gridRows } = fp
      if (children.length > 0) {
        for (let j = 0; j < children.length; j++) {
          const r = Math.floor(j / cols)
          const isLastRow = r === gridRows - 1
          const itemsInRow = isLastRow ? (children.length - r * cols) : cols
          const rowW2 = itemsInRow * moduleW + (itemsInRow - 1) * SPACING.moduleGapX
          const rowStartX = agentX - rowW2 / 2 + moduleW / 2
          const c = j - r * cols
          pos[children[j].id] = {
            x: rowStartX + c * (moduleW + SPACING.moduleGapX),
            y: firstModuleRowY + r * (moduleH + SPACING.moduleGapY),
          }
        }
      }

      cursorX += fp.footprint + SPACING.agentGapX
    }

    const tallestGridH = row.reduce((m, fp) => Math.max(m, fp.childGridH), 0)
    cursorY += SPACING.agentToModuleY + tallestGridH + SPACING.rowVSpace
  })

  return pos
}

// Compute the {tx, ty, s} that fits all current nodes inside the canvas.
function computeFitView(positions, dimsLookup) {
  const ids = Object.keys(positions)
  if (ids.length === 0) return null
  let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity
  for (const id of ids) {
    const p = positions[id]
    const d = dimsLookup(id)
    if (!d) continue
    minX = Math.min(minX, p.x - d.w / 2)
    minY = Math.min(minY, p.y - d.h / 2)
    maxX = Math.max(maxX, p.x + d.w / 2)
    maxY = Math.max(maxY, p.y + d.h / 2)
  }
  const bboxW = (maxX - minX) + FIT_PADDING * 2
  const bboxH = (maxY - minY) + FIT_PADDING * 2
  if (!Number.isFinite(bboxW) || !Number.isFinite(bboxH) || bboxW <= 0 || bboxH <= 0) return null
  const s = clamp(Math.min(CANVAS_W / bboxW, CANVAS_H / bboxH), ZOOM_MIN, ZOOM_MAX)
  const cx = (minX + maxX) / 2
  const cy = (minY + maxY) / 2
  return {
    s,
    tx: CANVAS_W / 2 - cx * s,
    ty: CANVAS_H / 2 - cy * s,
  }
}

// Hash of the graph structure to detect when topology actually changes.
function graphSignature(agents) {
  return agents
    .map(a => `${a.agent_id}:${agentProtocols(a).map(p => p.protocol).join(',')}`)
    .sort()
    .join('|')
}

export default function AgentTopology({ agents = [], logs = [], onModuleClick }) {
  const svgRef = useRef(null)
  const wrapperRef = useRef(null)

  const visibleAgents = useMemo(
    () => agents.filter(a => a.status !== 'enrolled' && a.status !== 'pending'),
    [agents]
  )

  const graph = useMemo(() => buildGraph(visibleAgents), [visibleAgents])
  const signature = useMemo(() => graphSignature(visibleAgents), [visibleAgents])

  const [positions, setPositions] = useState(() => {
    const stored = loadJSON(LS_POSITIONS, {})
    const computed = computeLayout(graph)
    const merged = { ...computed }
    for (const id of Object.keys(computed)) {
      if (stored[id]) merged[id] = stored[id]
    }
    return merged
  })

  const lastSigRef = useRef(signature)
  useEffect(() => {
    if (lastSigRef.current === signature) return
    lastSigRef.current = signature
    const computed = computeLayout(graph)
    setPositions(prev => {
      const next = { ...computed }
      for (const id of Object.keys(computed)) {
        if (prev[id]) next[id] = prev[id]
      }
      return next
    })
    setAutoFit(true)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [signature])

  const dimsLookup = useCallback(id => graph[id]?.dims, [graph])

  const [view, setView] = useState({ tx: 0, ty: 0, s: 1 })
  const [autoFit, setAutoFit] = useState(true)
  const viewRef = useRef(view)
  useEffect(() => { viewRef.current = view }, [view])

  useEffect(() => {
    if (!autoFit) return
    const next = computeFitView(positions, dimsLookup)
    if (next) setView(next)
  }, [autoFit, positions, dimsLookup])

  useEffect(() => {
    if (typeof ResizeObserver === 'undefined') return
    const el = wrapperRef.current
    if (!el) return
    const ro = new ResizeObserver(() => {
      if (autoFit) {
        const next = computeFitView(positions, dimsLookup)
        if (next) setView(next)
      }
    })
    ro.observe(el)
    return () => ro.disconnect()
  }, [autoFit, positions, dimsLookup])

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
    const cur = positions[id]
    if (!cur) return
    const svgPt = screenToSvg(e.clientX, e.clientY)
    const world = svgToWorld(svgPt.x, svgPt.y)
    dragRef.current = {
      kind: 'node',
      id,
      moved: false,
      offX: world.x - cur.x,
      offY: world.y - cur.y,
    }
    setDraggingId(id)
    setAutoFit(false)
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
      if (!drag.moved) {
        const cur = positions[drag.id]
        if (cur && (Math.abs(world.x - drag.offX - cur.x) > 4 || Math.abs(world.y - drag.offY - cur.y) > 4)) {
          drag.moved = true
        }
      }
      if (drag.moved) {
        setPositions(prev => ({
          ...prev,
          [drag.id]: { x: world.x - drag.offX, y: world.y - drag.offY },
        }))
      }
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

    if (!drag) return

    if (drag.kind === 'node') {
      if (!drag.moved && drag.id.startsWith('mod:')) {
        const [, agentId, proto] = drag.id.split(':')
        if (onModuleClick) onModuleClick(proto, agentId)
        return
      }
      if (drag.moved) {
        setPositions(latest => { saveJSON(LS_POSITIONS, latest); return latest })
      }
    }
  }

  useEffect(() => {
    const svg = svgRef.current
    if (!svg) return
    const handler = e => {
      e.preventDefault()
      const svgPt = screenToSvg(e.clientX, e.clientY)
      setAutoFit(false)
      setView(v => {
        const factor = e.deltaY < 0 ? ZOOM_STEP : 1 / ZOOM_STEP
        const newS = clamp(v.s * factor, ZOOM_MIN, ZOOM_MAX)
        const wx = (svgPt.x - v.tx) / v.s
        const wy = (svgPt.y - v.ty) / v.s
        return { s: newS, tx: svgPt.x - wx * newS, ty: svgPt.y - wy * newS }
      })
    }
    svg.addEventListener('wheel', handler, { passive: false })
    return () => svg.removeEventListener('wheel', handler)
  }, [screenToSvg])

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

  const fitNow = useCallback(() => setAutoFit(true), [])

  const resetLayout = useCallback(() => {
    const computed = computeLayout(graph)
    setPositions(computed)
    try { localStorage.removeItem(LS_POSITIONS) } catch { /* ignore */ }
    setAutoFit(true)
  }, [graph])

  const connections = useMemo(() => {
    const lines = { manager: [], modules: [] }
    const m = positions['manager']
    const mDims = NODE_DIMS.manager
    if (!m) return lines
    const mBottom = { x: m.x, y: m.y + mDims.h / 2 }

    for (const id of Object.keys(graph)) {
      const meta = graph[id]
      const p = positions[id]
      if (!p) continue
      if (meta.kind === 'agent') {
        const aTop = { x: p.x, y: p.y - meta.dims.h / 2 }
        lines.manager.push({ id: `link-m-${id}`, d: curvePath(mBottom, aTop) })
      } else if (meta.kind === 'module') {
        const parent = positions[meta.parent]
        const parentMeta = graph[meta.parent]
        if (!parent || !parentMeta) continue
        const aBot = { x: parent.x, y: parent.y + parentMeta.dims.h / 2 }
        const modTop = { x: p.x, y: p.y - meta.dims.h / 2 }
        const proto = id.split(':')[2]
        const agentId = id.split(':')[1]
        lines.modules.push({
          id: `link-${id}`,
          key: `${agentId}:${proto}`,
          color: PROTOCOL_COLOR[proto] || '#30363d',
          d: curvePath(aBot, modTop),
        })
      }
    }
    return lines
  }, [graph, positions])

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

    newLogs.sort((a, b) => compareLogTimestampsDesc(b, a))
    const SPREAD = Math.min(15000, Math.max(1000, newLogs.length * 250))
    const step = SPREAD / Math.max(1, newLogs.length)
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

  // Flash a module node and animate a packet along the agent → module edge.
  function triggerFlash(log) {
    const proto = moduleProtocol(String(log.protocol || ''))
    if (!proto) return
    const nodeId = `mod:${log.agent_id}:${proto}`
    if (!positions[nodeId]) return

    const fid = ++idCounterRef.current
    setFlashes(prev => [...prev, { id: fid, nodeId }])
    const t1 = setTimeout(() => {
      timersRef.current.delete(t1)
      setFlashes(prev => prev.filter(f => f.id !== fid))
    }, 1400)
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

  return (
    <div className="glass-card p-5 h-full flex flex-col">
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
          <ToolbarBtn label="Fit" title="Fit all nodes in view" onClick={fitNow} />
          <ToolbarBtn label="Reset" title="Reset to default layout" onClick={resetLayout} />
        </div>
      </div>

      {visibleAgents.length === 0 ? (
        <div className="text-center text-xs text-text-muted italic py-8">
          No active agents to display
        </div>
      ) : (
        <div ref={wrapperRef} className="relative rounded-lg overflow-hidden border border-border bg-surface-tertiary/40 flex-1 min-h-[240px]">
          <svg
            ref={svgRef}
            viewBox={`0 0 ${CANVAS_W} ${CANVAS_H}`}
            preserveAspectRatio="xMidYMid slice"
            className="block w-full h-full select-none absolute inset-0"
            style={{ cursor, touchAction: 'none' }}
            onPointerDown={onPointerDownBackground}
            onPointerMove={onPointerMove}
            onPointerUp={onPointerUp}
            onPointerCancel={onPointerUp}
          >
            <defs>
              <pattern id="topo-grid" width="40" height="40" patternUnits="userSpaceOnUse">
                <path d="M 40 0 L 0 0 0 40" fill="none" stroke="#1f2630" strokeWidth="1" />
              </pattern>
            </defs>
            <rect width={CANVAS_W} height={CANVAS_H} fill="#0d1117" />
            <rect width={CANVAS_W} height={CANVAS_H} fill="url(#topo-grid)" opacity="0.35" />

            <g transform={`translate(${view.tx} ${view.ty}) scale(${view.s})`}>
              {connections.manager.map(p => (
                <path key={p.id} d={p.d} stroke="#30363d" strokeWidth="1.4" fill="none" />
              ))}
              {connections.modules.map(p => (
                <path key={p.id} d={p.d} stroke={p.color} strokeOpacity="0.5" strokeWidth="1.2" fill="none" strokeDasharray="4 4" />
              ))}

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

              {Object.keys(graph).map(id => {
                const meta = graph[id]
                const p = positions[id]
                if (!p) return null
                const common = {
                  pos: p,
                  dims: meta.dims,
                  hovered: hoveringId === id,
                  dragging: draggingId === id,
                  onPointerDown: e => onPointerDownNode(e, id),
                  onMouseEnter: () => setHoveringId(id),
                  onMouseLeave: () => setHoveringId(null),
                }
                if (meta.kind === 'manager') return <ManagerNode key={id} {...common} />
                if (meta.kind === 'agent') return <AgentNode key={id} agent={meta.agent} {...common} />
                const flashing = flashes.some(f => f.nodeId === id)
                const a = visibleAgents.find(x => x.agent_id === meta.agentId)
                return (
                  <ProtocolNode
                    key={id}
                    proto={meta.proto}
                    flashing={flashing}
                    unreachable={a?.status === 'unreachable'}
                    {...common}
                  />
                )
              })}
            </g>
          </svg>

          <div className="absolute bottom-2 right-2 text-[10px] font-mono text-text-muted pointer-events-none">
            drag · wheel zoom · click protocol
          </div>
        </div>
      )}
    </div>
  )
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

function ManagerNode({ pos, dims, hovered, dragging, onPointerDown, onMouseEnter, onMouseLeave }) {
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

function AgentNode({ agent, pos, dims, hovered, dragging, onPointerDown, onMouseEnter, onMouseLeave }) {
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
      <circle cx={14} cy={h / 2} r={4} fill={dot} />
      <text
        x={26} y={h / 2 + 4}
        fontSize={font}
        fontWeight="600"
        fill="#e6edf3"
        style={{ pointerEvents: 'none' }}
      >
        {truncate(agent.agent_id, 22)}
      </text>
    </g>
  )
}

function ProtocolNode({ proto, pos, dims, unreachable, hovered, dragging, flashing, onPointerDown, onMouseEnter, onMouseLeave }) {
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
      style={{ cursor: unreachable ? 'default' : (dragging ? 'grabbing' : 'pointer'), opacity }}
      onPointerDown={unreachable ? undefined : onPointerDown}
      onMouseEnter={onMouseEnter}
      onMouseLeave={onMouseLeave}
    >
      <title>{titleAttr}</title>
      {flashing && (
        <rect
          x={-6} y={-6} width={w + 12} height={h + 12} rx={rx + 4} ry={rx + 4}
          fill="none" stroke="#c97878" strokeWidth="2" opacity="0.85"
        >
          <animate attributeName="opacity" values="0.85;0" dur="1.4s" fill="freeze" />
          <animate attributeName="stroke-width" values="2;9" dur="1.4s" fill="freeze" />
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
