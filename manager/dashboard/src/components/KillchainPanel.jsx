import { useState, useEffect } from 'react'
import { fetchKillchain } from '../api'

const killchainCache = new Map()
const MAX_CACHE = 200

const dotColors = {
  ssh:    'bg-protocol-ssh',
  ftp:    'bg-protocol-ftp',
  http:   'bg-protocol-http',
  modbus: 'bg-protocol-modbus',
  mqtt:   'bg-protocol-mqtt',
  telnet: 'bg-protocol-telnet',
  other:  'bg-gray-400',
}

// Format a timestamp for display
function formatTime(ts) {
  if (!Number.isFinite(ts)) return 'Unknown'
  const d = new Date(ts)
  return `${d.toLocaleDateString()} ${d.toLocaleTimeString()}`
}

// Process raw killchain events into timeline data
function processEvents(rawEvents) {
  const events = rawEvents
    .map(e => {
      const rawTime = e.timestamp || e.time || e.date || e.datetime
      const ts = rawTime ? new Date(rawTime).getTime() : NaN
      const protocol = (e.protocol || e.proto || 'other').toLowerCase()
      return { ts, protocol }
    })
    .filter(e => Number.isFinite(e.ts))

  if (events.length === 0) return []

  const protoMap = new Map()
  events.forEach(evt => {
    const found = protoMap.get(evt.protocol) || {
      protocol: evt.protocol,
      start: evt.ts,
      end: evt.ts,
      first: evt.ts,
    }
    found.start = Math.min(found.start, evt.ts)
    found.end = Math.max(found.end, evt.ts)
    found.first = Math.min(found.first, evt.ts)
    protoMap.set(evt.protocol, found)
  })

  return Array.from(protoMap.values()).sort((a, b) => {
    const aKey = a.start !== a.end ? a.end : a.first
    const bKey = b.start !== b.end ? b.end : b.first
    return aKey - bKey
  })
}

// Attack killchain timeline visualization
export default function KillchainPanel({ ip, onClose }) {
  const [events, setEvents] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    if (!ip) return
    setLoading(true)
    setError(null)

    if (killchainCache.has(ip)) {
      setEvents(killchainCache.get(ip))
      setLoading(false)
      return
    }

    fetchKillchain(ip)
      .then(data => {
        if (killchainCache.size >= MAX_CACHE) killchainCache.delete(killchainCache.keys().next().value)
        killchainCache.set(ip, data)
        setEvents(data)
      })
      .catch(err => setError(err.message))
      .finally(() => setLoading(false))
  }, [ip])

  if (!ip) return null

  const grouped = processEvents(events || [])

  return (
    <div className="glass-card p-5">
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div>
          <p className="section-title">Killchain</p>
          <h3 className="text-lg font-semibold text-text-primary font-mono">
            {ip}
          </h3>
        </div>
        <button
          onClick={onClose}
          className="w-8 h-8 rounded-full bg-surface-tertiary text-text-secondary hover:bg-surface-hover hover:text-text-primary flex items-center justify-center transition-colors text-lg"
          aria-label="Close killchain"
        >
          &times;
        </button>
      </div>

      {/* Body */}
      <div className="border border-dashed border-border rounded-lg p-4 bg-surface/50">
        {loading && (
          <p className="text-center text-text-muted italic py-4">
            Loading killchain...
          </p>
        )}

        {error && (
          <p className="text-center text-verdict-malicious py-4">
            Error: {error}
          </p>
        )}

        {!loading && !error && grouped.length === 0 && (
          <p className="text-center text-text-muted italic py-4">
            No events found for this IP
          </p>
        )}

        {!loading && !error && grouped.length > 0 && (
          <>
            <div className="flex gap-3 overflow-x-auto pb-2">
              {grouped.map((item, idx) => (
                <div
                  key={idx}
                  className="flex items-center gap-3 px-4 py-3 bg-surface-secondary border border-border rounded-lg min-w-[210px]"
                >
                  <div className="w-7 h-7 rounded-full bg-surface-tertiary flex items-center justify-center text-xs font-bold text-text-primary shrink-0">
                    {idx + 1}
                  </div>
                  <div
                    className={`w-4 h-4 rounded-full shrink-0 ${
                      dotColors[item.protocol] || dotColors.other
                    }`}
                  />
                  <div className="min-w-0">
                    <div className="font-bold text-sm text-text-primary">
                      {item.protocol.toUpperCase()}
                    </div>
                    <div className="text-xs text-text-muted">
                      {item.start === item.end
                        ? formatTime(item.start)
                        : `${formatTime(item.start)} → ${formatTime(item.end)}`}
                    </div>
                  </div>
                </div>
              ))}
            </div>

            {/* Legend */}
            <div className="flex flex-wrap gap-4 mt-3 text-xs text-text-muted">
              {[...new Set(grouped.map(g => g.protocol))].map(proto => (
                <span key={proto} className="inline-flex items-center gap-2">
                  <span
                    className={`w-3 h-3 rounded ${
                      dotColors[proto] || dotColors.other
                    }`}
                  />
                  {proto.toUpperCase()}
                </span>
              ))}
            </div>
          </>
        )}
      </div>
    </div>
  )
}

