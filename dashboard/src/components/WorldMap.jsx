import { useState, memo } from 'react'
import {
  ComposableMap,
  Geographies,
  Geography,
  Marker,
  ZoomableGroup,
} from 'react-simple-maps'

const GEO_URL = '/countries-110m.json'

const verdictColor = v => {
  switch (v?.toLowerCase()) {
    case 'malicious': return '#ef4444'
    case 'suspicious': return '#f59e0b'
    case 'benign': return '#22c55e'
    default: return '#6366f1'
  }
}

const CountryShapes = memo(function CountryShapes() {
  return (
    <Geographies geography={GEO_URL}>
      {({ geographies }) =>
        geographies.map(geo => (
          <Geography
            key={geo.rsmKey}
            geography={geo}
            fill="#1c2333"
            stroke="#30363d"
            strokeWidth={0.4}
            style={{
              default: { outline: 'none' },
              hover: { fill: '#242d3d', outline: 'none' },
              pressed: { outline: 'none' },
            }}
          />
        ))
      }
    </Geographies>
  )
})

export default function WorldMap({ threats, onIPClick }) {
  const [tooltip, setTooltip] = useState(null)

  const markers = threats
    .filter(t => t.geo?.lat != null && t.geo?.lon != null)
    .map(t => ({
      ip: t.ip,
      verdict: t.verdict,
      score: t['protocol-score'],
      coordinates: [t.geo.lon, t.geo.lat],
      country: t.geo.country,
      city: t.geo.city,
    }))

  if (markers.length === 0) {
    return (
      <div className="text-center text-text-muted py-10">
        <div className="text-3xl mb-2 opacity-40">🌍</div>
        <p className="text-sm">No geolocation data available yet.</p>
        <p className="text-xs mt-1 opacity-60">
          GeoIP enrichment runs automatically during threat analysis.
        </p>
      </div>
    )
  }

  return (
    <div className="relative h-full overflow-hidden">
      <ComposableMap
        projection="geoMercator"
        projectionConfig={{ scale: 140, center: [20, 20] }}
        style={{ width: '100%', height: '100%' }}
      >
        <ZoomableGroup>
          <CountryShapes />
          {markers.map((m, i) => {
            const r = Math.max(3, Math.min(12, 3 + (m.score || 0) / 12))
            return (
              <Marker
                key={`${m.ip}-${i}`}
                coordinates={m.coordinates}
                onMouseEnter={() => setTooltip(m)}
                onMouseLeave={() => setTooltip(null)}
                onClick={() => onIPClick?.(m.ip)}
                style={{ cursor: 'pointer' }}
              >
                {/* Glow */}
                <circle
                  r={r + 4}
                  fill={verdictColor(m.verdict)}
                  opacity={0.12}
                />
                {/* Dot */}
                <circle
                  r={r}
                  fill={verdictColor(m.verdict)}
                  stroke="#0d1117"
                  strokeWidth={1.2}
                  opacity={0.85}
                />
              </Marker>
            )
          })}
        </ZoomableGroup>
      </ComposableMap>

      {/* Tooltip */}
      {tooltip && (
        <div className="absolute top-3 right-3 bg-surface-tertiary border border-border rounded-lg p-3 shadow-xl pointer-events-none z-10 min-w-[190px]">
          <p className="font-mono text-text-primary font-semibold text-sm">
            {tooltip.ip}
          </p>
          <p className="text-text-secondary text-xs mt-1">
            {[tooltip.city, tooltip.country].filter(Boolean).join(', ') || 'Unknown location'}
          </p>
          <div className="flex items-center gap-2 mt-2">
            <span
              className="w-2.5 h-2.5 rounded-full inline-block flex-shrink-0"
              style={{ backgroundColor: verdictColor(tooltip.verdict) }}
            />
            <span className="text-text-secondary text-xs capitalize">
              {tooltip.verdict || 'unknown'} — {tooltip.score ?? '?'}/100
            </span>
          </div>
        </div>
      )}

      {/* Legend */}
      <div className="absolute bottom-3 left-3 flex gap-4 text-xs text-text-muted">
        {[
          { label: 'Benign', color: '#22c55e' },
          { label: 'Suspicious', color: '#f59e0b' },
          { label: 'Malicious', color: '#ef4444' },
        ].map(({ label, color }) => (
          <span key={label} className="flex items-center gap-1.5">
            <span
              className="w-2 h-2 rounded-full inline-block"
              style={{ backgroundColor: color }}
            />
            {label}
          </span>
        ))}
      </div>
    </div>
  )
}
