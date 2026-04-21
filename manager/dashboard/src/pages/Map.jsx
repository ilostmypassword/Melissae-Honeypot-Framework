import { useState, useEffect, useMemo, Component } from 'react'
import { useNavigate } from 'react-router-dom'
import { fetchThreats } from '../api'
import WorldMap from '../components/WorldMap'
import { VerdictTag } from '../components/Tags'

class MapErrorBoundary extends Component {
  state = { error: null }
  static getDerivedStateFromError(error) { return { error } }
  render() {
    if (this.state.error) {
      return (
        <div className="text-center text-text-muted py-10">
          <div className="text-3xl mb-2 opacity-40">⚠️</div>
          <p className="text-sm">Map component failed to load.</p>
          <p className="text-xs mt-1 opacity-60">{this.state.error.message}</p>
        </div>
      )
    }
    return this.props.children
  }
}

export default function Map() {
  const [threats, setThreats] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const navigate = useNavigate()

  useEffect(() => {
    fetchThreats()
      .then(setThreats)
      .catch(err => setError(err.message))
      .finally(() => setLoading(false))
  }, [])

  const goSearch = ip => navigate(`/search?q=${encodeURIComponent(`ip:${ip}`)}`)

  const geoThreats = useMemo(
    () => threats.filter(t => t.geo?.lat != null && t.geo?.lon != null),
    [threats]
  )

  const localThreats = useMemo(
    () => threats.filter(t => !t.geo?.lat && !t.geo?.lon),
    [threats]
  )

  const countryStats = useMemo(() => {
    const map = {}
    for (const t of geoThreats) {
      const country = t.geo?.country || 'Unknown'
      if (!map[country]) map[country] = { count: 0, malicious: 0, suspicious: 0, benign: 0 }
      map[country].count++
      const v = t.verdict?.toLowerCase()
      if (v === 'malicious') map[country].malicious++
      else if (v === 'suspicious') map[country].suspicious++
      else map[country].benign++
    }
    return Object.entries(map)
      .sort((a, b) => b[1].count - a[1].count)
      .slice(0, 15)
  }, [geoThreats])

  const hasExternal = geoThreats.length > 0
  const hasInternal = localThreats.length > 0

  if (loading) {
    return (
      <div className="space-y-6 animate-fade-in">
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          {Array.from({ length: 3 }, (_, i) => (
            <div key={i} className="skeleton h-20 rounded-xl" />
          ))}
        </div>
        <div className="skeleton h-[500px] rounded-xl" />
      </div>
    )
  }

  if (error) {
    return (
      <div className="glass-card text-verdict-malicious p-6 text-center border-verdict-malicious/20 animate-fade-in">
        <div className="font-medium">Unable to load data</div>
        <div className="text-sm mt-1 opacity-60">{error}</div>
      </div>
    )
  }

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Summary bar */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="glass-card p-4">
          <p className="section-title">Total IPs</p>
          <p className="text-2xl font-semibold text-text-primary font-mono mt-1">{threats.length}</p>
        </div>
        <div className="glass-card p-4">
          <p className="section-title">External (Public)</p>
          <p className="text-2xl font-semibold text-protocol-http font-mono mt-1">{geoThreats.length}</p>
        </div>
        <div className="glass-card p-4">
          <p className="section-title">Internal (Private)</p>
          <p className="text-2xl font-semibold text-protocol-ssh font-mono mt-1">{localThreats.length}</p>
        </div>
      </div>

      {/* World map — external threats */}
      {hasExternal && (
        <div className="glass-card p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="section-title">External Attack Origins</h3>
            <span className="text-xs text-text-muted">
              {geoThreats.length} geolocated IPs
            </span>
          </div>
          <div className="h-[500px]">
            <MapErrorBoundary>
              <WorldMap threats={threats} onIPClick={goSearch} />
            </MapErrorBoundary>
          </div>
        </div>
      )}

      {/* Internal network threats */}
      {hasInternal && (
        <div className="glass-card p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="section-title">Internal Network Threats</h3>
            <span className="text-xs text-text-muted">
              {localThreats.length} private IPs
            </span>
          </div>

          {hasExternal && (
            <div className="bg-protocol-ssh/10 border border-protocol-ssh/20 rounded-lg p-3 mb-4 text-xs text-text-secondary">
              These IPs belong to your internal network and cannot be geolocated.
            </div>
          )}

          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-text-muted text-xs uppercase tracking-wider border-b border-border">
                  <th className="text-left py-2 px-3">IP</th>
                  <th className="text-left py-2 px-3">Verdict</th>
                  <th className="text-right py-2 px-3">Score</th>
                  <th className="text-right py-2 px-3">Confidence</th>
                  <th className="text-left py-2 px-3">Reasons</th>
                  <th className="text-left py-2 px-3">First Seen</th>
                  <th className="text-left py-2 px-3">Last Seen</th>
                </tr>
              </thead>
              <tbody>
                {[...localThreats]
                  .sort((a, b) => (b['protocol-score'] || 0) - (a['protocol-score'] || 0))
                  .map(t => (
                    <tr
                      key={t.ip}
                      onClick={() => goSearch(t.ip)}
                      className="border-b border-border/50 hover:bg-surface-hover transition-colors cursor-pointer"
                    >
                      <td className="py-2.5 px-3 font-mono text-text-primary">{t.ip}</td>
                      <td className="py-2.5 px-3">
                        <VerdictTag verdict={t.verdict} />
                      </td>
                      <td className="py-2.5 px-3 text-right font-mono text-text-secondary">
                        {t['protocol-score'] ?? '—'}/100
                      </td>
                      <td className="py-2.5 px-3 text-right font-mono text-text-secondary">
                        {Number.isFinite(t.confidence) ? `${Math.round(t.confidence * 100)}%` : '—'}
                      </td>
                      <td className="py-2.5 px-3 text-text-muted text-xs max-w-xs truncate">
                        {Array.isArray(t.reasons) ? t.reasons.slice(0, 3).join(' · ') : '—'}
                      </td>
                      <td className="py-2.5 px-3 text-text-muted text-xs font-mono whitespace-nowrap">
                        {t.first_seen?.replace('T', ' ').slice(0, 19) || '—'}
                      </td>
                      <td className="py-2.5 px-3 text-text-muted text-xs font-mono whitespace-nowrap">
                        {t.last_seen?.replace('T', ' ').slice(0, 19) || '—'}
                      </td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Country breakdown table */}
      {countryStats.length > 0 && (
        <div className="glass-card p-5">
          <h3 className="section-title mb-4">Top Attack Origins by Country</h3>
          <div className="overflow-x-auto overflow-y-auto max-h-[280px]">
            <table className="w-full text-sm">
              <thead className="sticky top-0 z-10 bg-surface-secondary">
                <tr className="text-text-muted text-xs uppercase tracking-wider border-b border-border">
                  <th className="text-left py-2 px-3">Country</th>
                  <th className="text-right py-2 px-3">IPs</th>
                  <th className="text-right py-2 px-3">Malicious</th>
                  <th className="text-right py-2 px-3">Suspicious</th>
                  <th className="text-right py-2 px-3">Benign</th>
                </tr>
              </thead>
              <tbody>
                {countryStats.map(([country, s]) => (
                  <tr
                    key={country}
                    className="border-b border-border/50 hover:bg-surface-hover transition-colors"
                  >
                    <td className="py-2.5 px-3 text-text-primary font-medium">{country}</td>
                    <td className="py-2.5 px-3 text-text-secondary text-right font-mono">{s.count}</td>
                    <td className="py-2.5 px-3 text-right font-mono text-verdict-malicious">{s.malicious || '–'}</td>
                    <td className="py-2.5 px-3 text-right font-mono text-verdict-suspicious">{s.suspicious || '–'}</td>
                    <td className="py-2.5 px-3 text-right font-mono text-verdict-benign">{s.benign || '–'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Recent geolocated threats */}
      {geoThreats.length > 0 && (
        <div className="glass-card p-5">
          <h3 className="section-title mb-4">Geolocated Threats</h3>
          <div className="overflow-x-auto overflow-y-auto max-h-[280px]">
            <table className="w-full text-sm">
              <thead className="sticky top-0 z-10 bg-surface-secondary">
                <tr className="text-text-muted text-xs uppercase tracking-wider border-b border-border">
                  <th className="text-left py-2 px-3">IP</th>
                  <th className="text-left py-2 px-3">Location</th>
                  <th className="text-left py-2 px-3">ISP / Org</th>
                  <th className="text-left py-2 px-3">Verdict</th>
                  <th className="text-right py-2 px-3">Score</th>
                </tr>
              </thead>
              <tbody>
                {geoThreats
                  .sort((a, b) => (b['protocol-score'] || 0) - (a['protocol-score'] || 0))
                  .map(t => (
                    <tr
                      key={t.ip}
                      onClick={() => goSearch(t.ip)}
                      className="border-b border-border/50 hover:bg-surface-hover transition-colors cursor-pointer"
                    >
                      <td className="py-2.5 px-3 font-mono text-text-primary">{t.ip}</td>
                      <td className="py-2.5 px-3 text-text-secondary">
                        {[t.geo?.city, t.geo?.country].filter(Boolean).join(', ') || '—'}
                      </td>
                      <td className="py-2.5 px-3 text-text-muted text-xs">
                        {t.geo?.org || t.geo?.isp || '—'}
                      </td>
                      <td className="py-2.5 px-3">
                        <VerdictTag verdict={t.verdict} />
                      </td>
                      <td className="py-2.5 px-3 text-right font-mono text-text-secondary">
                        {t['protocol-score'] ?? '—'}/100
                      </td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}

