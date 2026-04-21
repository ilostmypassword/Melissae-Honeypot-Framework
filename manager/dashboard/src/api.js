const API_BASE = '/api'

// Fetch paginated logs from the API
export async function fetchLogs(agentId) {
  const params = agentId ? `?agent_id=${encodeURIComponent(agentId)}` : ''
  const res = await fetch(`${API_BASE}/logs${params}`)
  if (!res.ok) throw new Error(`API error ${res.status}`)
  return res.json()
}

// Fetch paginated threats from the API
export async function fetchThreats(agentId) {
  const params = agentId ? `?agent_id=${encodeURIComponent(agentId)}` : ''
  const res = await fetch(`${API_BASE}/threats${params}`)
  if (!res.ok) throw new Error(`API error ${res.status}`)
  return res.json()
}

// Fetch registered agents list
export async function fetchAgents() {
  const res = await fetch(`${API_BASE}/agents`)
  if (!res.ok) throw new Error(`API error ${res.status}`)
  return res.json()
}

// Fetch attack killchain for an IP
export async function fetchKillchain(ip) {
  const res = await fetch(`${API_BASE}/threats/${encodeURIComponent(ip)}/killchain`)
  if (!res.ok) throw new Error(`API error ${res.status}`)
  const payload = await res.json()
  return Array.isArray(payload?.events) ? payload.events : Array.isArray(payload) ? payload : []
}

const geoCache = {}

export async function fetchGeoIP(ips) {
  const uncached = ips.filter(ip => !(ip in geoCache))
  if (uncached.length > 0) {
    try {
      const res = await fetch(`${API_BASE}/geoip`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ips: uncached }),
      })
      if (res.ok) {
        const data = await res.json()
        Object.assign(geoCache, data)
      }
    } catch {
    }
  }
  const result = {}
  for (const ip of ips) result[ip] = geoCache[ip] || null
  return result
}

