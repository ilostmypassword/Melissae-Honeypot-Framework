const API_BASE = '/api'

// Fetch paginated logs (accepts an agent_id string or { agent_id, log_id })
export async function fetchLogs(opts = {}) {
  const options = typeof opts === 'string' ? { agent_id: opts } : (opts || {})
  const params = new URLSearchParams()
  if (options.agent_id) params.set('agent_id', options.agent_id)
  if (options.log_id) params.set('log_id', options.log_id)
  const qs = params.toString()
  const res = await fetch(`${API_BASE}/logs${qs ? `?${qs}` : ''}`)
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
const geoDetailsCache = {}

export async function fetchGeoIPDetails(ip) {
  if (!ip) return null
  if (ip in geoDetailsCache) return geoDetailsCache[ip]
  try {
    const res = await fetch(`${API_BASE}/geoip/${encodeURIComponent(ip)}`)
    if (!res.ok) return null
    const data = await res.json()
    geoDetailsCache[ip] = data
    return data
  } catch {
    return null
  }
}

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

// Fetch alerts backlog with optional filters
export async function fetchAlerts(filters = {}) {
  const params = new URLSearchParams()
  for (const [k, v] of Object.entries(filters)) {
    if (v != null && v !== '') params.set(k, v)
  }
  const qs = params.toString()
  const res = await fetch(`${API_BASE}/alerts${qs ? `?${qs}` : ''}`)
  if (!res.ok) throw new Error(`API error ${res.status}`)
  return res.json()
}

// Fetch alert counts grouped by status (for the navbar badge)
export async function fetchAlertCounts() {
  const res = await fetch(`${API_BASE}/alerts/count`)
  if (!res.ok) throw new Error(`API error ${res.status}`)
  return res.json()
}

// Update a single alert's status (new / acknowledged / resolved)
export async function updateAlertStatus(alertId, status) {
  const res = await fetch(`${API_BASE}/alerts/${encodeURIComponent(alertId)}/status`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ status }),
  })
  if (!res.ok) throw new Error(`API error ${res.status}`)
  return res.json()
}

// Bulk update alerts status. 
export async function updateAlertsBulk(ids, status) {
  const CHUNK = 500
  let updated = 0
  for (let i = 0; i < ids.length; i += CHUNK) {
    const slice = ids.slice(i, i + CHUNK)
    const res = await fetch(`${API_BASE}/alerts/bulk-status`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ids: slice, status }),
    })
    if (!res.ok) throw new Error(`API error ${res.status}`)
    const json = await res.json()
    updated += json.updated || 0
  }
  return { status: 'ok', updated }
}

// Fetch the rule catalog
export async function fetchRules() {
  const res = await fetch(`${API_BASE}/rules`)
  if (!res.ok) throw new Error(`API error ${res.status}`)
  return res.json()
}
