const API_BASE = '/api'

// Fetch paginated logs (accepts an agent_id string or { agent_id, log_id })
export async function fetchLogs(opts = {}) {
  const options = typeof opts === 'string' ? { agent_id: opts } : (opts || {})
  const params = new URLSearchParams()
  if (options.agent_id) params.set('agent_id', options.agent_id)
  if (options.log_id) params.set('log_id', options.log_id)
  if (options.limit) params.set('limit', options.limit)
  if (options.skip) params.set('skip', options.skip)
  const qs = params.toString()
  const res = await fetch(`${API_BASE}/logs${qs ? `?${qs}` : ''}`)
  if (!res.ok) throw new Error(`API error ${res.status}`)
  return res.json()
}

const FETCH_ALL_PAGE_SIZE = 5000
const FETCH_ALL_SAFETY_CAP = 200_000

export async function fetchAllLogs(opts = {}) {
  const base = typeof opts === 'string' ? { agent_id: opts } : (opts || {})
  let skip = 0
  let all = []
  while (true) {
    const page = await fetchLogs({ ...base, limit: FETCH_ALL_PAGE_SIZE, skip })
    all = all.concat(page)
    if (page.length < FETCH_ALL_PAGE_SIZE || all.length >= FETCH_ALL_SAFETY_CAP) break
    skip += FETCH_ALL_PAGE_SIZE
  }
  return all
}

export async function fetchLogStats(filters = {}) {
  const params = new URLSearchParams()
  for (const [k, v] of Object.entries(filters)) {
    if (v != null && v !== '') params.set(k, v)
  }
  const qs = params.toString()
  const res = await fetch(`${API_BASE}/logs/stats${qs ? `?${qs}` : ''}`)
  if (!res.ok) throw new Error(`API error ${res.status}`)
  return res.json()
}

// Fetch date × hour × protocol × agent buckets aggregated server-side over all
// logs. Bucket rows look like logs ({ date, hour, protocol, agent_id }) plus a
// `count` weight, so chart components accept them directly.
export async function fetchLogTimeline(filters = {}) {
  const params = new URLSearchParams()
  for (const [k, v] of Object.entries(filters)) {
    if (v != null && v !== '') params.set(k, v)
  }
  const qs = params.toString()
  const res = await fetch(`${API_BASE}/logs/timeline${qs ? `?${qs}` : ''}`)
  if (!res.ok) throw new Error(`API error ${res.status}`)
  const data = await res.json()
  return Array.isArray(data?.buckets) ? data.buckets : []
}


export async function fetchThreats(agentId) {
  const params = agentId ? `?agent_id=${encodeURIComponent(agentId)}` : ''
  const res = await fetch(`${API_BASE}/threats${params}`)
  if (!res.ok) throw new Error(`API error ${res.status}`)
  return res.json()
}


export async function fetchInspektorReport() {
  const res = await fetch(`${API_BASE}/inspektor/report`)
  if (!res.ok) throw new Error(`API error ${res.status}`)
  return res.json()
}

export async function fetchInspektorStatus() {
  const res = await fetch(`${API_BASE}/inspektor/status`)
  if (!res.ok) return { enabled: false, ready: false, configured: false }
  return res.json()
}

export async function generateInspektorReport() {
  const res = await fetch(`${API_BASE}/inspektor/generate`, { method: 'POST' })
  const data = await res.json().catch(() => ({}))
  if (!res.ok) throw new Error(data?.error || `API error ${res.status}`)
  return data
}


export async function sendInspektorChat(message, history = []) {
  const res = await fetch(`${API_BASE}/inspektor/chat`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ message, history }),
  })
  const data = await res.json().catch(() => ({}))
  if (!res.ok) throw new Error(data?.error || `API error ${res.status}`)
  return data
}


export async function fetchAgents() {
  const res = await fetch(`${API_BASE}/agents`)
  if (!res.ok) throw new Error(`API error ${res.status}`)
  return res.json()
}


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


export async function fetchAlertCounts(filters = {}) {
  const params = new URLSearchParams()
  for (const [k, v] of Object.entries(filters)) {
    if (v != null && v !== '') params.set(k, v)
  }
  const qs = params.toString()
  const res = await fetch(`${API_BASE}/alerts/count${qs ? `?${qs}` : ''}`)
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


export async function fetchRules() {
  const res = await fetch(`${API_BASE}/rules`)
  if (!res.ok) throw new Error(`API error ${res.status}`)
  return res.json()
}
