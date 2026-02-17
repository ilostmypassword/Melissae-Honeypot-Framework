const API_BASE = '/api'

export async function fetchLogs() {
  const res = await fetch(`${API_BASE}/logs`)
  if (!res.ok) throw new Error(`API error ${res.status}`)
  return res.json()
}

export async function fetchThreats() {
  const res = await fetch(`${API_BASE}/threats`)
  if (!res.ok) throw new Error(`API error ${res.status}`)
  return res.json()
}

export async function fetchKillchain(ip) {
  const res = await fetch(`${API_BASE}/threats/${encodeURIComponent(ip)}/killchain`)
  if (!res.ok) throw new Error(`API error ${res.status}`)
  const payload = await res.json()
  return Array.isArray(payload?.events) ? payload.events : Array.isArray(payload) ? payload : []
}
