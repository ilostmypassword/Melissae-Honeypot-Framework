/**
 * Format a number into a compact human-readable string.
 */
export function formatNumber(n) {
  if (!Number.isFinite(n)) return n
  if (n >= 1_000_000_000) {
    return (n / 1_000_000_000).toFixed(1).replace(/\.0$/, '') + 'B'
  }
  if (n >= 1_000_000) {
    return (n / 1_000_000).toFixed(1).replace(/\.0$/, '') + 'M'
  }
  if (n >= 1_000) {
    return (n / 1_000).toFixed(1).replace(/\.0$/, '') + 'K'
  }
  return String(n)
}

/**
 * Filter logs by a named date range ('today', '7d', '30d', 'all').
 */
export function filterByDateRange(logs, dateRange) {
  if (dateRange === 'all') return logs
  const now = new Date()
  const pad = n => String(n).padStart(2, '0')
  const todayStr = `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}`
  let cutoffDate
  if (dateRange === 'today') {
    cutoffDate = todayStr
  } else {
    const cutoff = new Date(now)
    if (dateRange === '7d') cutoff.setDate(cutoff.getDate() - 7)
    else if (dateRange === '30d') cutoff.setDate(cutoff.getDate() - 30)
    cutoffDate = `${cutoff.getFullYear()}-${pad(cutoff.getMonth() + 1)}-${pad(cutoff.getDate())}`
  }
  return logs.filter(l => l.date && l.date >= cutoffDate)
}

/**
 * Compute aggregate statistics from a logs array.
 */
export function computeStats(logs) {
  const protocols = { ssh: 0, ftp: 0, http: 0, modbus: 0, mqtt: 0, telnet: 0 }
  const uniqueIPs = new Set()
  let cveLogs = 0, successSSH = 0, successFTP = 0, successTelnet = 0, modbusWrites = 0

  for (const l of logs) {
    if (l.protocol && protocols[l.protocol] !== undefined) protocols[l.protocol]++
    if (l.ip) uniqueIPs.add(l.ip)
    if (l.cve) cveLogs++
    const action = l.action?.toLowerCase() || ''
    if (l.protocol === 'ssh' && (action.includes('accepted') || action.includes('successful'))) successSSH++
    if (l.protocol === 'ftp' && action.includes('successful')) successFTP++
    if (l.protocol === 'telnet' && action.includes('session opened')) successTelnet++
    if (l.protocol === 'modbus' && action.includes('write')) modbusWrites++
  }

  return { totalLogs: logs.length, uniqueIPs: uniqueIPs.size, protocols, cveLogs, successSSH, successFTP, successTelnet, modbusWrites }
}

/**
 * Compute event trend (%) comparing last 24h vs previous 24h window.
 */
export function computeTrend(allLogs, selectedAgent) {
  const now = new Date()
  const h24 = new Date(now - 86400_000)
  const h48 = new Date(now - 172800_000)

  const inRange = (l, from, to) => {
    if (!l.date) return false
    const d = new Date(l.date + 'T' + (l.hour || '00:00:00'))
    return d >= from && d < to
  }

  const logs = selectedAgent ? allLogs.filter(l => l.agent_id === selectedAgent) : allLogs
  const last24 = logs.filter(l => inRange(l, h24, now))
  const prev24 = logs.filter(l => inRange(l, h48, h24))

  const trend = (curr, prev) => {
    if (prev === 0) return curr > 0 ? 100 : 0
    return Math.round(((curr - prev) / prev) * 100)
  }

  return {
    totalTrend: trend(last24.length, prev24.length),
    ipTrend: trend(new Set(last24.map(l => l.ip)).size, new Set(prev24.map(l => l.ip)).size),
    sshTrend: trend(last24.filter(l => l.protocol === 'ssh').length, prev24.filter(l => l.protocol === 'ssh').length),
    httpTrend: trend(last24.filter(l => l.protocol === 'http').length, prev24.filter(l => l.protocol === 'http').length),
  }
}
