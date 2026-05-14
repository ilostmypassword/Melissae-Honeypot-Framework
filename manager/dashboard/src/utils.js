// Format a number into a compact human-readable string (1.2K, 3.4M, 5.6B)
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

// Parse Melissae timestamps consistently as UTC.
export function parseTimestampValue(value) {
  if (!value) return null
  let raw = String(value).trim()
  if (!raw) return null

  if (/^\d{4}-\d{2}-\d{2}$/.test(raw)) raw = `${raw}T00:00:00Z`
  else raw = raw.replace(' ', 'T')

  const hasTimezone = /(?:Z|[+-]\d{2}:?\d{2})$/i.test(raw)
  if (!hasTimezone) raw += 'Z'

  const parsed = new Date(raw)
  return Number.isNaN(parsed.getTime()) ? null : parsed
}

// Resolve the best timestamp available on a log-like object
export function parseLogTimestamp(log) {
  if (!log) return null
  return parseTimestampValue(log.timestamp)
    || parseTimestampValue(log.time)
    || parseTimestampValue(log.datetime)
    || parseTimestampValue(log.date && `${log.date}T${log.hour || '00:00:00'}`)
}

export function timestampToMs(value) {
  const parsed = parseTimestampValue(value)
  return parsed ? parsed.getTime() : NaN
}

export function logTimestampToMs(log) {
  const parsed = parseLogTimestamp(log)
  return parsed ? parsed.getTime() : NaN
}

export function getLogDateKey(log) {
  const parsed = parseLogTimestamp(log)
  if (parsed) return parsed.toISOString().slice(0, 10)
  return typeof log?.date === 'string' ? log.date.slice(0, 10) : ''
}

export function getLogHourKey(log) {
  const parsed = parseLogTimestamp(log)
  if (parsed) return parsed.toISOString().slice(11, 19)
  return typeof log?.hour === 'string' ? log.hour.slice(0, 8) : ''
}

export function formatTimestampUTC(value) {
  const parsed = parseTimestampValue(value)
  if (!parsed) return value || '—'
  return parsed.toLocaleString('en-GB', {
    timeZone: 'UTC',
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  }) + ' UTC'
}

export function formatLogTimestampUTC(log) {
  const parsed = parseLogTimestamp(log)
  return parsed ? formatTimestampUTC(parsed.toISOString()) : '—'
}

export function compareLogTimestampsDesc(a, b) {
  const ta = logTimestampToMs(a)
  const tb = logTimestampToMs(b)
  if (Number.isFinite(ta) && Number.isFinite(tb)) return tb - ta
  if (Number.isFinite(ta)) return -1
  if (Number.isFinite(tb)) return 1
  return String(b?.timestamp || '').localeCompare(String(a?.timestamp || ''))
}

export function sameUTCDate(a, b) {
  if (!a || !b) return false
  return a.toISOString().slice(0, 10) === b.toISOString().slice(0, 10)
}

// Filter logs by a named date range ('today', '7d', '30d', 'all')
export function filterByDateRange(logs, dateRange) {
  if (dateRange === 'all') return logs
  const now = new Date()
  let from
  if (dateRange === 'today') {
    from = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate())
  } else {
    const days = dateRange === '30d' ? 30 : 7
    from = now.getTime() - days * 86400_000
  }
  return logs.filter(l => {
    const ts = logTimestampToMs(l)
    return Number.isFinite(ts) && ts >= from && ts <= now.getTime()
  })
}

// Compute aggregate statistics from a logs array
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

// Compute event trend (%) comparing last 24h vs previous 24h window
export function computeTrend(allLogs, selectedAgent) {
  const now = new Date()
  const h24 = new Date(now - 86400_000)
  const h48 = new Date(now - 172800_000)

  const inRange = (l, from, to) => {
    const ts = logTimestampToMs(l)
    return Number.isFinite(ts) && ts >= from.getTime() && ts < to.getTime()
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
