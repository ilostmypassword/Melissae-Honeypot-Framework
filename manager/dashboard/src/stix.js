// Validate and sanitize an IP address string
function sanitizeIP(ip) {
  const str = String(ip || '').trim()
  if (/^[0-9a-fA-F.:]+$/.test(str)) return str
  return 'invalid-ip'
}

// Normalize a verdict string to a known value
function sanitizeVerdict(verdict) {
  const allowed = ['benign', 'suspicious', 'malicious', 'unknown']
  const v = String(verdict || 'unknown').toLowerCase()
  return allowed.includes(v) ? v : 'unknown'
}

// Convert a value to a short printable string for STIX descriptions
function sanitizeText(value, maxLength = 160) {
  return String(value || '')
    .replace(/[\r\n\t]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, maxLength)
}

// Format a compact list for human-readable STIX descriptions
function formatList(values, maxItems = 4) {
  const items = [...new Set((values || []).map(v => sanitizeText(v)).filter(Boolean))]
  if (items.length === 0) return null
  const visible = items.slice(0, maxItems).join(', ')
  const remaining = items.length - maxItems
  return remaining > 0 ? `${visible}, +${remaining} more` : visible
}

// Build a contextual IOC description from Melissae threat data
function buildIndicatorDescription(threat, ip, verdict, scoreText) {
  const parts = [
    `Attacker IP ${ip} was observed by Melissae-Honeypot-Framework and classified as ${verdict} ${scoreText}.`,
  ]

  if (Number.isFinite(threat.alert_count)) {
    parts.push(`${threat.alert_count} alert${threat.alert_count === 1 ? '' : 's'} contributed to this assessment.`)
  }

  const ruleNames = formatList((threat.rules || []).map(rule => rule?.name || rule?.id))
  if (ruleNames) parts.push(`Matched detection context: ${ruleNames}.`)

  const reasons = formatList(threat.reasons)
  if (!ruleNames && reasons) parts.push(`Observed activity context: ${reasons}.`)

  const tags = formatList(threat.tags)
  if (tags) parts.push(`Related tags: ${tags}.`)

  if (threat.first_seen || threat.last_seen) {
    const firstSeen = sanitizeText(threat.first_seen || 'unknown')
    const lastSeen = sanitizeText(threat.last_seen || 'unknown')
    parts.push(`Activity window: first seen ${firstSeen}, last seen ${lastSeen}.`)
  }

  return parts.join(' ')
}

// Generate a random UUID v4
function uuidv4() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
    const r = crypto.getRandomValues(new Uint8Array(1))[0] & 15
    const v = c === 'x' ? r : (r & 0x3) | 0x8
    return v.toString(16)
  })
}

// Build a STIX 2.1 bundle from threat data
export function buildStixBundle(threats) {
  const now = new Date().toISOString()
  const identityId = `identity--${uuidv4()}`

  const identity = {
    type: 'identity',
    spec_version: '2.1',
    id: identityId,
    created: now,
    modified: now,
    name: 'Melissae-Honeypot-Framework',
    identity_class: 'organization',
  }

  const indicators = threats.map(threat => {
    const ip = sanitizeIP(threat.ip)
    const verdict = sanitizeVerdict(threat.verdict)
    const score = threat['protocol-score']
    const scoreText = Number.isFinite(score)
      ? `with a threat score of ${score}/100`
      : 'with no score available'

    return {
      type: 'indicator',
      spec_version: '2.1',
      id: `indicator--${uuidv4()}`,
      created: now,
      modified: now,
      name: 'Melissae-Honeypot-Framework IOC',
      description: buildIndicatorDescription(threat, ip, verdict, scoreText),
      labels: ['malicious-activity', verdict],
      pattern_type: 'stix',
      pattern: `[ipv4-addr:value = '${ip}']`,
      valid_from: now,
      created_by_ref: identityId,
      x_melissae_verdict: verdict,
      x_melissae_score: score,
    }
  })

  return {
    type: 'bundle',
    id: `bundle--${uuidv4()}`,
    objects: [identity, ...indicators],
  }
}

// Download a JSON object as a file
export function downloadJson(data, filename) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}

