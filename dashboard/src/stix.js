function sanitizeIP(ip) {
  const str = String(ip || '').trim()
  if (/^[0-9a-fA-F.:]+$/.test(str)) return str
  return 'invalid-ip'
}

function sanitizeVerdict(verdict) {
  const allowed = ['benign', 'suspicious', 'malicious', 'unknown']
  const v = String(verdict || 'unknown').toLowerCase()
  return allowed.includes(v) ? v : 'unknown'
}

function uuidv4() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
    const r = crypto.getRandomValues(new Uint8Array(1))[0] & 15
    const v = c === 'x' ? r : (r & 0x3) | 0x8
    return v.toString(16)
  })
}

export function buildStixBundle(threats) {
  const now = new Date().toISOString()
  const identityId = `identity--${uuidv4()}`

  const identity = {
    type: 'identity',
    spec_version: '2.1',
    id: identityId,
    created: now,
    modified: now,
    name: 'Melissae',
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
      name: `Melissae IOC ${ip}`,
      description: `${verdict} IP detected on a Melissae honeypot endpoint ${scoreText}`,
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

export function downloadJson(data, filename) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}
