// MQL parser mirroring

const FIELDS = {
  protocol:    log => log.protocol,
  action:      log => log.action,
  ip:          log => log.ip,
  date:        log => log.date,
  user:        log => log.user,
  'user-agent': log => log['user-agent'],
  path:        log => log.path,
  cve:         log => log.cve,
  agent:       log => log.agent_id,
  agent_id:    log => log.agent_id,
}

function checkHourMatch(logHour, searchValue) {
  if (!logHour) return false
  return String(logHour).toLowerCase().split(':')[0] === String(searchValue).toLowerCase().split(':')[0]
}

function unquote(s) {
  if (s.length >= 2 && s.startsWith('"') && s.endsWith('"')) return s.slice(1, -1)
  return s
}

function matchesTerm(log, term) {
  term = term.trim()
  if (!term) return false

  // field:value or field:"value with spaces"
  const m = /^([A-Za-z_][\w-]*):(.*)$/s.exec(term)
  if (m) {
    const field = m[1].toLowerCase()
    const value = unquote(m[2]).toLowerCase()
    if (!value) return false
    if (field === 'hour') return checkHourMatch(log.hour, value)
    if (!Object.hasOwn(FIELDS, field)) return false
    const getter = FIELDS[field]
    return String(getter(log) || '').toLowerCase().includes(value)
  }

  const needle = unquote(term).toLowerCase()
  if (!needle) return false
  return Object.values(log).some(v => String(v ?? '').toLowerCase().includes(needle))
}

// Tokenizer
const TOKEN_RE = /\(|\)|\bAND\b|\bOR\b|\bNOT\b|!|[^\s():"]+:"[^"]*"|"[^"]*"|[^\s()]+/gi
const KEYWORDS = new Set(['AND', 'OR', 'NOT'])

function tokenize(query) {
  return query.match(TOKEN_RE) || []
}

class Parser {
  constructor(tokens) {
    this.tokens = tokens
    this.pos = 0
  }
  peek() { return this.pos < this.tokens.length ? this.tokens[this.pos] : null }
  peekUpper() { const t = this.peek(); return t == null ? null : t.toUpperCase() }
  consume() { return this.pos < this.tokens.length ? this.tokens[this.pos++] : null }

  parseOr() {
    let left = this.parseAnd()
    while (this.peekUpper() === 'OR') {
      this.consume()
      left = ['OR', left, this.parseAnd()]
    }
    return left
  }

  parseAnd() {
    let left = this.parseFactor()
    while (true) {
      const nxt = this.peekUpper()
      if (nxt == null || nxt === ')' || nxt === 'OR') break
      if (nxt === 'AND') this.consume()
      left = ['AND', left, this.parseFactor()]
    }
    return left
  }

  parseFactor() {
    const tok = this.peek()
    if (tok == null) return ['TRUE']
    const upper = tok.toUpperCase()
    if (upper === 'NOT' || tok === '!') {
      this.consume()
      return ['NOT', this.parseFactor()]
    }
    if (tok === '(') {
      this.consume()
      const inner = this.parseOr()
      if (this.peek() === ')') this.consume()
      return inner
    }
    if (KEYWORDS.has(upper) || tok === ')') {
      this.consume()
      return ['TRUE']
    }
    this.consume()
    return ['TERM', tok]
  }
}

function evalNode(node, log) {
  switch (node[0]) {
    case 'TRUE': return true
    case 'TERM': return matchesTerm(log, node[1])
    case 'NOT':  return !evalNode(node[1], log)
    case 'AND':  return evalNode(node[1], log) && evalNode(node[2], log)
    case 'OR':   return evalNode(node[1], log) || evalNode(node[2], log)
    default:     return false
  }
}

function collectTerms(node, out) {
  if (!node) return out
  if (node[0] === 'TERM') {
    const t = node[1]
    const m = /^([A-Za-z_][\w-]*):(.*)$/s.exec(t)
    out.push(unquote(m ? m[2] : t))
  } else {
    for (let i = 1; i < node.length; i++) collectTerms(node[i], out)
  }
  return out
}

// Execute a search query with AND/OR/NOT logic and parenthesized groups
export function searchLogs(logs, query) {
  if (!query || !query.trim()) return { results: [], terms: [] }
  const tokens = tokenize(query)
  if (tokens.length === 0) return { results: [], terms: [] }
  const tree = new Parser(tokens).parseOr()
  const results = logs.filter(log => evalNode(tree, log))
  return { results, terms: collectTerms(tree, []) }
}
