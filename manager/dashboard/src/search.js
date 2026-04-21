// Check if a log entry matches a single search term
function matchesTerm(log, term) {
  let isNegation = false
  term = term.trim()

  if (/^(NOT\s+|!)/i.test(term)) {
    isNegation = true
    term = term.replace(/^(NOT\s+|!)/i, '').trim()
  }

  let match = false

  if (term.includes(':')) {
    const colonIdx = term.indexOf(':')
    const field = term.slice(0, colonIdx).toLowerCase()
    const value = term.slice(colonIdx + 1).toLowerCase()

    switch (field) {
      case 'protocol':   match = log.protocol?.toLowerCase().includes(value); break
      case 'action':     match = log.action?.toLowerCase().includes(value); break
      case 'ip':         match = log.ip?.toLowerCase().includes(value); break
      case 'date':       match = log.date?.toLowerCase().includes(value); break
      case 'hour':       match = checkHourMatch(log.hour, value); break
      case 'user':       match = (log.user || '').toLowerCase().includes(value); break
      case 'user-agent': match = log['user-agent']?.toLowerCase().includes(value); break
      case 'path':       match = log.path?.toLowerCase().includes(value); break
      case 'cve':        match = (log.cve || '').toLowerCase().includes(value); break
      case 'agent':
      case 'agent_id':   match = (log.agent_id || '').toLowerCase().includes(value); break
      default:           match = false
    }
  } else {
    match = Object.values(log).some(val =>
      String(val).toLowerCase().includes(term.toLowerCase())
    )
  }

  return isNegation ? !match : match
}

// Check if a log timestamp matches an hour filter
function checkHourMatch(logHour, searchValue) {
  if (!logHour) return false
  const logHourPart = logHour.toLowerCase().split(':')[0]
  const searchHour = searchValue.toLowerCase().split(':')[0]
  return logHourPart === searchHour
}

// Execute a search query with AND/OR/NOT logic
export function searchLogs(logs, query) {
  const termsWithOperators = query.split(/(\bAND\b|\bOR\b)/i)
  const searchGroups = []
  let currentGroup = []
  let lastOperator = 'AND'

  termsWithOperators.forEach(term => {
    term = term.trim()
    if (!term) return

    if (/^AND$/i.test(term)) {
      if (currentGroup.length > 0) {
        searchGroups.push({ terms: currentGroup, operator: lastOperator })
        currentGroup = []
      }
      lastOperator = 'AND'
    } else if (/^OR$/i.test(term)) {
      if (currentGroup.length > 0) {
        searchGroups.push({ terms: currentGroup, operator: lastOperator })
        currentGroup = []
      }
      lastOperator = 'OR'
    } else {
      if (term.length >= 2) {
        if (term.includes(':') && term.split(':')[1].trim() === '') return
        currentGroup.push(term)
      }
    }
  })

  if (currentGroup.length > 0) {
    searchGroups.push({ terms: currentGroup, operator: lastOperator })
  }

  if (searchGroups.length === 0) return { results: [], terms: [] }

  let filteredLogs = []

  searchGroups.forEach((group, index) => {
    const groupResults = logs.filter(log =>
      group.terms.every(term => matchesTerm(log, term))
    )

    if (index === 0) {
      filteredLogs = groupResults
    } else {
      if (group.operator === 'AND') {
        filteredLogs = filteredLogs.filter(log =>
          groupResults.some(r => r === log)
        )
      } else {
        const newLogs = groupResults.filter(log =>
          !filteredLogs.some(f => f === log)
        )
        filteredLogs = [...filteredLogs, ...newLogs]
      }
    }
  })

  return { results: filteredLogs, terms: searchGroups.flatMap(g => g.terms) }
}

