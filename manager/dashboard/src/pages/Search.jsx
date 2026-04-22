import { useState, useEffect, useCallback, useMemo } from 'react'
import { useSearchParams } from 'react-router-dom'
import { fetchLogs } from '../api'
import { searchLogs } from '../search'
import { ProtocolTag } from '../components/Tags'
import DataTable from '../components/DataTable'
import { downloadJson } from '../stix'

// Log search page with MQL query support
export default function Search() {
  const [logs, setLogs] = useState([])
  const [results, setResults] = useState(null)
  const [searchTerms, setSearchTerms] = useState([])
  const [query, setQuery] = useState('')
  const [agentFilter, setAgentFilter] = useState('')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [searchParams] = useSearchParams()

  useEffect(() => {
    fetchLogs()
      .then(data => {
        setLogs(data)
        const q = searchParams.get('q')
        const agent = searchParams.get('agent')
        if (agent) setAgentFilter(agent)
        if (q) {
          setQuery(q)
          const filtered = agent ? data.filter(l => l.agent_id === agent) : data
          const { results: r, terms } = searchLogs(filtered, q)
          setResults(r)
          setSearchTerms(terms)
        }
      })
      .catch(err => setError(err.message))
      .finally(() => setLoading(false))
  }, [])

  const agentIds = useMemo(() => {
    const ids = [...new Set(logs.map(l => l.agent_id).filter(Boolean))]
    return ids.sort()
  }, [logs])

  const filteredLogs = useMemo(() => {
    return agentFilter ? logs.filter(l => l.agent_id === agentFilter) : logs
  }, [logs, agentFilter])

  const handleSearch = useCallback(() => {
    if (!query.trim()) return
    const { results: r, terms } = searchLogs(filteredLogs, query)
    setResults(r)
    setSearchTerms(terms)
  }, [filteredLogs, query])

  const handleKeyDown = e => {
    if (e.key === 'Enter') handleSearch()
  }

  const handleExport = () => {
    if (!results || results.length === 0) return
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5)
    const sanitizedQuery = query.replace(/[^\w\s-]/g, '').replace(/\s+/g, '_').slice(0, 30)
    downloadJson(results, `melissae-logs_${sanitizedQuery || 'all'}_${timestamp}.json`)
  }

  const getColumns = data => {
    const base = [
      { key: 'agent_id', label: 'Agent' },
      { key: 'protocol', label: 'Protocol' },
      { key: 'date', label: 'Date' },
      { key: 'hour', label: 'Hour' },
      { key: 'ip', label: 'IP' },
    ]
    const optional = [
      { key: 'user', label: 'User', check: l => l.user?.trim() },
      { key: 'action', label: 'Action', always: true },
      { key: 'cve', label: 'CVE', check: l => l.cve?.trim(), className: 'text-red-400 font-semibold' },
      { key: 'user-agent', label: 'User-Agent', check: l => l['user-agent']?.trim(), className: 'max-w-[200px] truncate' },
      { key: 'path', label: 'Path', check: l => l.path?.trim(), className: 'max-w-[200px] truncate' },
    ]
    return [
      ...base,
      ...optional.filter(col => col.always || data.some(l => col.check?.(l))),
    ]
  }

  const columns = results ? getColumns(results) : []

  const renderCell = (key, value, row) => {
    switch (key) {
      case 'agent_id':
        return (
          <span className="text-xs font-medium px-2 py-1 rounded bg-surface-tertiary text-text-secondary">
            {value || '—'}
          </span>
        )
      case 'protocol':
        return <ProtocolTag protocol={value} />
      case 'date':
      case 'hour':
        return (
          <code className="text-xs font-mono text-text-secondary">{value}</code>
        )
      case 'ip':
        return (
          <code className="text-xs font-mono text-accent">
            <HighlightedText text={value} terms={searchTerms} />
          </code>
        )
      default:
        return (
          <span>
            <HighlightedText text={value || '-'} terms={searchTerms} />
          </span>
        )
    }
  }

  if (loading) return <LoadingState />
  if (error) return <ErrorState message={error} />

  return (
    <div className="space-y-5 animate-fade-in">
      {/* Search Bar */}
      <div className="glass-card p-4 flex flex-col sm:flex-row gap-3 flex-wrap items-stretch sm:items-center">
        <select
          value={agentFilter}
          onChange={e => { setAgentFilter(e.target.value); setResults(null) }}
          className="px-3 py-2.5 bg-surface-tertiary border border-border rounded-lg text-text-primary text-sm focus:border-accent outline-none"
        >
          <option value="">All agents</option>
          {agentIds.map(id => (
            <option key={id} value={id}>{id}</option>
          ))}
        </select>
        <input
          type="text"
          value={query}
          onChange={e => setQuery(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder="Search by IP, User, action... (e.g. protocol:ssh AND action:failed)"
          className="flex-1 min-w-0 px-4 py-2.5 bg-surface-tertiary border border-border rounded-lg text-text-primary placeholder-text-muted text-sm focus:border-accent focus:ring-1 focus:ring-accent/30 outline-none transition-all"
        />
        <div className="flex gap-2">
          <button
            onClick={handleSearch}
            className="flex-1 sm:flex-none px-5 py-2.5 bg-accent hover:bg-accent-hover text-white rounded-lg font-medium text-sm transition-colors"
          >
            Search
          </button>
          {results && results.length > 0 && (
            <button
              onClick={handleExport}
              className="flex-1 sm:flex-none px-4 py-2.5 bg-surface-tertiary hover:bg-surface-hover text-text-primary border border-border rounded-lg font-medium text-sm transition-colors whitespace-nowrap"
            >
              Export ({results.length})
            </button>
          )}
        </div>
      </div>

      {/* Results */}
      {results === null ? (
        <div className="glass-card text-center py-16 text-text-muted italic border-dashed">
          Enter a search query to begin
        </div>
      ) : (
        <DataTable
          columns={columns}
          data={results}
          emptyMessage="No results found — try adjusting your search criteria"
          renderCell={renderCell}
          maxHeight="calc(100vh - 220px)"
          paginate
          sortable
          defaultPageSize={50}
        />
      )}
    </div>
  )
}

// Text with search term highlighting
function HighlightedText({ text, terms }) {
  if (!text || !terms || terms.length === 0) return <>{String(text)}</>

  const str = String(text)
  const cleanTerms = terms
    .map(t => t.replace(/^[!=]+/, '').trim())
    .filter(Boolean)

  if (cleanTerms.length === 0) return <>{str}</>

  const escaped = cleanTerms.map(t => t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
  const regex = new RegExp(`(${escaped.join('|')})`, 'gi')
  const parts = str.split(regex)

  return (
    <>
      {parts.map((part, i) =>
        regex.test(part) ? (
          <mark key={i} className="bg-accent/20 text-accent-hover px-0.5 rounded">
            {part}
          </mark>
        ) : (
          <span key={i}>{part}</span>
        )
      )}
    </>
  )
}

function LoadingState() {
  return (
    <div className="space-y-5 animate-fade-in">
      <div className="skeleton h-16 rounded-xl" />
      <div className="skeleton h-64 rounded-xl" />
    </div>
  )
}

function ErrorState({ message }) {
  return (
    <div className="glass-card text-verdict-malicious p-6 text-center border-verdict-malicious/20 animate-fade-in">
      <div className="font-medium">Unable to load logs</div>
      <div className="text-sm mt-1 opacity-60">{message}</div>
    </div>
  )
}

