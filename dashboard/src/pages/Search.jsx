import { useState, useEffect, useCallback } from 'react'
import { useSearchParams } from 'react-router-dom'
import { fetchLogs } from '../api'
import { searchLogs } from '../search'
import { ProtocolTag } from '../components/Tags'
import DataTable from '../components/DataTable'
import { downloadJson } from '../stix'

export default function Search() {
  const [logs, setLogs] = useState([])
  const [results, setResults] = useState(null)
  const [searchTerms, setSearchTerms] = useState([])
  const [query, setQuery] = useState('')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [searchParams] = useSearchParams()

  useEffect(() => {
    fetchLogs()
      .then(data => {
        setLogs(data)
        const q = searchParams.get('q')
        if (q) {
          setQuery(q)
          const { results: r, terms } = searchLogs(data, q)
          setResults(r)
          setSearchTerms(terms)
        }
      })
      .catch(err => setError(err.message))
      .finally(() => setLoading(false))
  }, [])

  const handleSearch = useCallback(() => {
    if (!query.trim()) return
    const { results: r, terms } = searchLogs(logs, query)
    setResults(r)
    setSearchTerms(terms)
  }, [logs, query])

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
    <div className="space-y-5">
      {/* Search Bar */}
      <div className="bg-surface-secondary rounded-xl border border-border p-4 flex gap-3 flex-wrap">
        <input
          type="text"
          value={query}
          onChange={e => setQuery(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder="Search by IP, User, action... (e.g. protocol:ssh AND action:failed)"
          className="flex-1 min-w-[240px] px-4 py-2.5 bg-surface-tertiary border border-border rounded-lg text-text-primary placeholder-text-muted text-sm focus:border-accent focus:ring-1 focus:ring-accent/30 outline-none transition-all"
        />
        <button
          onClick={handleSearch}
          className="px-5 py-2.5 bg-accent hover:bg-accent-hover text-white rounded-lg font-medium text-sm transition-colors"
        >
          Search
        </button>
        {results && results.length > 0 && (
          <button
            onClick={handleExport}
            className="px-5 py-2.5 bg-surface-tertiary hover:bg-surface-hover text-text-primary border border-border rounded-lg font-medium text-sm transition-colors"
          >
            Export ({results.length} logs)
          </button>
        )}
      </div>

      {/* Results */}
      {results === null ? (
        <div className="text-center py-16 text-text-muted italic border-2 border-dashed border-border rounded-xl">
          Enter a search query to begin
        </div>
      ) : (
        <DataTable
          columns={columns}
          data={results}
          emptyMessage="No results found — try adjusting your search criteria"
          renderCell={renderCell}
          maxHeight="660px"
        />
      )}
    </div>
  )
}

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
    <div className="flex items-center justify-center h-64">
      <div className="text-text-muted text-lg flex items-center gap-3">
        <div className="w-5 h-5 border-2 border-accent border-t-transparent rounded-full animate-spin" />
        Loading logs...
      </div>
    </div>
  )
}

function ErrorState({ message }) {
  return (
    <div className="bg-verdict-malicious/10 border border-verdict-malicious/30 text-verdict-malicious rounded-xl p-6 text-center">
      <div className="text-2xl mb-2">&diams;</div>
      <div className="font-medium">Unable to load logs</div>
      <div className="text-sm mt-1 opacity-75">{message}</div>
    </div>
  )
}
