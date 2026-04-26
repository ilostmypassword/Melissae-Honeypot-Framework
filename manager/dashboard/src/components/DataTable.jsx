import { useState, useMemo, useEffect } from 'react'
import { formatNumber } from '../utils'

const PAGE_SIZES = [25, 50, 100, 250]

// Sortable, paginated data table component
export default function DataTable({
  columns,
  data,
  emptyMessage = 'No data',
  renderCell,
  maxHeight = '280px',
  paginate = false,
  defaultPageSize = 50,
  sortable = false,
}) {

  const [page, setPage] = useState(0)
  const [pageSize, setPageSize] = useState(defaultPageSize)
  const [sortKey, setSortKey] = useState(null)
  const [sortDir, setSortDir] = useState('asc')

  const handleSort = key => {
    if (!sortable) return
    if (sortKey === key) {
      setSortDir(d => d === 'asc' ? 'desc' : 'asc')
    } else {
      setSortKey(key)
      setSortDir('asc')
    }
    setPage(0)
  }

  const sortedData = useMemo(() => {
    if (!sortable || !sortKey) return data
    return [...data].sort((a, b) => {
      const va = a[sortKey] ?? ''
      const vb = b[sortKey] ?? ''
      const cmp = typeof va === 'number' && typeof vb === 'number'
        ? va - vb
        : String(va).localeCompare(String(vb), undefined, { numeric: true })
      return sortDir === 'asc' ? cmp : -cmp
    })
  }, [data, sortKey, sortDir, sortable])

  const totalPages = paginate ? Math.max(1, Math.ceil(sortedData.length / pageSize)) : 1
  const visibleData = useMemo(() => {
    if (!paginate) return sortedData
    const start = page * pageSize
    return sortedData.slice(start, start + pageSize)
  }, [sortedData, page, pageSize, paginate])

  useEffect(() => { if (page >= totalPages) setPage(0) }, [data.length, pageSize, page, totalPages])

  if (data.length === 0) {
    return (
      <div className="text-center py-12 text-text-muted italic border border-dashed border-border/50 rounded-xl bg-surface-secondary/30">
        {emptyMessage}
      </div>
    )
  }

  return (
    <div>
      <div className="overflow-x-auto overflow-y-auto rounded-xl border border-border bg-surface-secondary" style={{ maxHeight }}>
        <table className="w-full text-sm">
          <thead className="sticky top-0 z-10">
            <tr className="bg-surface-tertiary border-b border-border">
              {columns.map(col => (
                <th
                  key={col.key}
                  onClick={() => handleSort(col.key)}
                  className={`px-4 py-3 text-left text-[10px] font-semibold uppercase tracking-[0.12em] text-text-muted ${
                    sortable ? 'cursor-pointer select-none hover:text-text-secondary transition-colors' : ''
                  }`}
                >
                  <span className="inline-flex items-center gap-1">
                    {col.label}
                    {sortable && sortKey === col.key && (
                      <span className="text-accent text-[10px]">{sortDir === 'asc' ? '▲' : '▼'}</span>
                    )}
                  </span>
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-border/20">
            {visibleData.map((row, i) => (
              <tr
                key={i}
                className="hover:bg-surface-hover/30 transition-colors duration-150"
              >
                {columns.map(col => (
                  <td
                    key={col.key}
                    className={`px-4 py-3 text-text-primary ${col.className || ''}`}
                  >
                    {renderCell
                      ? renderCell(col.key, row[col.key], row)
                      : (row[col.key] ?? '-')}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Pagination controls */}
      {paginate && data.length > PAGE_SIZES[0] && (
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 mt-3 text-sm text-text-secondary">
          <div className="flex items-center gap-2">
            <span className="text-[10px] text-text-muted uppercase tracking-wider">Show</span>
            <select
              value={pageSize}
              onChange={e => { setPageSize(Number(e.target.value)); setPage(0) }}
              className="px-2 py-1 bg-surface-tertiary/80 border border-border/40 rounded-md text-text-primary text-xs outline-none focus:border-accent transition-colors"
            >
              {PAGE_SIZES.map(s => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
            <span className="text-[10px] text-text-muted">
              of {formatNumber(data.length)} logs
            </span>
          </div>

          <div className="flex items-center gap-1">
            <PaginationBtn onClick={() => setPage(0)} disabled={page === 0}>«</PaginationBtn>
            <PaginationBtn onClick={() => setPage(p => p - 1)} disabled={page === 0}>‹</PaginationBtn>
            <span className="px-3 py-1 text-xs font-mono text-text-primary">
              {page + 1} / {totalPages}
            </span>
            <PaginationBtn onClick={() => setPage(p => p + 1)} disabled={page >= totalPages - 1}>›</PaginationBtn>
            <PaginationBtn onClick={() => setPage(totalPages - 1)} disabled={page >= totalPages - 1}>»</PaginationBtn>
          </div>
        </div>
      )}
    </div>
  )
}

function PaginationBtn({ onClick, disabled, children }) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className={`w-7 h-7 flex items-center justify-center rounded-md text-sm transition-all duration-150 ${
        disabled
          ? 'text-text-muted/30 cursor-not-allowed'
          : 'text-text-secondary hover:text-text-primary hover:bg-surface-hover/50'
      }`}
    >
      {children}
    </button>
  )
}

