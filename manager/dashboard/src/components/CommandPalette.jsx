import { useState, useEffect, useMemo, useRef } from 'react'
import { useNavigate } from 'react-router-dom'

const ENTRIES = [
  { group: 'Go to', label: 'Dashboard', hint: 'Overview', to: '/', keywords: 'home overview' },
  { group: 'Go to', label: 'Agents', hint: 'Honeypot nodes', to: '/agents', keywords: 'nodes sensors topology' },
  { group: 'Go to', label: 'Alerts', hint: 'Detection rules', to: '/alerts', keywords: 'detection rules incidents' },
  { group: 'Go to', label: 'Traffic', hint: 'Activity statistics', to: '/stats/activity', keywords: 'activity stats timeline' },
  { group: 'Go to', label: 'Threats', hint: 'Attacker statistics', to: '/stats/attackers', keywords: 'attackers stats' },
  { group: 'Go to', label: 'Inspektor', hint: 'AI assistant', to: '/inspektor', keywords: 'ai chat assistant bedrock' },
  { group: 'Go to', label: 'Threat Intelligence', hint: 'Verdicts and kill chains', to: '/threats', keywords: 'verdict killchain stix' },
  { group: 'Go to', label: 'Search', hint: 'Query logs', to: '/search', keywords: 'logs query find' },
  { group: 'Go to', label: 'Geo Map', hint: 'Attack origins', to: '/map', keywords: 'world map geoip' },
  { group: 'Quick search', label: 'SSH activity', hint: 'protocol:ssh', to: '/search?q=protocol%3Assh', keywords: 'protocol:ssh' },
  { group: 'Quick search', label: 'HTTP activity', hint: 'protocol:http', to: '/search?q=protocol%3Ahttp', keywords: 'protocol:http web' },
  { group: 'Quick search', label: 'Successful logins', hint: 'action:successful', to: '/search?q=action%3Asuccessful', keywords: 'action:successful login auth' },
  { group: 'Quick search', label: 'CVE exploits', hint: 'cve:CVE', to: '/search?q=cve%3ACVE', keywords: 'cve:CVE exploit vulnerability' },
]


export default function CommandPalette({ open, onClose }) {
  const navigate = useNavigate()
  const [query, setQuery] = useState('')
  const [active, setActive] = useState(0)
  const inputRef = useRef(null)
  const listRef = useRef(null)
  const returnFocusRef = useRef(null)

  useEffect(() => {
    if (!open) return undefined
    returnFocusRef.current = document.activeElement
    setQuery('')
    setActive(0)
    inputRef.current?.focus()
    return () => {
      const el = returnFocusRef.current
      if (el && typeof el.focus === 'function') el.focus()
    }
  }, [open])

  const items = useMemo(() => {
    const q = query.trim().toLowerCase()
    const matches = ENTRIES.filter(e =>
      !q || `${e.label} ${e.hint} ${e.keywords}`.toLowerCase().includes(q)
    )
    if (q) {
      matches.push({
        group: 'Search',
        label: `Search logs for \u201C${query.trim()}\u201D`,
        hint: '',
        to: `/search?q=${encodeURIComponent(query.trim())}`,
      })
    }
    return matches
  }, [query])

  useEffect(() => {
    if (!open) return
    listRef.current
      ?.querySelector(`[data-idx="${active}"]`)
      ?.scrollIntoView({ block: 'nearest' })
  }, [active, open])

  if (!open) return null

  const choose = item => {
    if (!item) return
    onClose()
    navigate(item.to, { viewTransition: true })
  }

  const onKeyDown = e => {
    if (e.key === 'Escape') {
      e.preventDefault()
      onClose()
    } else if (e.key === 'ArrowDown') {
      e.preventDefault()
      if (items.length) setActive(i => (i + 1) % items.length)
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      if (items.length) setActive(i => (i - 1 + items.length) % items.length)
    } else if (e.key === 'Enter') {
      e.preventDefault()
      choose(items[active])
    } else if (e.key === 'Tab') {
      // Keep focus inside the dialog
      e.preventDefault()
    }
  }

  let lastGroup = null

  return (
    <div
      className="fixed inset-0 z-[10000] flex items-start justify-center px-4 pt-[15vh] bg-black/60 backdrop-blur-sm animate-fade-in"
      onMouseDown={e => { if (e.target === e.currentTarget) onClose() }}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Command palette"
        onKeyDown={onKeyDown}
        className="glass-card w-full max-w-xl overflow-hidden shadow-2xl shadow-black/50 animate-slide-up"
      >
        <div className="flex items-center gap-3 px-4 py-3 border-b border-border">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" className="text-text-muted shrink-0" aria-hidden="true">
            <circle cx="11" cy="11" r="7" />
            <line x1="16.5" y1="16.5" x2="21" y2="21" />
          </svg>
          <input
            ref={inputRef}
            value={query}
            onChange={e => { setQuery(e.target.value); setActive(0) }}
            maxLength={200}
            placeholder="Jump to a page or search logs…"
            spellCheck={false}
            autoComplete="off"
            role="combobox"
            aria-expanded="true"
            aria-controls="cmdk-list"
            aria-activedescendant={items.length ? `cmdk-item-${active}` : undefined}
            className="flex-1 min-w-0 bg-transparent text-sm text-text-primary placeholder:text-text-muted outline-none"
          />
          <kbd className="text-[10px] font-mono text-text-muted px-1.5 py-0.5 rounded bg-surface-tertiary border border-border">Esc</kbd>
        </div>

        <ul id="cmdk-list" role="listbox" ref={listRef} className="max-h-[50vh] overflow-y-auto py-2">
          {items.map((item, idx) => {
            const showGroup = item.group !== lastGroup
            lastGroup = item.group
            const isActive = idx === active
            return (
              <li key={`${item.group}-${item.to}`} role="presentation">
                {showGroup && (
                  <p className="section-title px-4 pt-2 pb-1">{item.group}</p>
                )}
                <div
                  id={`cmdk-item-${idx}`}
                  role="option"
                  aria-selected={isActive}
                  data-idx={idx}
                  onMouseEnter={() => setActive(idx)}
                  onClick={() => choose(item)}
                  className={`flex items-center gap-3 mx-2 px-3 py-2 rounded-lg text-[13px] cursor-pointer transition-colors ${
                    isActive ? 'bg-accent/15 text-accent-hover' : 'text-text-secondary'
                  }`}
                >
                  <span className="truncate flex-1 min-w-0 font-medium">{item.label}</span>
                  {item.hint && (
                    <span className="text-[11px] text-text-muted font-mono truncate shrink-0 max-w-[40%]">{item.hint}</span>
                  )}
                  {isActive && <span className="text-[11px] text-text-muted shrink-0" aria-hidden="true">↵</span>}
                </div>
              </li>
            )
          })}
        </ul>

        <div className="flex items-center gap-4 px-4 py-2 border-t border-border text-[10px] text-text-muted">
          <span><kbd className="font-mono">↑↓</kbd> navigate</span>
          <span><kbd className="font-mono">↵</kbd> open</span>
          <span><kbd className="font-mono">Esc</kbd> close</span>
        </div>
      </div>
    </div>
  )
}
