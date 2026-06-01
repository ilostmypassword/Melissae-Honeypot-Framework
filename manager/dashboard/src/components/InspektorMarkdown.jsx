export const mdComponents = {
  h1: ({ children }) => (
    <h1 className="text-base font-bold text-text-primary mt-2 mb-3">{children}</h1>
  ),
  h2: ({ children }) => (
    <h2 className="text-sm font-bold uppercase tracking-widest text-text-secondary mt-1 mb-2">
      {children}
    </h2>
  ),
  h3: ({ children }) => (
    <h3 className="text-xs font-bold uppercase tracking-wider text-accent mt-4 mb-2">
      {children}
    </h3>
  ),
  p: ({ children }) => (
    <p className="text-sm text-text-secondary leading-relaxed mb-2">{children}</p>
  ),
  strong: ({ children }) => (
    <strong className="font-semibold text-text-primary">{children}</strong>
  ),
  ul: ({ children }) => <ul className="space-y-1.5 mb-2 ml-1">{children}</ul>,
  ol: ({ children }) => <ol className="space-y-1.5 mb-2 ml-1 list-decimal list-inside">{children}</ol>,
  li: ({ children }) => (
    <li className="text-sm text-text-secondary leading-snug flex gap-2">
      <span className="text-accent shrink-0 mt-1.5 w-1 h-1 rounded-full bg-accent" />
      <span className="min-w-0">{children}</span>
    </li>
  ),
  code: ({ children }) => (
    <code className="font-mono text-[12px] px-1.5 py-0.5 rounded bg-surface-tertiary text-text-primary">
      {children}
    </code>
  ),
  table: ({ children }) => (
    <div className="overflow-x-auto my-2 rounded-lg border border-border/50">
      <table className="w-full text-xs">{children}</table>
    </div>
  ),
  thead: ({ children }) => <thead className="bg-surface-tertiary/60">{children}</thead>,
  th: ({ children }) => (
    <th className="text-left font-semibold uppercase tracking-wide text-[10px] text-text-muted px-3 py-2">
      {children}
    </th>
  ),
  td: ({ children }) => (
    <td className="px-3 py-2 text-text-secondary border-t border-border/40 align-top">
      {children}
    </td>
  ),
  a: ({ children, href }) => (
    <a href={href} className="text-accent hover:text-accent-hover underline" target="_blank" rel="noreferrer">
      {children}
    </a>
  ),
}

// Compact "x min ago" formatter for an ISO timestamp
export function timeAgo(iso) {
  if (!iso) return null
  const then = new Date(iso).getTime()
  if (Number.isNaN(then)) return null
  const secs = Math.max(0, Math.floor((Date.now() - then) / 1000))
  if (secs < 60) return 'just now'
  const mins = Math.floor(secs / 60)
  if (mins < 60) return `${mins}m ago`
  const hours = Math.floor(mins / 60)
  if (hours < 24) return `${hours}h ago`
  return `${Math.floor(hours / 24)}d ago`
}
