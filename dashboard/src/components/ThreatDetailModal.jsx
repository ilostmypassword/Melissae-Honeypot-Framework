import { VerdictTag } from './Tags'

export default function ThreatDetailModal({ threat, onClose }) {
  if (!threat) return null

  const score = Number.isFinite(threat['protocol-score'])
    ? `${threat['protocol-score']}/100`
    : 'N/A'
  const confidence = Number.isFinite(threat.confidence)
    ? `${Math.round(threat.confidence * 100)}%`
    : 'N/A'
  const reasons = Array.isArray(threat.reasons) ? threat.reasons : []

  return (
    <div
      className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-[9999]"
      onClick={onClose}
    >
      <div
        className="bg-surface-secondary border border-border rounded-xl p-5 w-full max-w-lg mx-4 shadow-2xl"
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-start justify-between mb-4">
          <div>
            <p className="text-xs uppercase tracking-wide text-text-muted font-semibold">
              Threat details
            </p>
            <div className="flex items-center gap-3 mt-1">
              <h3 className="text-lg font-semibold text-text-primary font-mono">
                {threat.ip}
              </h3>
              <VerdictTag verdict={threat.verdict} />
            </div>
          </div>
          <button
            onClick={onClose}
            className="w-8 h-8 rounded-full bg-surface-tertiary text-text-secondary hover:bg-surface-hover hover:text-text-primary flex items-center justify-center transition-colors text-lg"
            aria-label="Close"
          >
            &times;
          </button>
        </div>

        {/* Metrics */}
        <div className="grid grid-cols-2 gap-3 mb-4">
          {[
            { label: 'Score', value: score },
            { label: 'Confidence', value: confidence },
            { label: 'First seen', value: threat.first_seen || 'N/A' },
            { label: 'Last seen', value: threat.last_seen || 'N/A' },
          ].map(m => (
            <div key={m.label} className="bg-surface-tertiary rounded-lg p-3">
              <span className="text-xs text-text-muted block">{m.label}</span>
              <strong className="block text-text-primary mt-1 font-mono text-sm">
                {m.value}
              </strong>
            </div>
          ))}
        </div>

        {/* Reasons */}
        <div>
          <p className="text-xs uppercase tracking-wide text-text-muted font-semibold mb-2">
            Reasons
          </p>
          {reasons.length === 0 ? (
            <p className="text-sm text-text-muted italic">
              No reasons available
            </p>
          ) : (
            <ul className="space-y-2 max-h-48 overflow-y-auto">
              {reasons.map((r, i) => (
                <li
                  key={i}
                  className="flex items-start gap-3 bg-surface-tertiary rounded-lg px-3 py-2.5 text-sm text-text-primary"
                >
                  <span className="w-2 h-2 rounded-full bg-accent mt-1.5 shrink-0" />
                  <span>{r}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </div>
  )
}
