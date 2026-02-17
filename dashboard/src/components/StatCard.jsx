export default function StatCard({ value, label, onClick, variant }) {
  const variants = {
    default: 'border-border',
    success: 'border-l-4 border-l-verdict-benign border-t-border border-r-border border-b-border',
    alert: 'border-l-4 border-l-verdict-malicious border-t-border border-r-border border-b-border bg-red-500/5',
    warning: 'border-l-4 border-l-verdict-suspicious border-t-border border-r-border border-b-border',
    critical: 'border-2 border-red-500 bg-red-500/10 shadow-lg shadow-red-500/20',
  }

  const isCritical = variant === 'critical'

  return (
    <div
      className={`bg-surface-secondary rounded-xl border p-5 transition-all duration-200 ${
        onClick
          ? 'cursor-pointer hover:-translate-y-0.5 hover:border-accent/40 hover:shadow-lg hover:shadow-accent/5'
          : ''
      } ${variants[variant || 'default']}`}
      onClick={onClick}
      title={onClick ? 'Click to search' : undefined}
    >
      <div className={`text-3xl font-bold font-mono ${isCritical ? 'text-red-400' : 'text-text-primary'}`}>
        {isCritical && <span className="inline-block w-2 h-2 bg-red-500 rounded-full animate-pulse mr-2 align-middle"></span>}
        {value}
      </div>
      <div className={`text-sm mt-2 uppercase tracking-wide font-medium ${isCritical ? 'text-red-300' : 'text-text-secondary'}`}>
        {label}
      </div>
    </div>
  )
}
