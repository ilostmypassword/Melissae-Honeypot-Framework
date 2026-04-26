import { formatNumber } from '../utils'

// Dashboard statistic card with label and value
export default function StatCard({ value, label, onClick, variant, trend }) {
  const variants = {
    default: 'border-border/50',
    success: 'border-l-[3px] border-l-verdict-benign border-t-border/50 border-r-border/50 border-b-border/50',
    alert: 'border-l-[3px] border-l-verdict-malicious border-t-border/50 border-r-border/50 border-b-border/50 bg-red-500/[0.03]',
    warning: 'border-l-[3px] border-l-verdict-suspicious border-t-border/50 border-r-border/50 border-b-border/50',
    critical: 'border border-red-500/40 bg-red-500/[0.06] shadow-lg shadow-red-500/10',
  }

  const isCritical = variant === 'critical'

  return (
    <div
      className={`glass-card-hover p-5 ${
        onClick ? 'cursor-pointer' : ''
      } ${variants[variant || 'default']}`}
      onClick={onClick}
      title={onClick ? 'Click to search' : undefined}
    >
      <div className="flex items-start justify-between gap-2">
        <div className={`text-3xl font-bold font-mono tracking-tight ${isCritical ? 'text-red-400' : 'text-text-primary'}`}>
          {isCritical && <span className="inline-block w-2 h-2 bg-red-500 rounded-full animate-pulse mr-2 align-middle"></span>}
          {typeof value === 'number' ? formatNumber(value) : value}
        </div>
        {trend != null && trend !== 0 && (
          <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded-md flex items-center gap-0.5 shrink-0 mt-1 ${
            trend > 0
              ? 'bg-red-500/10 text-red-400 border border-red-500/20'
              : 'bg-green-500/10 text-green-400 border border-green-500/20'
          }`}>
            {trend > 0 ? '↑' : '↓'} {Math.abs(trend)}%
          </span>
        )}
      </div>
      <div className={`text-xs mt-2.5 uppercase tracking-[0.12em] font-medium ${isCritical ? 'text-red-300/80' : 'text-text-muted'}`}>
        {label}
      </div>
      {trend != null && trend !== 0 && (
        <div className="text-[10px] text-text-muted/60 mt-1">vs previous 24h</div>
      )}
    </div>
  )
}

