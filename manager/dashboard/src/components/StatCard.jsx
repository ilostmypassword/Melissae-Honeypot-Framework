import { formatNumber } from '../utils'

// Dashboard statistic card with label and value
export default function StatCard({ value, label, onClick, variant, trend }) {
  const variants = {
    default: 'border-border/50',
    success: 'border-l-[3px] border-l-verdict-benign border-t-border/50 border-r-border/50 border-b-border/50',
    alert: 'border-l-[3px] border-l-verdict-malicious border-t-border/50 border-r-border/50 border-b-border/50 bg-verdict-malicious/[0.035]',
    warning: 'border-l-[3px] border-l-verdict-suspicious border-t-border/50 border-r-border/50 border-b-border/50',
    critical: 'border border-verdict-malicious/35 bg-verdict-malicious/[0.055] shadow-lg shadow-verdict-malicious/10',
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
        <div className={`text-3xl font-bold font-mono tracking-tight ${isCritical ? 'text-verdict-malicious' : 'text-text-primary'}`}>
          {isCritical && <span className="inline-block w-2 h-2 bg-verdict-malicious rounded-full animate-pulse mr-2 align-middle"></span>}
          {typeof value === 'number' ? formatNumber(value) : value}
        </div>
        {trend != null && trend !== 0 && (
          <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded-md flex items-center gap-0.5 shrink-0 mt-1 ${
            trend > 0
              ? 'bg-verdict-malicious/10 text-verdict-malicious border border-verdict-malicious/20'
              : 'bg-verdict-benign/10 text-verdict-benign border border-verdict-benign/20'
          }`}>
            {trend > 0 ? '↑' : '↓'} {Math.abs(trend)}%
          </span>
        )}
      </div>
      <div className={`text-xs mt-2.5 uppercase tracking-[0.12em] font-medium ${isCritical ? 'text-verdict-malicious/80' : 'text-text-muted'}`}>
        {label}
      </div>
      {trend != null && trend !== 0 && (
        <div className="text-[10px] text-text-muted/60 mt-1">vs previous 24h</div>
      )}
    </div>
  )
}

