/**
 * SeverityBadge — Restrained enterprise severity indicator badge.
 * Compact pill with subtle solid tint, clean 1px border, and optional status dot.
 */

const SEVERITY_CONFIG = {
  critical: {
    label: 'CRITICAL',
    className: 'bg-red-950/40 text-red-400 border border-red-500/30',
    dot: 'bg-red-500',
  },
  high: {
    label: 'HIGH',
    className: 'bg-orange-950/40 text-orange-400 border border-orange-500/30',
    dot: 'bg-orange-500',
  },
  medium: {
    label: 'MEDIUM',
    className: 'bg-amber-950/30 text-amber-400 border border-amber-500/30',
    dot: 'bg-amber-400',
  },
  low: {
    label: 'LOW',
    className: 'bg-slate-800/60 text-slate-400 border border-slate-700/50',
    dot: 'bg-slate-500',
  },
}

export default function SeverityBadge({ severity, size = 'sm', showDot = true }) {
  let key = 'low'
  if (typeof severity === 'number') {
    if (severity >= 4) key = 'critical'
    else if (severity === 3) key = 'high'
    else if (severity === 2) key = 'medium'
    else key = 'low'
  } else if (typeof severity === 'string') {
    key = severity.toLowerCase()
  }

  const config = SEVERITY_CONFIG[key] || SEVERITY_CONFIG.low
  const isLarge = size === 'lg'

  return (
    <span
      className={`
        inline-flex items-center gap-1.5 font-semibold font-mono uppercase tracking-wider rounded
        ${isLarge ? 'px-2.5 py-1 text-xs' : 'px-1.5 py-0.5 text-[10px]'}
        ${config.className}
      `}
    >
      {showDot && (
        <span
          className={`rounded-full shrink-0 ${isLarge ? 'w-2 h-2' : 'w-1.5 h-1.5'} ${config.dot} ${
            key === 'critical' ? 'animate-pulse' : ''
          }`}
        />
      )}
      {config.label}
    </span>
  )
}
