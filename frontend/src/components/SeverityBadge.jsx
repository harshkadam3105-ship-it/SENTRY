/**
 * SeverityBadge — pill badge for incident severity levels
 */

const SEVERITY_CONFIG = {
  critical: {
    label: 'CRITICAL',
    className: 'badge-critical',
    dot: 'bg-red-400',
    glow: 'shadow-red-500/30',
  },
  high: {
    label: 'HIGH',
    className: 'badge-high',
    dot: 'bg-orange-400',
    glow: 'shadow-orange-500/30',
  },
  medium: {
    label: 'MEDIUM',
    className: 'badge-medium',
    dot: 'bg-yellow-400',
    glow: 'shadow-yellow-500/30',
  },
  low: {
    label: 'LOW',
    className: 'badge-low',
    dot: 'bg-slate-400',
    glow: '',
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
        inline-flex items-center gap-1.5
        ${config.className}
        ${isLarge ? 'px-3 py-1 text-sm' : ''}
        ${config.glow ? `shadow-md ${config.glow}` : ''}
      `}
    >
      {showDot && (
        <span className={`w-1.5 h-1.5 rounded-full ${config.dot} ${key === 'critical' ? 'animate-pulse' : ''}`} />
      )}
      {config.label}
    </span>
  )
}
