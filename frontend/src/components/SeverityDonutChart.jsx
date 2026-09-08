import { IconPieChart } from './Icons'

/**
 * SeverityDonutChart — Threat breakdown donut chart
 * Inspired by Siemplify and enterprise SOAR summary views:
 * Displays incident severity distribution using pure, responsive SVG.
 */

export default function SeverityDonutChart({ incidents = [] }) {
  const counts = {
    critical: incidents.filter(i => i.severity === 'critical').length,
    high:     incidents.filter(i => i.severity === 'high').length,
    medium:   incidents.filter(i => i.severity === 'medium').length,
    low:      incidents.filter(i => i.severity === 'low').length,
  }

  const total = incidents.length || 1

  const segments = [
    { key: 'critical', label: 'Critical', count: counts.critical, color: '#ef4444', pct: Math.round((counts.critical / total) * 100) },
    { key: 'high',     label: 'High',     count: counts.high,     color: '#f97316', pct: Math.round((counts.high / total) * 100) },
    { key: 'medium',   label: 'Medium',   count: counts.medium,   color: '#eab308', pct: Math.round((counts.medium / total) * 100) },
    { key: 'low',      label: 'Low',      count: counts.low,      color: '#64748b', pct: Math.round((counts.low / total) * 100) },
  ]

  // Calculate SVG stroke-dasharray
  // Circle circumference = 2 * PI * r = 2 * PI * 40 ≈ 251.3
  const radius = 40
  const circumference = 2 * Math.PI * radius
  let accumulatedOffset = 0

  return (
    <div className="glass-card p-5 flex flex-col justify-between h-full">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-white/5 pb-3">
        <div className="flex items-center gap-2">
          <IconPieChart className="w-4 h-4 text-cyan-400" /><div><h3 className="text-sm font-semibold text-slate-200">Severity Distribution</h3>
            <p className="text-xs text-slate-500">Active threats by risk category</p>
          </div>
        </div>
        <span className="text-xs font-mono text-slate-400 bg-surface-700/60 px-2 py-0.5 rounded">
          {incidents.length} Total
        </span>
      </div>

      {/* Donut Chart and Center Counter */}
      <div className="flex items-center justify-center my-4 relative">
        <svg width="150" height="150" viewBox="0 0 100 100" className="transform -rotate-90 overflow-visible">
          {/* Background track */}
          <circle
            cx="50"
            cy="50"
            r={radius}
            fill="transparent"
            stroke="rgba(255,255,255,0.04)"
            strokeWidth="12"
          />

          {segments.map(seg => {
            const strokeLength = (seg.count / total) * circumference
            const strokeDasharray = `${strokeLength} ${circumference - strokeLength}`
            const strokeDashoffset = -accumulatedOffset
            accumulatedOffset += strokeLength

            if (seg.count === 0) return null

            return (
              <circle
                key={seg.key}
                cx="50"
                cy="50"
                r={radius}
                fill="transparent"
                stroke={seg.color}
                strokeWidth="12"
                strokeDasharray={strokeDasharray}
                strokeDashoffset={strokeDashoffset}
                className="transition-all duration-700 hover:opacity-80"
              />
            )
          })}
        </svg>

        {/* Center label */}
        <div className="absolute inset-0 flex flex-col items-center justify-center text-center pointer-events-none">
          <span className="text-2xl font-bold font-mono text-white leading-none">
            {incidents.length}
          </span>
          <span className="text-[10px] uppercase text-slate-500 tracking-wider mt-1">Threats</span>
        </div>
      </div>

      {/* Legend */}
      <div className="grid grid-cols-2 gap-2 pt-2 border-t border-white/5">
        {segments.map(seg => (
          <div key={seg.key} className="flex items-center justify-between text-xs p-1.5 rounded bg-surface-800/30">
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full" style={{ backgroundColor: seg.color }} />
              <span className="text-slate-300">{seg.label}</span>
            </div>
            <div className="flex items-center gap-1 font-mono">
              <span className="text-white font-semibold">{seg.count}</span>
              <span className="text-[10px] text-slate-500">({seg.pct}%)</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
