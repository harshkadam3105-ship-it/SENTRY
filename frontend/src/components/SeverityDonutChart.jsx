/**
 * SeverityDonutChart — Severity Distribution Donut Chart.
 * Professional radial SVG donut chart with clean legend and centered threat tally.
 */

export default function SeverityDonutChart({ incidents = [] }) {
  const counts = {
    critical: incidents.filter(i => i.severity === 'critical').length,
    high: incidents.filter(i => i.severity === 'high').length,
    medium: incidents.filter(i => i.severity === 'medium').length,
    low: incidents.filter(i => i.severity === 'low').length,
  }

  const total = incidents.length

  const segments = [
    { key: 'critical', label: 'Critical', count: counts.critical, color: '#ef4444', pct: total > 0 ? Math.round((counts.critical / total) * 100) : 0 },
    { key: 'high', label: 'High', count: counts.high, color: '#f97316', pct: total > 0 ? Math.round((counts.high / total) * 100) : 0 },
    { key: 'medium', label: 'Medium', count: counts.medium, color: '#eab308', pct: total > 0 ? Math.round((counts.medium / total) * 100) : 0 },
    { key: 'low', label: 'Low', count: counts.low, color: '#64748b', pct: total > 0 ? Math.round((counts.low / total) * 100) : 0 },
  ]

  // Circle circumference = 2 * PI * r = 2 * PI * 38 ≈ 238.76
  const radius = 38
  const circumference = 2 * Math.PI * radius
  let accumulatedOffset = 0

  return (
    <div className="soc-panel p-4 flex flex-col justify-between h-full">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-slate-800 pb-2.5">
        <div className="flex items-center gap-2">
          <div className="p-1 rounded bg-slate-850 border border-slate-800 text-slate-400">
            <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M21.21 15.89A10 10 0 1 1 8 2.83" />
              <path d="M22 12A10 10 0 0 0 12 2v10z" />
            </svg>
          </div>
          <div>
            <h3 className="text-xs font-semibold text-slate-200 uppercase tracking-wider">
              Severity Distribution
            </h3>
            <p className="text-[11px] text-slate-400">Active incidents by tier</p>
          </div>
        </div>
        <span className="text-[11px] font-mono text-slate-400 bg-slate-900 border border-slate-800 px-2 py-0.5 rounded">
          {total} Total
        </span>
      </div>

      {/* Radial Donut and Center Metric */}
      <div className="flex items-center justify-center my-3 relative">
        <svg width="130" height="130" viewBox="0 0 100 100" className="transform -rotate-90">
          {/* Background track */}
          <circle
            cx="50"
            cy="50"
            r={radius}
            fill="transparent"
            stroke="#161e2e"
            strokeWidth="10"
          />

          {total > 0 &&
            segments.map(seg => {
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
                  strokeWidth="10"
                  strokeDasharray={strokeDasharray}
                  strokeDashoffset={strokeDashoffset}
                  className="transition-all duration-500"
                />
              )
            })}
        </svg>

        {/* Center label */}
        <div className="absolute inset-0 flex flex-col items-center justify-center text-center pointer-events-none">
          <span className="text-2xl font-bold font-mono text-slate-100 leading-none">
            {total}
          </span>
          <span className="text-[9px] uppercase font-semibold text-slate-500 tracking-wider mt-0.5">
            Incidents
          </span>
        </div>
      </div>

      {/* Legend */}
      <div className="grid grid-cols-2 gap-1.5 pt-2 border-t border-slate-800">
        {segments.map(seg => (
          <div
            key={seg.key}
            className="flex items-center justify-between text-[11px] px-2 py-1 rounded bg-slate-900/60 border border-slate-800/80"
          >
            <div className="flex items-center gap-1.5 min-w-0">
              <span className="w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: seg.color }} />
              <span className="text-slate-300 truncate">{seg.label}</span>
            </div>
            <div className="flex items-center gap-1 font-mono text-[11px] shrink-0 ml-1">
              <span className="text-slate-100 font-semibold">{seg.count}</span>
              <span className="text-slate-500 text-[10px]">({seg.pct}%)</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
