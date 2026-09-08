/**
 * StatCard — Compact, high-density KPI card for enterprise SOC analyst console.
 * Solid panel, subtle 1px border, monochrome SVG icon, restrained typography.
 */

export default function StatCard({
  label,
  value,
  sub,
  iconSvg,
  accentColor = 'neutral',
  highlight = false,
}) {
  // Restrained enterprise accent styles
  const accentClasses = {
    neutral: {
      text: 'text-slate-200',
      border: 'border-slate-800',
      indicator: 'bg-slate-500',
    },
    red: {
      text: 'text-red-400',
      border: highlight ? 'border-red-500/40 bg-red-950/15' : 'border-slate-800',
      indicator: 'bg-red-500',
    },
    orange: {
      text: 'text-orange-400',
      border: 'border-slate-800',
      indicator: 'bg-orange-500',
    },
    green: {
      text: 'text-emerald-400',
      border: 'border-slate-800',
      indicator: 'bg-emerald-500',
    },
    cyan: {
      text: 'text-slate-100',
      border: 'border-slate-800',
      indicator: 'bg-blue-500',
    },
  }

  const currentAccent = accentClasses[accentColor] || accentClasses.neutral

  return (
    <div
      className={`soc-panel p-3.5 flex flex-col justify-between transition-colors duration-150 ${currentAccent.border}`}
    >
      <div className="flex items-center justify-between gap-2 mb-2">
        <span className="text-[11px] font-semibold tracking-wider text-slate-400 uppercase">
          {label}
        </span>
        {iconSvg ? (
          <div className="text-slate-500 shrink-0">{iconSvg}</div>
        ) : (
          <span className={`w-1.5 h-1.5 rounded-full ${currentAccent.indicator}`} />
        )}
      </div>

      <div className="flex items-baseline justify-between gap-2">
        <span className={`text-2xl font-bold font-mono tracking-tight ${currentAccent.text}`}>
          {value}
        </span>
        {sub && (
          <span className="text-[11px] text-slate-500 truncate max-w-[120px]" title={sub}>
            {sub}
          </span>
        )}
      </div>
    </div>
  )
}
