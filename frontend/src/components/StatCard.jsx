/**
 * StatCard — glassmorphism summary stat card for SOC Overview
 */

export default function StatCard({ label, value, sub, icon, accentColor = 'cyber', highlight = false }) {
  const accentMap = {
    cyber: { text: 'text-cyan-400', border: 'border-cyan-500/20', glow: 'hover:border-cyan-500/40 hover:shadow-cyan-500/10' },
    red:   { text: 'text-red-400',  border: 'border-red-500/20',  glow: 'hover:border-red-500/40 hover:shadow-red-500/10'  },
    orange:{ text: 'text-orange-400',border: 'border-orange-500/20',glow:'hover:border-orange-500/40 hover:shadow-orange-500/10'},
    green: { text: 'text-green-400', border: 'border-green-500/20',glow: 'hover:border-green-500/40 hover:shadow-green-500/10'},
  }

  const colors = accentMap[accentColor] || accentMap.cyber

  return (
    <div
      className={`
        glass-card p-5 flex flex-col gap-3
        border ${colors.border} ${colors.glow}
        transition-all duration-200 hover:shadow-lg hover:-translate-y-0.5
        ${highlight ? 'ring-1 ring-red-500/30' : ''}
      `}
    >
      <div className="flex items-start justify-between">
        <span className="text-xs font-semibold text-slate-300 uppercase tracking-wider font-mono">{label}</span>
        {icon && (
          <div className={`p-1.5 rounded-lg bg-surface-800 border border-white/10 ${colors.text} flex items-center justify-center`}>
            {icon}
          </div>
        )}
      </div>

      <div className="flex items-end gap-2">
        <span className={`text-3xl font-bold ${colors.text} font-mono leading-none`}>
          {value}
        </span>
        {sub && (
          <span className="text-xs text-slate-500 mb-0.5">{sub}</span>
        )}
      </div>

      {highlight && (
        <div className="h-0.5 w-full rounded-full bg-red-500/30">
          <div className="h-full w-2/3 rounded-full bg-red-500 animate-pulse" />
        </div>
      )}
    </div>
  )
}
