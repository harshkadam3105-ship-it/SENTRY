import { useState } from 'react'

/**
 * AttackTrendChart — 24-Hour Threat Velocity & Incident Flow Chart
 * Inspired by Siemplify SOC dashboard and CISO anomaly trends:
 * Displays real-time attack wave dynamics and anomaly velocity using smooth SVG paths.
 */

export default function AttackTrendChart({ incidents = [] }) {
  const [metric, setMetric] = useState('volume') // 'volume' | 'risk'

  // Synthetic 24h datapoints based on incidents count
  const baseVolume = incidents.length || 7
  const points = [
    { time: '00:00', val: Math.round(baseVolume * 0.4), anomaly: 12 },
    { time: '04:00', val: Math.round(baseVolume * 0.3), anomaly: 8 },
    { time: '08:00', val: Math.round(baseVolume * 0.8), anomaly: 28 },
    { time: '11:00', val: Math.round(baseVolume * 1.4), anomaly: 65 },
    { time: '14:00', val: Math.round(baseVolume * 1.8), anomaly: 82 },
    { time: '17:00', val: Math.round(baseVolume * 1.5), anomaly: 54 },
    { time: '20:00', val: Math.round(baseVolume * 1.1), anomaly: 40 },
    { time: 'Now',   val: Math.round(baseVolume * 1.9), anomaly: 88 },
  ]

  const maxVal = Math.max(...points.map(p => metric === 'volume' ? p.val : p.anomaly)) || 10
  const width = 500
  const height = 110

  // Generate SVG path for smooth area chart
  const pathCoords = points.map((p, idx) => {
    const v = metric === 'volume' ? p.val : p.anomaly
    const x = (idx / (points.length - 1)) * (width - 20) + 10
    const y = height - (v / maxVal) * (height - 24) - 10
    return { x, y, ...p }
  })

  // Build SVG path string with cubic bezier curves
  const linePath = pathCoords.reduce((acc, pt, i, arr) => {
    if (i === 0) return `M ${pt.x},${pt.y}`
    const prev = arr[i - 1]
    const cx1 = (prev.x + pt.x) / 2
    const cy1 = prev.y
    const cx2 = (prev.x + pt.x) / 2
    const cy2 = pt.y
    return `${acc} C ${cx1},${cy1} ${cx2},${cy2} ${pt.x},${pt.y}`
  }, '')

  const areaPath = `${linePath} L ${pathCoords[pathCoords.length - 1].x},${height} L ${pathCoords[0].x},${height} Z`

  return (
    <div className="glass-card p-5 flex flex-col justify-between h-full">
      {/* Header with Switcher */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-white/5 pb-3">
        <div className="flex items-center gap-2">
          <span className="text-cyan-400 text-base">📈</span>
          <div>
            <h3 className="text-sm font-semibold text-slate-200">Attack Velocity & Flow</h3>
            <p className="text-xs text-slate-500">24-hour threat progression & anomaly spikes</p>
          </div>
        </div>

        <div className="flex items-center gap-1 bg-surface-800 p-0.5 rounded-lg border border-white/5 text-xs">
          <button
            onClick={() => setMetric('volume')}
            className={`px-2.5 py-1 rounded transition-colors ${
              metric === 'volume' ? 'bg-cyan-500/20 text-cyan-300 font-medium' : 'text-slate-400 hover:text-white'
            }`}
          >
            Incident Volume
          </button>
          <button
            onClick={() => setMetric('risk')}
            className={`px-2.5 py-1 rounded transition-colors ${
              metric === 'risk' ? 'bg-red-500/20 text-red-400 font-medium' : 'text-slate-400 hover:text-white'
            }`}
          >
            Anomaly Wave
          </button>
        </div>
      </div>

      {/* SVG Chart */}
      <div className="relative my-2">
        <svg viewBox={`0 0 ${width} ${height}`} className="w-full h-28 overflow-visible">
          <defs>
            <linearGradient id="areaGradient" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={metric === 'volume' ? '#06b6d4' : '#ef4444'} stopOpacity="0.35" />
              <stop offset="100%" stopColor={metric === 'volume' ? '#06b6d4' : '#ef4444'} stopOpacity="0.0" />
            </linearGradient>
            <linearGradient id="lineGradient" x1="0" y1="0" x2="1" y2="0">
              <stop offset="0%" stopColor="#3b82f6" />
              <stop offset="60%" stopColor={metric === 'volume' ? '#22d3ee' : '#f97316'} />
              <stop offset="100%" stopColor={metric === 'volume' ? '#06b6d4' : '#ef4444'} />
            </linearGradient>
          </defs>

          {/* Grid lines */}
          <line x1="10" y1="25" x2={width - 10} y2="25" stroke="rgba(255,255,255,0.05)" strokeDasharray="3 3" />
          <line x1="10" y1="65" x2={width - 10} y2="65" stroke="rgba(255,255,255,0.05)" strokeDasharray="3 3" />

          {/* Filled area */}
          <path d={areaPath} fill="url(#areaGradient)" />

          {/* Glowing stroke */}
          <path
            d={linePath}
            fill="none"
            stroke="url(#lineGradient)"
            strokeWidth="2.5"
            strokeLinecap="round"
          />

          {/* Datapoint nodes */}
          {pathCoords.map((pt, idx) => (
            <g key={pt.time}>
              <circle
                cx={pt.x}
                cy={pt.y}
                r={idx === pathCoords.length - 1 ? '4' : '2.5'}
                fill={idx === pathCoords.length - 1 ? '#22d3ee' : '#0d1117'}
                stroke={metric === 'volume' ? '#22d3ee' : '#ef4444'}
                strokeWidth="2"
                className={idx === pathCoords.length - 1 ? 'animate-pulse' : ''}
              />
            </g>
          ))}
        </svg>

        {/* X-axis timeline labels */}
        <div className="flex items-center justify-between text-[11px] text-slate-500 font-mono mt-1 px-1">
          {points.map(p => (
            <span key={p.time}>{p.time}</span>
          ))}
        </div>
      </div>

      {/* Mini footer metrics */}
      <div className="grid grid-cols-3 gap-2 pt-2 border-t border-white/5 text-center">
        <div className="p-1.5 rounded bg-surface-800/30">
          <div className="text-[10px] text-slate-500 uppercase">Velocity</div>
          <div className="text-xs font-bold font-mono text-cyan-400">+14% / hr</div>
        </div>
        <div className="p-1.5 rounded bg-surface-800/30">
          <div className="text-[10px] text-slate-500 uppercase">Sliding Window</div>
          <div className="text-xs font-bold font-mono text-slate-200">100 Events</div>
        </div>
        <div className="p-1.5 rounded bg-surface-800/30">
          <div className="text-[10px] text-slate-500 uppercase">Threat Status</div>
          <div className="text-xs font-bold font-mono text-red-400">High Active</div>
        </div>
      </div>
    </div>
  )
}
