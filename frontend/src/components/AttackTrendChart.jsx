import { useState, useMemo } from 'react'
import { IconBarChart } from './Icons'

/**
 * AttackTrendChart — Real-time Attack Velocity & Incident Flow Chart
 * Computes REAL dynamic timeline datapoints directly from live incidents & telemetry.
 * When 0 incidents exist, displays flat baseline (0 threats, Baseline Clean).
 * When incidents occur, plots the actual incident volume & risk progression over time.
 */

export default function AttackTrendChart({ incidents = [], streamedEvents = [] }) {
  const [metric, setMetric] = useState('volume') // 'volume' | 'risk'

  // Generate 8 actual time bucket labels based on current time (e.g. T-7h, T-6h, ..., Now)
  const { points, velocityStr, threatStatus, threatColor, totalInWindow } = useMemo(() => {
    const now = new Date()
    const buckets = []
    const numBuckets = 8

    // Generate bucket timestamps in 1-hour or 2-hour increments
    for (let i = numBuckets - 1; i >= 0; i--) {
      const d = new Date(now.getTime() - i * 60 * 60 * 1000)
      const hours = d.getHours().toString().padStart(2, '0')
      const minutes = '00'
      const label = i === 0 ? 'Now' : `${hours}:${minutes}`
      buckets.push({
        label,
        timestamp: d.getTime(),
        val: 0,
        anomaly: 0,
      })
    }

    // Combine all live timestamps from incidents and streamed events
    const allTelemetry = [
      ...incidents.map(i => ({
        timestamp: new Date(i.created_at || i.timestamp || Date.now()).getTime(),
        risk: (typeof i.risk_score === 'number' ? i.risk_score : 0.8) * (i.risk_score <= 1 ? 100 : 1),
        isIncident: true,
      })),
      ...streamedEvents.map(e => ({
        timestamp: new Date(e.timestamp || Date.now()).getTime(),
        risk: (e.risk_score || 0.5) * (e.risk_score <= 1 ? 100 : 1),
        isIncident: false,
      }))
    ]

    // Bucket width: 1 hour in ms
    const bucketWidthMs = 60 * 60 * 1000

    // Assign events to buckets
    allTelemetry.forEach(item => {
      const diff = now.getTime() - item.timestamp
      if (diff >= 0 && diff <= numBuckets * bucketWidthMs) {
        const bucketIndex = numBuckets - 1 - Math.min(numBuckets - 1, Math.floor(diff / bucketWidthMs))
        if (bucketIndex >= 0 && bucketIndex < numBuckets) {
          if (item.isIncident) {
            buckets[bucketIndex].val += 1
          }
          buckets[bucketIndex].anomaly = Math.max(buckets[bucketIndex].anomaly, Math.round(item.risk))
        }
      } else {
        // If timestamp is outside window, map to closest recent bucket
        buckets[numBuckets - 1].val += item.isIncident ? 1 : 0
        buckets[numBuckets - 1].anomaly = Math.max(buckets[numBuckets - 1].anomaly, Math.round(item.risk))
      }
    })

    const criticalCount = incidents.filter(i => i.severity === 'critical').length
    const highCount = incidents.filter(i => i.severity === 'high').length
    const totalInc = incidents.length

    let status = 'Baseline Clean'
    let color = 'text-emerald-400'
    let vel = '0 / hr'

    if (totalInc === 0) {
      status = 'Baseline Clean'
      color = 'text-emerald-400'
      vel = '0 / hr'
    } else if (criticalCount > 0) {
      status = `${criticalCount} Critical Active`
      color = 'text-red-400 animate-pulse'
      vel = `+${totalInc} / window`
    } else if (highCount > 0) {
      status = 'Elevated Risk'
      color = 'text-amber-400'
      vel = `+${totalInc} / window`
    } else {
      status = 'Guard Active'
      color = 'text-cyan-400'
      vel = `+${totalInc} / window`
    }

    return {
      points: buckets,
      velocityStr: vel,
      threatStatus: status,
      threatColor: color,
      totalInWindow: allTelemetry.length,
    }
  }, [incidents, streamedEvents])

  const maxVal = Math.max(1, ...points.map(p => metric === 'volume' ? p.val : p.anomaly))
  const width = 500
  const height = 110

  // Generate SVG path for smooth area chart
  const pathCoords = points.map((p, idx) => {
    const v = metric === 'volume' ? p.val : p.anomaly
    const x = (idx / (points.length - 1)) * (width - 20) + 10
    // If maxVal is 1 and all values are 0, flat at bottom
    const y = v === 0 ? height - 12 : height - (v / maxVal) * (height - 28) - 12
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
          <IconBarChart className="w-4 h-4 text-cyan-400" />
          <div>
            <h3 className="text-sm font-semibold text-slate-200">Attack Velocity & Flow</h3>
            <p className="text-xs text-slate-500">Live threat progression & anomaly timeline</p>
          </div>
        </div>

        <div className="flex items-center gap-1 bg-surface-800 p-0.5 rounded-lg border border-white/5 text-xs">
          <button
            onClick={() => setMetric('volume')}
            className={`px-2.5 py-1 rounded transition-colors cursor-pointer ${
              metric === 'volume' ? 'bg-cyan-500/20 text-cyan-300 font-medium' : 'text-slate-400 hover:text-white'
            }`}
          >
            Incident Volume
          </button>
          <button
            onClick={() => setMetric('risk')}
            className={`px-2.5 py-1 rounded transition-colors cursor-pointer ${
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
          {pathCoords.map((pt, idx) => {
            const val = metric === 'volume' ? pt.val : pt.anomaly
            const hasData = val > 0
            return (
              <g key={pt.label}>
                <circle
                  cx={pt.x}
                  cy={pt.y}
                  r={hasData ? '4' : '2'}
                  fill={hasData ? (metric === 'volume' ? '#22d3ee' : '#ef4444') : '#1e293b'}
                  stroke={hasData ? '#ffffff' : 'rgba(255,255,255,0.1)'}
                  strokeWidth="1.5"
                  className={hasData ? 'animate-pulse' : ''}
                />
              </g>
            )
          })}
        </svg>

        {/* X-axis timeline labels */}
        <div className="flex items-center justify-between text-[11px] text-slate-500 font-mono mt-1 px-1">
          {points.map(p => (
            <span key={p.label}>{p.label}</span>
          ))}
        </div>
      </div>

      {/* Mini footer metrics */}
      <div className="grid grid-cols-3 gap-2 pt-2 border-t border-white/5 text-center">
        <div className="p-1.5 rounded bg-surface-800/30">
          <div className="text-[10px] text-slate-500 uppercase font-medium">Velocity</div>
          <div className="text-xs font-bold font-mono text-cyan-400">{velocityStr}</div>
        </div>
        <div className="p-1.5 rounded bg-surface-800/30">
          <div className="text-[10px] text-slate-500 uppercase font-medium">Telemetry Stream</div>
          <div className="text-xs font-bold font-mono text-slate-200">{totalInWindow} Events</div>
        </div>
        <div className="p-1.5 rounded bg-surface-800/30">
          <div className="text-[10px] text-slate-500 uppercase font-medium">Threat Status</div>
          <div className={`text-xs font-bold font-mono ${threatColor}`}>{threatStatus}</div>
        </div>
      </div>
    </div>
  )
}
