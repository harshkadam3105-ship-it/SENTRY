import { useNavigate } from 'react-router-dom'
import SeverityBadge from './SeverityBadge'

/**
 * IncidentTable — High-density, professional SOC incident queue.
 * Prioritizes information density, monospace technical values, subtle severity accents,
 * and clean keyboard/mouse interaction states.
 */

function RiskBar({ score }) {
  const pct = Math.round((score || 0) * 100)
  const barColor =
    score >= 0.8
      ? 'bg-red-500'
      : score >= 0.6
      ? 'bg-orange-500'
      : score >= 0.4
      ? 'bg-amber-400'
      : 'bg-slate-500'

  return (
    <div className="flex items-center gap-2 min-w-[76px]">
      <div className="w-12 h-1.5 rounded bg-slate-800 overflow-hidden">
        <div className={`h-full ${barColor}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-[11px] font-mono text-slate-300 w-6 text-right font-medium">
        {pct}
      </span>
    </div>
  )
}

function formatTime(iso) {
  if (!iso) return '--:--:--'
  const d = new Date(iso)
  return d.toLocaleTimeString('en-US', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  })
}

function formatDate(iso) {
  if (!iso) return ''
  const d = new Date(iso)
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' })
}

function getStatusBadge(status) {
  const s = (status || 'open').toLowerCase()
  if (s === 'resolved') {
    return (
      <span className="px-1.5 py-0.5 text-[10px] font-mono uppercase rounded bg-slate-800 text-slate-400 border border-slate-700">
        Resolved
      </span>
    )
  }
  if (s === 'contained') {
    return (
      <span className="px-1.5 py-0.5 text-[10px] font-mono uppercase rounded bg-emerald-950/40 text-emerald-400 border border-emerald-500/30">
        Contained
      </span>
    )
  }
  if (s === 'investigating') {
    return (
      <span className="px-1.5 py-0.5 text-[10px] font-mono uppercase rounded bg-blue-950/40 text-blue-300 border border-blue-500/30">
        Investigating
      </span>
    )
  }
  return (
    <span className="px-1.5 py-0.5 text-[10px] font-mono uppercase rounded bg-amber-950/30 text-amber-400 border border-amber-500/30">
      Open
    </span>
  )
}

export default function IncidentTable({ incidents = [], newIds = new Set() }) {
  const navigate = useNavigate()

  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 }
  const sorted = [...incidents].sort(
    (a, b) =>
      (severityOrder[a.severity] ?? 3) - (severityOrder[b.severity] ?? 3) ||
      (b.risk_score || 0) - (a.risk_score || 0)
  )

  return (
    <div className="soc-panel overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="border-b border-slate-800 bg-slate-900/80 text-[10px] uppercase font-semibold tracking-wider text-slate-400">
              <th className="py-2.5 px-3">Severity</th>
              <th className="py-2.5 px-3">Incident ID</th>
              <th className="py-2.5 px-3">Threat Description</th>
              <th className="py-2.5 px-3">Host</th>
              <th className="py-2.5 px-3">User</th>
              <th className="py-2.5 px-3">Risk</th>
              <th className="py-2.5 px-3">MITRE</th>
              <th className="py-2.5 px-3">Timestamp</th>
              <th className="py-2.5 px-3 text-right">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-850/80 text-xs">
            {sorted.map(inc => {
              const isNew = newIds.has(inc.incident_id)
              const isCritical = inc.severity === 'critical'
              const isHigh = inc.severity === 'high'

              return (
                <tr
                  key={inc.incident_id}
                  onClick={() => navigate(`/incident/${inc.incident_id}`)}
                  className={`
                    cursor-pointer transition-colors duration-100 select-none
                    ${isNew ? 'flash-new-incident' : ''}
                    ${
                      isCritical
                        ? 'bg-red-950/15 hover:bg-red-950/30'
                        : isHigh
                        ? 'bg-orange-950/10 hover:bg-orange-950/20'
                        : 'hover:bg-slate-850/60'
                    }
                  `}
                >
                  <td className="py-2 px-3 whitespace-nowrap">
                    <SeverityBadge severity={inc.severity} />
                  </td>

                  <td className="py-2 px-3 whitespace-nowrap">
                    <span className="font-mono text-slate-200 text-xs font-semibold hover:text-white">
                      {inc.incident_id}
                    </span>
                  </td>

                  <td className="py-2 px-3 max-w-[260px] truncate text-slate-300 font-normal">
                    {inc.explanation || inc.title || 'Multi-stage correlation alert'}
                  </td>

                  <td className="py-2 px-3 whitespace-nowrap font-mono text-slate-300 text-[11px]">
                    {inc.host}
                  </td>

                  <td className="py-2 px-3 whitespace-nowrap font-mono text-slate-400 text-[11px]">
                    {inc.user}
                  </td>

                  <td className="py-2 px-3 whitespace-nowrap">
                    <RiskBar score={inc.risk_score} />
                  </td>

                  <td className="py-2 px-3 whitespace-nowrap">
                    <div className="flex items-center gap-1">
                      {(inc.mitre_techniques || []).slice(0, 2).map((t, idx) => {
                        const code =
                          typeof t === 'string'
                            ? t
                            : t?.mitre_id || t?.technique || `T-${idx}`
                        return (
                          <span key={code} className="mitre-tag">
                            {code}
                          </span>
                        )
                      })}
                      {(inc.mitre_techniques || []).length > 2 && (
                        <span className="text-[10px] text-slate-500 font-mono">
                          +{inc.mitre_techniques.length - 2}
                        </span>
                      )}
                    </div>
                  </td>

                  <td className="py-2 px-3 whitespace-nowrap">
                    <div className="flex items-center gap-1.5 font-mono text-[11px]">
                      <span className="text-slate-300">{formatTime(inc.created_at)}</span>
                      <span className="text-slate-500 text-[10px]">{formatDate(inc.created_at)}</span>
                    </div>
                  </td>

                  <td className="py-2 px-3 whitespace-nowrap text-right">
                    {getStatusBadge(inc.status)}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>

        {incidents.length === 0 && (
          <div className="py-14 text-center text-slate-500">
            <svg
              className="w-8 h-8 mx-auto text-slate-600 mb-2"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.5"
            >
              <circle cx="11" cy="11" r="8" />
              <line x1="21" y1="21" x2="16.65" y2="16.65" />
            </svg>
            <div className="text-xs font-semibold text-slate-400">No active incidents in queue</div>
            <div className="text-[11px] text-slate-600 mt-0.5">Correlation engine streaming live telemetry</div>
          </div>
        )}
      </div>
    </div>
  )
}
