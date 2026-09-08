import { useNavigate } from 'react-router-dom'
import SeverityBadge from './SeverityBadge'

/**
 * IncidentTable — sortable incident list for SOC Overview
 */

function RiskBar({ score }) {
  const pct = Math.round(score * 100)
  const color =
    score >= 0.8 ? 'from-red-600 to-red-400' :
    score >= 0.6 ? 'from-orange-600 to-orange-400' :
    score >= 0.4 ? 'from-yellow-600 to-yellow-400' :
                   'from-slate-600 to-slate-400'

  return (
    <div className="flex items-center gap-2 min-w-[90px]">
      <div className="risk-bar-track flex-1">
        <div
          className={`risk-bar-fill bg-gradient-to-r ${color}`}
          style={{ width: `${pct}%` }}
        />
      </div>
      <span className="text-xs font-mono text-slate-300 w-8 text-right">{pct}</span>
    </div>
  )
}

function formatTime(iso) {
  const d = new Date(iso)
  return d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false })
}

function formatDate(iso) {
  const d = new Date(iso)
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' })
}

export default function IncidentTable({ incidents = [], newIds = new Set() }) {
  const navigate = useNavigate()

  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 }
  const sorted = [...incidents].sort(
    (a, b) => (severityOrder[a.severity] ?? 3) - (severityOrder[b.severity] ?? 3) || (b.risk_score || 0) - (a.risk_score || 0)
  )

  return (
    <div className="glass-card overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-white/5">
              <th className="px-4 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Severity</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Incident ID</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Host</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">User</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Risk Score</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Time</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">MITRE</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/5">
            {sorted.map((inc) => {
              const isNew = newIds.has(inc.incident_id)
              const isCritical = inc.severity === 'critical'

              return (
                <tr
                  key={inc.incident_id}
                  onClick={() => navigate(`/incident/${inc.incident_id}`)}
                  className={`
                    table-row-hover
                    ${isNew ? 'slide-in-new' : ''}
                    ${isCritical ? 'bg-red-950/10' : ''}
                    group
                  `}
                >
                  <td className="px-4 py-3.5">
                    <SeverityBadge severity={inc.severity} />
                  </td>
                  <td className="px-4 py-3.5">
                    <span className="font-mono text-cyan-400 text-xs group-hover:text-cyan-300 transition-colors">
                      {inc.incident_id}
                    </span>
                  </td>
                  <td className="px-4 py-3.5">
                    <span className="text-slate-200 font-medium">{inc.host}</span>
                  </td>
                  <td className="px-4 py-3.5">
                    <span className="text-slate-400">{inc.user}</span>
                  </td>
                  <td className="px-4 py-3.5">
                    <RiskBar score={inc.risk_score} />
                  </td>
                  <td className="px-4 py-3.5">
                    <div className="flex flex-col">
                      <span className="text-slate-200 font-mono text-xs">{formatTime(inc.created_at)}</span>
                      <span className="text-slate-500 text-xs">{formatDate(inc.created_at)}</span>
                    </div>
                  </td>
                  <td className="px-4 py-3.5">
                    <div className="flex flex-wrap gap-1">
                      {inc.mitre_techniques?.slice(0, 2).map((t, idx) => {
                        const code = typeof t === 'string' ? t : (t?.mitre_id || t?.technique || `T-${idx}`)
                        return (
                          <span key={code} className="mitre-tag">{code}</span>
                        )
                      })}
                      {inc.mitre_techniques?.length > 2 && (
                        <span className="mitre-tag">+{inc.mitre_techniques.length - 2}</span>
                      )}
                    </div>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>

        {incidents.length === 0 && (
          <div className="py-16 text-center text-slate-500">
            <div className="text-4xl mb-3">🔍</div>
            <div>No incidents detected</div>
          </div>
        )}
      </div>
    </div>
  )
}
