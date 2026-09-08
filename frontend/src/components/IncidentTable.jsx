import { Link, useNavigate } from 'react-router-dom'
import SeverityBadge from './SeverityBadge'
import { IconShield } from './Icons'
import { resolveMitreTechnique, openMitreUrl } from '../utils/mitre'

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

  // Sort critical first, then by risk score descending
  const sorted = [...incidents].sort((a, b) => {
    if (a.severity === 'critical' && b.severity !== 'critical') return -1
    if (b.severity === 'critical' && a.severity !== 'critical') return 1
    return (b.risk_score || 0) - (a.risk_score || 0)
  })

  return (
    <div className="glass-card overflow-hidden">
      {/* Table header bar */}
      <div className="px-5 py-4 border-b border-white/5 flex items-center justify-between">
        <div>
          <h2 className="text-sm font-semibold text-slate-200 uppercase tracking-wider">Active Incidents</h2>
          <p className="text-xs text-slate-500 mt-0.5">Correlated security threats requiring analyst response</p>
        </div>
        <span className="text-xs font-mono px-2.5 py-1 rounded-full bg-surface-700 text-slate-400 border border-white/5">
          {incidents.length} total
        </span>
      </div>

      {/* Responsive table wrapper */}
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
              <th className="px-4 py-3 text-right text-xs font-medium text-slate-400 uppercase tracking-wider">Action</th>
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
                    group cursor-pointer
                  `}
                >
                  <td className="px-4 py-3.5">
                    <SeverityBadge severity={inc.severity} />
                  </td>
                  <td className="px-4 py-3.5">
                    <Link
                      to={`/incident/${inc.incident_id}`}
                      onClick={(e) => e.stopPropagation()}
                      className="font-mono text-cyan-400 hover:text-cyan-300 text-xs font-semibold hover:underline flex items-center gap-1"
                      title="Open full Incident Dossier"
                    >
                      <span>{inc.incident_id}</span>
                    </Link>
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
                        const m = resolveMitreTechnique(t, idx)
                        return (
                          <a
                            key={m.id + '-' + idx}
                            href={m.url}
                            target="_blank"
                            rel="noopener noreferrer"
                            onClick={(e) => openMitreUrl(m.url, e)}
                            title={`Open official MITRE definition for ${m.displayId} (${m.name}): ${m.url}`}
                            className="mitre-tag hover:bg-indigo-900/70 hover:text-indigo-200 transition-colors flex items-center gap-0.5 cursor-pointer"
                          >
                            <span>{m.displayId}</span>
                            <span className="text-[9px] opacity-70">↗</span>
                          </a>
                        )
                      })}
                      {inc.mitre_techniques?.length > 2 && (
                        <span className="mitre-tag">+{inc.mitre_techniques.length - 2}</span>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-3.5 text-right">
                    <Link
                      to={`/incident/${inc.incident_id}`}
                      onClick={(e) => e.stopPropagation()}
                      className="px-2.5 py-1 rounded text-xs font-semibold bg-cyan-950/70 hover:bg-cyan-900/80 text-cyan-300 border border-cyan-500/30 hover:border-cyan-400 transition-colors inline-flex items-center gap-1 cursor-pointer"
                      title="Open Incident Details in full view"
                    >
                      <span>Investigate</span>
                      <span className="text-[10px]">↗</span>
                    </Link>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>

        {incidents.length === 0 && (
          <div className="py-16 text-center text-slate-500">
            <IconShield className="w-10 h-10 text-slate-600 mb-3 mx-auto" />
            <div>No incidents detected</div>
          </div>
        )}
      </div>
    </div>
  )
}
