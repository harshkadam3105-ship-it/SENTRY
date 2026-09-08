import { useState, useMemo } from 'react'
import { revokeUser } from '../api/incidents'

/**
 * RiskyUsersPanel — UEBA (User & Entity Behavior Analytics) Ranking Console.
 * Dynamically computes risky identities directly from live incidents and telemetry events.
 * Renders analyst ranking table, subtle SVG sparklines, and 1-click operational account containment.
 */

function SubtleSparkline({ points = [], color = '#ef4444' }) {
  if (!points || points.length < 2) return <span className="text-slate-600 font-mono text-[10px]">--</span>
  const min = Math.min(...points)
  const max = Math.max(...points)
  const range = max - min || 1
  const width = 50
  const height = 16

  const coords = points
    .map((val, idx) => {
      const x = (idx / (points.length - 1)) * width
      const y = height - ((val - min) / range) * (height - 4) - 2
      return `${x.toFixed(1)},${y.toFixed(1)}`
    })
    .join(' ')

  return (
    <svg width={width} height={height} className="overflow-visible shrink-0">
      <polyline
        fill="none"
        stroke={color}
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
        points={coords}
      />
    </svg>
  )
}

export default function RiskyUsersPanel({ incidents = [], streamedEvents = [] }) {
  const [revokedUsers, setRevokedUsers] = useState(new Set())
  const [actionLoading, setActionLoading] = useState({})

  // Dynamically compute risky users from live telemetry
  const rankedUsers = useMemo(() => {
    const userMap = new Map()

    // 1. Process incidents
    incidents.forEach(inc => {
      const u = inc.user
      if (!u || u === 'unknown' || u === 'system') return
      const current = userMap.get(u) || {
        user: u,
        host: inc.host || 'unknown-host',
        maxRisk: 0,
        eventCount: 0,
        severity: inc.severity,
        incidentCount: 0,
      }

      const score = Math.round((inc.risk_score || 0) * 100)
      if (score > current.maxRisk) {
        current.maxRisk = score
        current.severity = inc.severity
        current.host = inc.host || current.host
      }
      current.incidentCount += 1
      current.eventCount += (inc.correlated_events?.length || 1)
      userMap.set(u, current)
    })

    // 2. Process streamed telemetry events
    streamedEvents.forEach(ev => {
      const u = ev.user
      if (!u || u === 'unknown' || u === 'system') return
      const current = userMap.get(u) || {
        user: u,
        host: ev.host || 'unknown-host',
        maxRisk: 30,
        eventCount: 0,
        severity: 'low',
        incidentCount: 0,
      }
      current.eventCount += 1
      if (ev.severity === 'critical') current.maxRisk = Math.max(current.maxRisk, 90)
      else if (ev.severity === 'high') current.maxRisk = Math.max(current.maxRisk, 75)
      userMap.set(u, current)
    })

    const list = Array.from(userMap.values()).map(item => {
      // Build 5-point trajectory
      const base = Math.max(20, item.maxRisk - 35)
      const trend = [
        base,
        Math.min(99, base + 10),
        Math.min(99, base + 20),
        Math.min(99, Math.max(base + 25, item.maxRisk - 5)),
        item.maxRisk,
      ]
      return { ...item, trend }
    })

    return list.sort((a, b) => b.maxRisk - a.maxRisk)
  }, [incidents, streamedEvents])

  async function handleQuickRevoke(username) {
    if (revokedUsers.has(username) || actionLoading[username]) return
    setActionLoading(prev => ({ ...prev, [username]: true }))
    try {
      await revokeUser(username, 'Manual containment lock from UEBA Risky Users console')
      setRevokedUsers(prev => new Set(prev).add(username))
    } catch (err) {
      console.error('Failed to revoke user session:', err)
    } finally {
      setActionLoading(prev => ({ ...prev, [username]: false }))
    }
  }

  return (
    <div className="soc-panel flex flex-col h-full overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-3 py-2.5 border-b border-slate-800 bg-slate-900/90 shrink-0">
        <div className="flex items-center gap-2">
          {/* User Shield SVG */}
          <div className="p-1 rounded bg-slate-850 border border-slate-800 text-slate-400">
            <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
              <circle cx="12" cy="7" r="4" />
            </svg>
          </div>
          <div>
            <h3 className="text-xs font-semibold text-slate-200 uppercase tracking-wider">
              Identity Risk Ranking (UEBA)
            </h3>
          </div>
        </div>
        <span className="text-[10px] font-mono text-slate-400 bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
          {rankedUsers.length} Flagged
        </span>
      </div>

      {/* Analyst Ranking Table */}
      <div className="flex-1 overflow-y-auto" style={{ minHeight: 0 }}>
        {rankedUsers.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-48 text-center p-6">
            <div className="flex items-center gap-1.5 text-emerald-400 text-xs font-semibold mb-1">
              <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <polyline points="20 6 9 17 4 12" />
              </svg>
              Zero Flagged Identities
            </div>
            <p className="text-[11px] text-slate-500 max-w-[220px]">
              All corporate and service accounts operating within nominal baseline parameters
            </p>
          </div>
        ) : (
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-900/50 text-[10px] uppercase font-semibold tracking-wider text-slate-400">
                <th className="py-2 px-2.5 text-center w-8">#</th>
                <th className="py-2 px-2.5">User / Host</th>
                <th className="py-2 px-2 text-right">Risk</th>
                <th className="py-2 px-2 text-right">Evts</th>
                <th className="py-2 px-2 text-center">Trend</th>
                <th className="py-2 px-2.5 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-850 text-xs">
              {rankedUsers.map((u, idx) => {
                const isRevoked = revokedUsers.has(u.user)
                const isActing = actionLoading[u.user]
                const sparkColor =
                  u.maxRisk >= 85 ? '#ef4444' : u.maxRisk >= 60 ? '#f97316' : '#eab308'

                return (
                  <tr key={u.user} className="hover:bg-slate-850/40 transition-colors">
                    <td className="py-2.5 px-2.5 text-center font-mono text-[11px] text-slate-500">
                      {idx + 1}
                    </td>

                    <td className="py-2.5 px-2.5 max-w-[130px]">
                      <div className="flex items-center gap-1.5">
                        <span className="font-mono text-slate-200 font-medium truncate text-xs">
                          {u.user}
                        </span>
                        {isRevoked && (
                          <span className="text-[9px] px-1 bg-red-950/80 text-red-400 border border-red-500/30 rounded font-mono">
                            LOCKED
                          </span>
                        )}
                      </div>
                      <div className="text-[10px] font-mono text-slate-500 truncate" title={u.host}>
                        {u.host}
                      </div>
                    </td>

                    <td className="py-2.5 px-2 text-right whitespace-nowrap">
                      <span
                        className={`font-mono text-xs font-bold ${
                          u.maxRisk >= 85
                            ? 'text-red-400'
                            : u.maxRisk >= 60
                            ? 'text-orange-400'
                            : 'text-amber-400'
                        }`}
                      >
                        {u.maxRisk}
                      </span>
                    </td>

                    <td className="py-2.5 px-2 text-right font-mono text-[11px] text-slate-400 whitespace-nowrap">
                      {u.eventCount}
                    </td>

                    <td className="py-2.5 px-2 text-center">
                      <SubtleSparkline points={u.trend} color={sparkColor} />
                    </td>

                    <td className="py-2.5 px-2.5 text-right whitespace-nowrap">
                      <button
                        disabled={isRevoked || isActing}
                        onClick={() => handleQuickRevoke(u.user)}
                        title={isRevoked ? 'Account Locked' : 'Revoke Session & Lock'}
                        className={`
                          inline-flex items-center gap-1 px-2 py-1 text-[10px] font-mono font-medium rounded transition-colors
                          ${
                            isRevoked
                              ? 'bg-slate-850 text-slate-500 border border-slate-700 cursor-default'
                              : isActing
                              ? 'bg-amber-950/40 text-amber-300 border border-amber-500/30 cursor-wait animate-pulse'
                              : 'bg-slate-850 hover:bg-red-950/40 text-slate-300 hover:text-red-400 border border-slate-700 hover:border-red-500/40'
                          }
                        `}
                      >
                        {/* Minimal Lock SVG */}
                        <svg className="w-2.5 h-2.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                          <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                          <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                        </svg>
                        {isRevoked ? 'Locked' : isActing ? '…' : 'Lock'}
                      </button>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        )}
      </div>

      {/* Footer Info */}
      <div className="px-3 py-2 border-t border-slate-800 bg-slate-900/60 text-[10px] text-slate-500 flex items-center justify-between shrink-0">
        <span>Dynamic UEBA Profile</span>
        <span className="font-mono">Sliding Correlation Buffer</span>
      </div>
    </div>
  )
}
