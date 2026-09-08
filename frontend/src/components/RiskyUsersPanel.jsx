import { useState, useEffect, useMemo } from 'react'
import { getRiskyUsers, revokeUser } from '../api/incidents'
import { IconUser, IconLock, IconCheckCircle } from './Icons'

function Sparkline({ points = [], color = '#ef4444' }) {
  if (!points || points.length < 2) return null
  const min = Math.min(...points)
  const max = Math.max(...points)
  const range = max - min || 1
  const width = 64
  const height = 20

  const coords = points.map((val, idx) => {
    const x = (idx / (points.length - 1)) * width
    const y = height - ((val - min) / range) * (height - 4) - 2
    return `${x.toFixed(1)},${y.toFixed(1)}`
  }).join(' ')

  return (
    <svg width={width} height={height} className="overflow-visible flex-shrink-0">
      <polyline
        fill="none"
        stroke={color}
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
        points={coords}
      />
    </svg>
  )
}

export default function RiskyUsersPanel({ incidents = [], streamedEvents = [] }) {
  const [apiUsers, setApiUsers] = useState([])
  const [loading, setLoading] = useState(true)
  const [revokedUsers, setRevokedUsers] = useState(new Set())
  const [actionLoading, setActionLoading] = useState({})

  useEffect(() => {
    let mounted = true
    getRiskyUsers()
      .then(data => {
        if (mounted) {
          setApiUsers(data || [])
          setLoading(false)
        }
      })
      .catch(() => {
        if (mounted) setLoading(false)
      })
    return () => { mounted = false }
  }, [incidents.length, streamedEvents.length])

  // Merge API users with real-time incidents
  const users = useMemo(() => {
    const userMap = new Map()

    // 1. Add any users from API
    for (const u of apiUsers) {
      if (u && u.user) userMap.set(u.user, { ...u })
    }

    // 2. Add/update users from real live incidents
    for (const inc of incidents) {
      const username = inc.user || inc.user_id
      if (!username || username === 'unknown' || username === 'system') continue

      const risk100 = typeof inc.risk_score === 'number'
        ? (inc.risk_score <= 1.0 ? Math.round(inc.risk_score * 100) : Math.round(inc.risk_score))
        : 50

      if (!userMap.has(username)) {
        userMap.set(username, {
          user: username,
          department: username === 'root' || username === 'admin' ? 'Privileged Identity' : 'Connected Endpoint Account',
          host: inc.host || 'friends-laptop',
          risk_score: risk100,
          anomalies_count: 1,
          severity: inc.severity || 'high',
          trend: [Math.max(20, risk100 - 30), Math.max(30, risk100 - 15), risk100],
          last_active: 'Just now',
        })
      } else {
        const item = userMap.get(username)
        item.anomalies_count = (item.anomalies_count || 0) + 1
        item.risk_score = Math.max(item.risk_score || 0, risk100)
        item.trend = item.trend || []
        item.trend.push(risk100)
        if (item.trend.length > 5) item.trend.shift()
        if (inc.host) item.host = inc.host
      }
    }

    return Array.from(userMap.values()).sort((a, b) => b.risk_score - a.risk_score)
  }, [apiUsers, incidents, streamedEvents])

  async function handleQuickRevoke(username) {
    if (revokedUsers.has(username) || actionLoading[username]) return
    setActionLoading(prev => ({ ...prev, [username]: true }))
    try {
      await revokeUser(username, 'Manual lock from UEBA Risky Users console')
      setRevokedUsers(prev => new Set(prev).add(username))
    } catch (err) {
      console.error(err)
    } finally {
      setActionLoading(prev => ({ ...prev, [username]: false }))
    }
  }

  return (
    <div className="glass-card p-5 flex flex-col h-full">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-white/5 pb-3 mb-3">
        <div className="flex items-center gap-2">
          <IconUser className="w-4 h-4 text-cyan-400" />
          <div>
            <h3 className="text-sm font-semibold text-slate-200">Risky Users</h3>
            <p className="text-xs text-slate-500">Identity & Entity Threat Scoring (UEBA)</p>
          </div>
        </div>
        <span className="text-xs font-mono text-cyan-400 bg-cyan-950/40 px-2 py-0.5 rounded border border-cyan-800/30">
          {users.length} Flagged
        </span>
      </div>

      {/* Users List */}
      <div className="flex-1 overflow-y-auto space-y-2 pr-1">
        {loading && users.length === 0 ? (
          <div className="flex items-center justify-center h-40 text-xs text-slate-500">
            Loading identity telemetry…
          </div>
        ) : users.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-48 text-center px-4">
            <div className="w-10 h-10 rounded-full bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 mb-2">
              <IconCheckCircle className="w-5 h-5" />
            </div>
            <p className="text-xs font-semibold text-slate-200">Zero Flagged Identities</p>
            <p className="text-[11px] text-slate-400 mt-0.5">All monitored accounts and connected endpoints are nominal.</p>
          </div>
        ) : (
          users.map(u => {
            const isRevoked = revokedUsers.has(u.user)
            const isActing = actionLoading[u.user]
            const sparkColor = u.risk_score >= 90 ? '#ef4444' : u.risk_score >= 70 ? '#f97316' : '#eab308'

            return (
              <div
                key={u.user}
                className="p-2.5 rounded-lg bg-surface-800/40 border border-white/5 hover:border-white/10 transition-colors flex items-center justify-between gap-3"
              >
                {/* Avatar + Info */}
                <div className="flex items-center gap-2.5 min-w-0 flex-1">
                  <div className="w-8 h-8 rounded-full bg-surface-700 flex items-center justify-center text-xs font-bold text-slate-300 flex-shrink-0 border border-white/10">
                    {u.user.slice(0, 2).toUpperCase()}
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-1.5">
                      <span className="text-xs font-medium text-slate-200 truncate font-mono">{u.user}</span>
                      {isRevoked && (
                        <span className="text-[10px] px-1 py-0.2 bg-red-950/80 text-red-400 border border-red-500/30 rounded font-bold">
                          LOCKED
                        </span>
                      )}
                    </div>
                    <div className="text-[11px] text-slate-500 truncate flex items-center gap-2">
                      <span>{u.department}</span>
                      <span>·</span>
                      <span className="font-mono text-cyan-400/70">{u.host}</span>
                    </div>
                  </div>
                </div>

                {/* Sparkline */}
                <div className="hidden sm:block">
                  <Sparkline points={u.trend} color={sparkColor} />
                </div>

                {/* Risk Score + Action */}
                <div className="flex items-center gap-2 flex-shrink-0">
                  <div className="text-right">
                    <div className={`text-sm font-bold font-mono ${
                      u.risk_score >= 80 ? 'text-red-400' : u.risk_score >= 60 ? 'text-orange-400' : 'text-yellow-400'
                    }`}>
                      {u.risk_score}
                    </div>
                    <div className="text-[10px] text-slate-500 uppercase tracking-tighter">RISK</div>
                  </div>

                  <button
                    disabled={isRevoked || isActing}
                    onClick={() => handleQuickRevoke(u.user)}
                    title={isRevoked ? 'Account Locked' : 'Revoke Session & Lock'}
                    className={`
                      px-2 py-1 text-[11px] font-medium rounded transition-all cursor-pointer
                      ${isRevoked
                        ? 'bg-slate-800 text-slate-500 cursor-default'
                        : isActing
                        ? 'bg-orange-950 text-orange-400 cursor-wait animate-pulse'
                        : 'bg-red-950/50 hover:bg-red-900/60 text-red-400 hover:text-red-200 border border-red-500/20 active:scale-95'
                      }
                    `}
                  >
                    {isRevoked ? 'Locked' : isActing ? 'Locking…' : 'Lock'}
                  </button>
                </div>
              </div>
            )
          })
        )}
      </div>

      <div className="border-t border-white/5 pt-2 mt-2 flex items-center justify-between text-[11px] text-slate-500">
        <span>Dynamic Real-Time UEBA</span>
        <span className="text-cyan-400 font-mono">Live Telemetry</span>
      </div>
    </div>
  )
}
