import { useEffect, useRef } from 'react'
import SeverityBadge from './SeverityBadge'

/**
 * LiveFeedPanel — Real-Time Telemetry Stream Console.
 * High-density event rows with monospace timestamps, host, user, and SVG category indicators.
 */

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

// Minimal monochrome SVG icons for telemetry types
function EventTypeIcon({ type }) {
  const t = (type || '').toLowerCase()
  const iconClass = 'w-3.5 h-3.5 text-slate-400 shrink-0'

  if (t.includes('auth') || t.includes('login') || t.includes('fail')) {
    // Key / Lock SVG
    return (
      <svg className={iconClass} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
        <path d="M7 11V7a5 5 0 0 1 10 0v4" />
      </svg>
    )
  }
  if (t.includes('privilege') || t.includes('escalat')) {
    // Chevron Up / Shield SVG
    return (
      <svg className={iconClass} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <polyline points="17 11 12 6 7 11" />
        <polyline points="17 18 12 13 7 18" />
      </svg>
    )
  }
  if (t.includes('exfiltrat') || t.includes('transfer') || t.includes('upload')) {
    // Data exfiltration / Upload SVG
    return (
      <svg className={iconClass} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
        <polyline points="17 8 12 3 7 8" />
        <line x1="12" y1="3" x2="12" y2="15" />
      </svg>
    )
  }
  if (t.includes('credential') || t.includes('dump') || t.includes('lsass')) {
    // Disk / memory dump SVG
    return (
      <svg className={iconClass} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <rect x="4" y="4" width="16" height="16" rx="2" />
        <rect x="9" y="4" width="6" height="6" />
        <line x1="9" y1="20" x2="15" y2="20" />
      </svg>
    )
  }
  if (t.includes('network') || t.includes('c2') || t.includes('flow')) {
    // Network / Globe SVG
    return (
      <svg className={iconClass} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <circle cx="12" cy="12" r="10" />
        <line x1="2" y1="12" x2="22" y2="12" />
        <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
      </svg>
    )
  }
  if (t.includes('normal')) {
    // Check SVG (green baseline)
    return (
      <svg className="w-3.5 h-3.5 text-emerald-400 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <polyline points="20 6 9 17 4 12" />
      </svg>
    )
  }

  // Generic Anomaly Alert Triangle SVG
  return (
    <svg className={iconClass} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
      <line x1="12" y1="9" x2="12" y2="13" />
      <line x1="12" y1="17" x2="12.01" y2="17" />
    </svg>
  )
}

export default function LiveFeedPanel({ incidents = [], streamedEvents = [], wsStatus = 'disconnected' }) {
  const scrollRef = useRef(null)
  const prevCountRef = useRef(0)

  // Extract events from incidents
  const incidentEvents = incidents.flatMap(inc =>
    (inc.correlated_events || []).map(ev => ({
      ...ev,
      incident_id: inc.incident_id,
      host: ev.host || inc.host,
      user: ev.user || inc.user,
      severity: ev.severity || inc.severity,
    }))
  )

  // Merge and deduplicate by event_id
  const seenIds = new Set()
  const allEvents = [...streamedEvents, ...incidentEvents].filter(ev => {
    if (!ev.event_id) return true
    if (seenIds.has(ev.event_id)) return false
    seenIds.add(ev.event_id)
    return true
  })

  const events = allEvents
    .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
    .slice(0, 60)

  // Auto-scroll to top when new events arrive
  useEffect(() => {
    if (events.length > prevCountRef.current && scrollRef.current) {
      scrollRef.current.scrollTo({ top: 0, behavior: 'smooth' })
    }
    prevCountRef.current = events.length
  }, [events.length])

  return (
    <div className="soc-panel flex flex-col h-full overflow-hidden">
      {/* Console Header */}
      <div className="flex items-center justify-between px-3 py-2 border-b border-slate-800 bg-slate-900/90 shrink-0">
        <div className="flex items-center gap-2">
          <span
            className={`w-2 h-2 rounded-full ${
              wsStatus === 'connected'
                ? 'bg-emerald-400'
                : wsStatus === 'connecting'
                ? 'bg-amber-400 animate-pulse'
                : 'bg-slate-600'
            }`}
          />
          <h3 className="text-xs font-semibold text-slate-200 uppercase tracking-wider">
            Live Telemetry Console
          </h3>
        </div>
        <div className="flex items-center gap-2 font-mono text-[10px]">
          <span className="text-slate-400">{events.length} streamed</span>
          <span
            className={`px-1.5 py-0.5 rounded border uppercase font-semibold ${
              wsStatus === 'connected'
                ? 'text-emerald-400 bg-emerald-950/40 border-emerald-500/30'
                : 'text-slate-500 bg-slate-900 border-slate-800'
            }`}
          >
            {wsStatus === 'connected' ? 'STREAMING' : wsStatus}
          </span>
        </div>
      </div>

      {/* Stream List */}
      <div
        ref={scrollRef}
        className="flex-1 overflow-y-auto divide-y divide-slate-850"
        style={{ minHeight: 0 }}
      >
        {events.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-40 text-slate-500 text-xs font-mono">
            <svg
              className="w-6 h-6 text-slate-600 mb-2"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.5"
            >
              <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
            </svg>
            <span>Waiting for incoming stream…</span>
          </div>
        ) : (
          events.map((ev, idx) => {
            const isNew = idx === 0
            const sev = ev.severity || 'low'
            const formattedType = (ev.type || 'anomaly_detected').toUpperCase().replace(/_/g, ' ')

            return (
              <div
                key={ev.event_id || `evt-${idx}`}
                className={`
                  p-2.5 flex flex-col gap-1 text-xs transition-colors duration-100
                  ${isNew ? 'bg-slate-850/70' : 'hover:bg-slate-850/40'}
                  ${sev === 'critical' ? 'border-l-2 border-red-500 bg-red-950/10' : ''}
                `}
              >
                {/* Top Row: Timestamp, Type, Severity */}
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-1.5 min-w-0">
                    <EventTypeIcon type={ev.type} />
                    <span className="font-mono text-[11px] text-slate-400 whitespace-nowrap">
                      {formatTime(ev.timestamp)}
                    </span>
                    <span className="font-mono text-[11px] font-semibold text-slate-200 truncate uppercase">
                      {formattedType}
                    </span>
                  </div>
                  <SeverityBadge severity={sev} />
                </div>

                {/* Second Row: Host, User, Anomaly Score */}
                <div className="flex items-center justify-between text-[11px] text-slate-400 font-mono mt-0.5">
                  <div className="flex items-center gap-2 truncate">
                    <span className="text-slate-300 truncate" title={ev.host}>
                      {ev.host || 'unknown-host'}
                    </span>
                    <span className="text-slate-600">•</span>
                    <span className="text-slate-400 truncate" title={ev.user}>
                      {ev.user || 'system'}
                    </span>
                  </div>
                  {ev.anomaly_score != null && (
                    <span className="text-slate-500 shrink-0 ml-2">
                      score:{' '}
                      <span className="text-slate-300">
                        {Math.round((ev.anomaly_score > 1 ? ev.anomaly_score : ev.anomaly_score * 100))}
                      </span>
                    </span>
                  )}
                </div>

                {/* Detail snippet if present */}
                {ev.detail && ev.detail !== ev.type && (
                  <div className="text-[11px] text-slate-400 truncate mt-0.5 font-sans">
                    {ev.detail}
                  </div>
                )}
              </div>
            )
          })
        )}
      </div>
    </div>
  )
}
