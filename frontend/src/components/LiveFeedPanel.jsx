import { useEffect, useRef } from 'react'

/**
 * LiveFeedPanel — auto-scrolling real-time event feed
 * Shows recent correlated events from all incidents, newest first.
 */

function formatRelative(iso) {
  const diff = Date.now() - new Date(iso).getTime()
  const s = Math.floor(diff / 1000)
  if (s < 60) return `${s}s ago`
  const m = Math.floor(s / 60)
  if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60)
  return `${h}h ago`
}

const EVENT_TYPE_ICONS = {
  auth_failure:         '🔑',
  failed_login:         '🔑',
  lateral_movement:     '↔️',
  privilege_escalation: '⬆️',
  data_exfiltration:    '📤',
  command_and_control:  '📡',
  suspicious_process:   '⚙️',
  new_process:          '⚙️',
  account_creation:     '👤',
  persistence:          '🔒',
  network_anomaly:      '🌐',
  connection_attempt:   '🔌',
  packet_drop:          '🛑',
  suspicious_flow:      '🌊',
  app_log:              '📝',
  credential_dump:      '💾',
  ransomware_indicator: '🚨',
  file_discovery:       '📂',
  data_collection:      '📦',
  anomaly_detected:     '⚠️',
}

export default function LiveFeedPanel({ incidents = [], streamedEvents = [], wsStatus = 'disconnected' }) {
  const scrollRef = useRef(null)
  const prevCountRef = useRef(0)

  // Flatten all correlated events from incidents, attach parent incident info
  const incidentEvents = incidents
    .flatMap(inc =>
      inc.correlated_events?.map(ev => ({
        ...ev,
        incident_id: inc.incident_id,
        host: inc.host,
        severity: inc.severity,
      })) || []
    )

  // Merge streamed real-time events with incident events, deduplicating by event_id
  const seenIds = new Set()
  const allEvents = [...streamedEvents, ...incidentEvents].filter(ev => {
    if (!ev.event_id) return true
    if (seenIds.has(ev.event_id)) return false
    seenIds.add(ev.event_id)
    return true
  })

  const events = allEvents
    .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
    .slice(0, 50)

  // Auto-scroll to top when new events arrive
  useEffect(() => {
    if (events.length > prevCountRef.current && scrollRef.current) {
      scrollRef.current.scrollTo({ top: 0, behavior: 'smooth' })
    }
    prevCountRef.current = events.length
  }, [events.length])

  const statusColors = {
    connected:    'bg-green-400',
    connecting:   'bg-yellow-400',
    disconnected: 'bg-slate-500',
    error:        'bg-red-500',
  }

  return (
    <div className="glass-card flex flex-col h-full">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-white/5 flex-shrink-0">
        <div className="flex items-center gap-2">
          <span className={`w-2 h-2 rounded-full ${statusColors[wsStatus] || 'bg-slate-500'} animate-pulse`} />
          <h3 className="text-sm font-semibold text-slate-200">Live Event Feed</h3>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs text-slate-500">{events.length} events</span>
          <span className={`text-xs px-1.5 py-0.5 rounded ${
            wsStatus === 'connected' ? 'text-green-400 bg-green-400/10' : 'text-slate-500 bg-slate-500/10'
          }`}>
            {wsStatus === 'connected' ? 'LIVE' : wsStatus.toUpperCase()}
          </span>
        </div>
      </div>

      {/* Scrollable feed */}
      <div
        ref={scrollRef}
        className="flex-1 overflow-y-auto space-y-px"
        style={{ minHeight: 0 }}
      >
        {events.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-32 text-slate-600 text-sm">
            <span className="text-2xl mb-2">📡</span>
            Waiting for events…
          </div>
        ) : (
          events.map((ev, idx) => (
            <div
              key={ev.event_id}
              className={`
                px-3 py-2.5 flex gap-3 items-start
                border-l-2 transition-colors
                ${ev.severity === 'critical' ? 'border-red-500/50 bg-red-950/5' :
                  ev.severity === 'high'     ? 'border-orange-500/40 bg-orange-950/5' :
                  ev.severity === 'medium'   ? 'border-yellow-500/30' :
                                              'border-slate-700/30'}
                ${idx === 0 ? 'slide-in-new' : ''}
              `}
            >
              <span className="text-base flex-shrink-0 mt-0.5">
                {EVENT_TYPE_ICONS[ev.type] || '⚠️'}
              </span>

              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-0.5 flex-wrap">
                  <span className="text-xs font-mono text-cyan-500">{ev.incident_id}</span>
                  <span className="text-xs text-slate-400 truncate">{ev.host}</span>
                  <span className="text-xs text-slate-600 ml-auto flex-shrink-0">{formatRelative(ev.timestamp)}</span>
                </div>
                <p className="text-xs text-slate-300 leading-relaxed line-clamp-2">{ev.detail}</p>
                <div className="flex items-center gap-2 mt-1">
                  <span className="text-xs text-slate-600">{ev.type.replace(/_/g, ' ')}</span>
                  {ev.anomaly_score != null && (
                    <span className="text-xs text-slate-600">
                      anomaly: <span className="text-slate-400 font-mono">{(ev.anomaly_score * 100).toFixed(0)}</span>
                    </span>
                  )}
                </div>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  )
}
