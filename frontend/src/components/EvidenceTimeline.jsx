/**
 * EvidenceTimeline — Chronological Attack Sequence & Correlated Telemetry Timeline.
 * Professional DFIR layout with monospace timestamps, event IDs, and minimal iconography.
 */

function formatFull(iso) {
  if (!iso) return '--:--:--'
  const d = new Date(iso)
  return d.toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  })
}

// Minimal monochrome event icon helper
function TimelineIcon({ type }) {
  const t = (type || '').toLowerCase()
  const iconClass = 'w-3.5 h-3.5 text-slate-300'

  if (t.includes('auth') || t.includes('login') || t.includes('fail')) {
    return (
      <svg className={iconClass} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
        <path d="M7 11V7a5 5 0 0 1 10 0v4" />
      </svg>
    )
  }
  if (t.includes('privilege') || t.includes('escalat')) {
    return (
      <svg className={iconClass} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <polyline points="17 11 12 6 7 11" />
        <polyline points="17 18 12 13 7 18" />
      </svg>
    )
  }
  if (t.includes('exfiltrat') || t.includes('transfer')) {
    return (
      <svg className={iconClass} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
        <polyline points="17 8 12 3 7 8" />
        <line x1="12" y1="3" x2="12" y2="15" />
      </svg>
    )
  }
  if (t.includes('credential') || t.includes('dump') || t.includes('lsass')) {
    return (
      <svg className={iconClass} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <rect x="4" y="4" width="16" height="16" rx="2" />
        <rect x="9" y="4" width="6" height="6" />
        <line x1="9" y1="20" x2="15" y2="20" />
      </svg>
    )
  }
  if (t.includes('process')) {
    return (
      <svg className={iconClass} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <polyline points="4 17 10 11 4 5" />
        <line x1="12" y1="19" x2="20" y2="19" />
      </svg>
    )
  }

  return (
    <svg className={iconClass} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <circle cx="12" cy="12" r="10" />
      <line x1="12" y1="8" x2="12" y2="12" />
      <line x1="12" y1="16" x2="12.01" y2="16" />
    </svg>
  )
}

export default function EvidenceTimeline({ events = [] }) {
  const sorted = [...events].sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp))

  return (
    <div className="soc-panel p-5">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
        <div className="flex items-center gap-2">
          <div className="p-1 rounded bg-slate-850 border border-slate-800 text-slate-300">
            <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <line x1="12" y1="20" x2="12" y2="10" />
              <line x1="18" y1="20" x2="18" y2="4" />
              <line x1="6" y1="20" x2="6" y2="16" />
            </svg>
          </div>
          <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider">
            Forensic Evidence Chain
          </h3>
        </div>
        <span className="text-[11px] font-mono text-slate-400 bg-slate-900 border border-slate-800 px-2 py-0.5 rounded">
          {events.length} Correlated {events.length === 1 ? 'Event' : 'Events'}
        </span>
      </div>

      {/* Timeline List */}
      <div className="relative pl-6">
        {/* Subtle vertical spine line */}
        <div className="absolute left-2.5 top-2 bottom-2 w-px bg-slate-800" />

        <div className="space-y-4">
          {sorted.map((ev, idx) => {
            const isLast = idx === sorted.length - 1
            const formattedType = (ev.type || 'anomaly').toUpperCase().replace(/_/g, ' ')

            return (
              <div key={ev.event_id || `ev-${idx}`} className="relative flex items-start gap-3.5">
                {/* Timeline node */}
                <div
                  className={`
                    absolute -left-6 top-1 w-5 h-5 rounded-full flex items-center justify-center border
                    ${
                      isLast
                        ? 'bg-red-950 border-red-500/50 text-red-400'
                        : 'bg-slate-900 border-slate-700 text-slate-400'
                    }
                  `}
                >
                  <TimelineIcon type={ev.type} />
                </div>

                {/* Event Card */}
                <div
                  className={`
                    flex-1 p-3 rounded soc-panel-subtle border
                    ${
                      isLast
                        ? 'border-red-500/30 bg-red-950/10'
                        : 'border-slate-800/90'
                    }
                  `}
                >
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1 mb-1.5">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="px-1.5 py-0.5 rounded bg-slate-850 text-slate-200 border border-slate-700 font-mono text-[10px] font-semibold">
                        {formattedType}
                      </span>
                      <span className="text-[11px] font-mono text-slate-400">
                        {ev.event_id}
                      </span>
                    </div>
                    <span className="text-[10px] font-mono text-slate-500 whitespace-nowrap">
                      {formatFull(ev.timestamp)}
                    </span>
                  </div>

                  <p className="text-xs text-slate-300 font-normal leading-relaxed">
                    {ev.detail || ev.type}
                  </p>

                  <div className="flex items-center gap-3 mt-2 font-mono text-[10px] text-slate-500 border-t border-slate-850 pt-1.5">
                    {ev.anomaly_score != null && (
                      <div>
                        Anomaly Weight:{' '}
                        <span className="text-slate-300 font-semibold">
                          {Math.round((ev.anomaly_score > 1 ? ev.anomaly_score : ev.anomaly_score * 100))}%
                        </span>
                      </div>
                    )}
                    {ev.rule_score != null && (
                      <div>
                        Rule Match:{' '}
                        <span className="text-slate-300 font-semibold">
                          {Math.round((ev.rule_score > 1 ? ev.rule_score : ev.rule_score * 100))}%
                        </span>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}
