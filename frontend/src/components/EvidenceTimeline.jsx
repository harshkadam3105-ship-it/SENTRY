/**
 * EvidenceTimeline — chronological display of correlated events
 */

const EVENT_TYPE_CONFIG = {
  auth_failure:         { label: 'Auth Failure',         color: 'border-red-500',    bg: 'bg-red-500',    icon: '🔑' },
  failed_login:         { label: 'Failed Login',         color: 'border-red-500',    bg: 'bg-red-500',    icon: '🔑' },
  lateral_movement:     { label: 'Lateral Movement',     color: 'border-orange-500', bg: 'bg-orange-500', icon: '↔️' },
  privilege_escalation: { label: 'Priv. Escalation',     color: 'border-red-600',    bg: 'bg-red-600',    icon: '⬆️' },
  data_exfiltration:    { label: 'Data Exfiltration',    color: 'border-red-500',    bg: 'bg-red-500',    icon: '📤' },
  command_and_control:  { label: 'C2 Communication',     color: 'border-orange-500', bg: 'bg-orange-500', icon: '📡' },
  suspicious_process:   { label: 'Suspicious Process',   color: 'border-yellow-500', bg: 'bg-yellow-500', icon: '⚙️' },
  new_process:          { label: 'New Process',          color: 'border-yellow-500', bg: 'bg-yellow-500', icon: '⚙️' },
  account_creation:     { label: 'Account Creation',     color: 'border-orange-500', bg: 'bg-orange-500', icon: '👤' },
  persistence:          { label: 'Persistence',          color: 'border-orange-500', bg: 'bg-orange-500', icon: '🔒' },
  network_anomaly:      { label: 'Network Anomaly',      color: 'border-cyan-500',   bg: 'bg-cyan-500',   icon: '🌐' },
  connection_attempt:   { label: 'Connection Attempt',   color: 'border-cyan-500',   bg: 'bg-cyan-500',   icon: '🔌' },
  packet_drop:          { label: 'Packet Drop',          color: 'border-red-400',    bg: 'bg-red-400',    icon: '🛑' },
  suspicious_flow:      { label: 'Suspicious Flow',      color: 'border-orange-500', bg: 'bg-orange-500', icon: '🌊' },
  app_log:              { label: 'Application Log',      color: 'border-slate-400',  bg: 'bg-slate-400',  icon: '📝' },
  credential_dump:      { label: 'Credential Dump',      color: 'border-red-600',    bg: 'bg-red-600',    icon: '💾' },
  ransomware_indicator: { label: 'Ransomware Indicator', color: 'border-red-700',    bg: 'bg-red-700',    icon: '🚨' },
  file_discovery:       { label: 'File Discovery',       color: 'border-yellow-500', bg: 'bg-yellow-500', icon: '📂' },
  data_collection:      { label: 'Data Collection',      color: 'border-yellow-500', bg: 'bg-yellow-500', icon: '📦' },
  anomaly_detected:     { label: 'Anomaly Detected',     color: 'border-cyan-500',   bg: 'bg-cyan-500',   icon: '⚠️' },
}

function formatFull(iso) {
  const d = new Date(iso)
  return d.toLocaleString('en-US', {
    month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
    hour12: false
  })
}

export default function EvidenceTimeline({ events = [] }) {
  const sorted = [...events].sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp))

  return (
    <div className="glass-card p-5">
      <h3 className="text-sm font-semibold text-slate-200 uppercase tracking-wider mb-5">
        Evidence Timeline
        <span className="ml-2 text-xs font-normal text-slate-500 normal-case">
          ({events.length} event{events.length !== 1 ? 's' : ''})
        </span>
      </h3>

      <div className="relative">
        {/* Vertical line */}
        <div className="absolute left-5 top-0 bottom-0 w-px bg-gradient-to-b from-white/10 via-white/5 to-transparent" />

        <div className="space-y-5">
          {sorted.map((ev, idx) => {
            const config = EVENT_TYPE_CONFIG[ev.type] || {
              label: ev.type, color: 'border-slate-500', bg: 'bg-slate-500', icon: '⚠️'
            }

            return (
              <div key={ev.event_id} className="relative flex gap-4 animate-fade-in">
                {/* Timeline dot */}
                <div className={`
                  relative z-10 flex-shrink-0 w-10 h-10 rounded-full
                  flex items-center justify-center
                  border-2 ${config.color} bg-surface-800 text-base
                `}>
                  {config.icon}
                </div>

                {/* Event card */}
                <div className={`
                  flex-1 rounded-lg p-3.5 border
                  ${idx === sorted.length - 1
                    ? 'border-red-500/20 bg-red-950/10'
                    : 'border-white/5 bg-white/2'
                  }
                `}
                style={{ background: idx === sorted.length - 1 ? undefined : 'rgba(255,255,255,0.015)' }}
                >
                  <div className="flex items-start justify-between gap-4 mb-2">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className={`
                        text-xs font-semibold px-2 py-0.5 rounded
                        ${config.bg} bg-opacity-20 text-white
                        border ${config.color} border-opacity-40
                      `}>
                        {config.label}
                      </span>
                      <span className="text-xs font-mono text-slate-500">{ev.event_id}</span>
                    </div>
                    <span className="text-xs font-mono text-slate-500 flex-shrink-0">{formatFull(ev.timestamp)}</span>
                  </div>

                  <p className="text-sm text-slate-200 leading-relaxed">{ev.detail}</p>

                  <div className="flex items-center gap-4 mt-2.5">
                    <div className="flex items-center gap-1.5">
                      <span className="text-xs text-slate-500">Anomaly</span>
                      <span className="text-xs font-mono font-medium text-slate-300">
                        {((ev.anomaly_score || 0) * 100).toFixed(0)}%
                      </span>
                    </div>
                    <div className="w-px h-3 bg-white/10" />
                    <div className="flex items-center gap-1.5">
                      <span className="text-xs text-slate-500">Rule</span>
                      <span className="text-xs font-mono font-medium text-slate-300">
                        {((ev.rule_score || 0) * 100).toFixed(0)}%
                      </span>
                    </div>
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
