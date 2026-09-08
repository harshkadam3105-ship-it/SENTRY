import { useState, useMemo } from 'react'
import { API_BASE, generateSafeUUID } from '../api/incidents'

/**
 * EventInjectorModal — Analyst Event Ingestion & Threat Analysis Console.
 * Allows security operators to input raw telemetry, extract features in real-time,
 * and submit directly to the FastAPI detection & correlation pipeline.
 */

const PRESETS = [
  {
    label: 'Brute Force Attack',
    type: 'failed_login',
    host: 'laptop-mgmt-05.corp',
    user: 'admin',
    sourceType: 'endpoint',
    severity: 4,
    text: 'Failed SSH login attempt 12 times within 45 seconds from external IP 198.51.100.24',
    features: { failed_login_count: 12, bytes_sent: 2400, privilege_change: 0, lsass_access: 0 },
    mitre: ['T1110', 'T1110.001'],
  },
  {
    label: 'Privilege Escalation',
    type: 'privilege_escalation',
    host: 'srv-finance-02',
    user: 'eve.patel',
    sourceType: 'endpoint',
    severity: 5,
    text: 'Unauthorized sudo token manipulation and SeDebugPrivilege grant detected in kernel ring buffer',
    features: { failed_login_count: 0, bytes_sent: 1800, privilege_change: 1, lsass_access: 0 },
    mitre: ['T1068', 'T1548'],
  },
  {
    label: 'Data Exfiltration Spike',
    type: 'data_exfiltration',
    host: 'workstation-14.corp',
    user: 'alice.chen',
    sourceType: 'network',
    severity: 4,
    text: 'Unusual outbound data transfer (3.8 GB) via encrypted TLS to unregistered C2 IP 203.0.113.88',
    features: { failed_login_count: 0, bytes_sent: 3800000000, privilege_change: 0, lsass_access: 0 },
    mitre: ['T1048', 'T1567'],
  },
  {
    label: 'Credential Memory Dump',
    type: 'credential_access',
    host: 'workstation-14.corp',
    user: 'developer',
    sourceType: 'endpoint',
    severity: 4,
    text: 'LSASS process memory access request opened with PROCESS_ALL_ACCESS by unverified executable',
    features: { failed_login_count: 0, bytes_sent: 5200, privilege_change: 1, lsass_access: 1 },
    mitre: ['T1003', 'T1003.001'],
  },
  {
    label: 'Nominal Baseline Login',
    type: 'normal_login',
    host: 'dev-box-03',
    user: 'bob.miller',
    sourceType: 'endpoint',
    severity: 1,
    text: 'Standard Kerberos user logon session initialized through active directory SSO',
    features: { failed_login_count: 0, bytes_sent: 850, privilege_change: 0, lsass_access: 0 },
    mitre: [],
  },
]

export default function EventInjectorModal({ isOpen, onClose, onEventInjected }) {
  const [host, setHost] = useState('workstation-14.corp')
  const [user, setUser] = useState('admin')
  const [sourceType, setSourceType] = useState('endpoint')
  const [eventText, setEventText] = useState(PRESETS[0].text)
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [lastVerdict, setLastVerdict] = useState(null)
  const [error, setError] = useState(null)

  // Real-time pre-classifier parsing
  const parsedAnalysis = useMemo(() => {
    const text = eventText.toLowerCase()
    let event_type = 'anomaly_detected'
    let severity = 2
    let mitre = ['T1059']
    const features = {
      failed_login_count: 0,
      bytes_sent: 1200,
      privilege_change: 0,
      lsass_access: 0,
    }

    if (text.includes('ssh') || text.includes('failed') || text.includes('brute') || text.includes('auth')) {
      event_type = 'failed_login'
      severity = 4
      features.failed_login_count = 8
      mitre = ['T1110', 'T1110.001']
    } else if (text.includes('privilege') || text.includes('sudo') || text.includes('escalat') || text.includes('sedebug')) {
      event_type = 'privilege_escalation'
      severity = 5
      features.privilege_change = 1
      mitre = ['T1068', 'T1548']
    } else if (text.includes('exfiltrat') || text.includes('gb') || text.includes('transfer') || text.includes('outbound')) {
      event_type = 'data_exfiltration'
      severity = 4
      features.bytes_sent = 3500000000
      mitre = ['T1048', 'T1567']
    } else if (text.includes('lsass') || text.includes('dump') || text.includes('credential') || text.includes('mimikatz')) {
      event_type = 'credential_access'
      severity = 4
      features.lsass_access = 1
      mitre = ['T1003', 'T1003.001']
    } else if (text.includes('normal') || text.includes('standard') || text.includes('sso') || text.includes('kerberos')) {
      event_type = 'normal_login'
      severity = 1
      mitre = []
    }

    return { event_type, severity, features, mitre }
  }, [eventText])

  if (!isOpen) return null

  function applyPreset(p) {
    setHost(p.host)
    setUser(p.user)
    setSourceType(p.sourceType)
    setEventText(p.text)
    setLastVerdict(null)
    setError(null)
  }

  async function handleInject() {
    setIsSubmitting(true)
    setError(null)

    // Build EventIn schema payload using safe UUID generator
    const eventId = generateSafeUUID()
    const payload = {
      event_id: eventId,
      timestamp: new Date().toISOString(),
      source_type: sourceType,
      host_id: host.trim() || 'workstation-14.corp',
      user_id: user.trim() || 'analyst',
      src_ip: '192.168.1.55',
      dst_ip: '10.0.0.1',
      protocol: 'TCP',
      event_type: parsedAnalysis.event_type,
      severity: parsedAnalysis.severity,
      features: parsedAnalysis.features,
      raw_data: {
        log: eventText,
        host: host.trim() || 'workstation-14.corp',
        user: user.trim() || 'analyst',
        source_type: sourceType,
      },
    }

    try {
      const res = await fetch(`${API_BASE}/events`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      })

      if (!res.ok) {
        throw new Error(`HTTP ${res.status} ${res.statusText}`)
      }

      const result = await res.json()
      setLastVerdict(result)
      if (onEventInjected) {
        onEventInjected(result)
      }
    } catch (err) {
      console.error('Failed to inject event:', err)
      setError(err.message || 'Pipeline ingestion error')
    } finally {
      setIsSubmitting(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-xs">
      <div className="soc-panel w-full max-w-4xl max-h-[92vh] flex flex-col overflow-hidden shadow-2xl border border-slate-750">
        {/* Modal Header */}
        <div className="flex items-center justify-between px-5 py-3 border-b border-slate-800 bg-slate-900/90 shrink-0">
          <div className="flex items-center gap-2.5">
            <div className="p-1 rounded bg-slate-850 border border-slate-800 text-slate-300">
              {/* Terminal / Ingestion SVG */}
              <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <polyline points="4 17 10 11 4 5" />
                <line x1="12" y1="19" x2="20" y2="19" />
              </svg>
            </div>
            <div>
              <h2 className="text-xs font-bold text-slate-200 uppercase tracking-wider">
                Event Injection & Telemetry Console
              </h2>
              <p className="text-[11px] text-slate-500">
                Feed raw telemetry into hybrid ML Anomaly Detection & Correlation Engine
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <line x1="18" y1="6" x2="6" y2="18" />
              <line x1="6" y1="6" x2="18" y2="18" />
            </svg>
          </button>
        </div>

        {/* Modal Body: Two Columns */}
        <div className="grid grid-cols-1 md:grid-cols-2 divide-y md:divide-y-0 md:divide-x divide-slate-800 overflow-y-auto flex-1">
          {/* Left Column: Input Form */}
          <div className="p-5 flex flex-col gap-4">
            {/* Quick Scenario Presets */}
            <div>
              <div className="text-[10px] font-semibold uppercase tracking-wider text-slate-400 mb-2">
                Quick Telemetry Scenarios
              </div>
              <div className="flex flex-wrap gap-1.5">
                {PRESETS.map(p => (
                  <button
                    key={p.label}
                    onClick={() => applyPreset(p)}
                    className="px-2 py-1 text-[11px] font-mono rounded bg-slate-850 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-750 transition-colors"
                  >
                    {p.label}
                  </button>
                ))}
              </div>
            </div>

            {/* Inputs: Host, User, Source Type */}
            <div className="grid grid-cols-3 gap-2">
              <div>
                <label className="block text-[10px] font-semibold uppercase text-slate-400 mb-1">
                  Target Host
                </label>
                <input
                  type="text"
                  value={host}
                  onChange={e => setHost(e.target.value)}
                  className="w-full px-2.5 py-1.5 rounded bg-slate-900 border border-slate-800 text-slate-200 text-xs font-mono focus:border-slate-600 focus:outline-none"
                  placeholder="e.g. host-01.corp"
                />
              </div>
              <div>
                <label className="block text-[10px] font-semibold uppercase text-slate-400 mb-1">
                  Identity / User
                </label>
                <input
                  type="text"
                  value={user}
                  onChange={e => setUser(e.target.value)}
                  className="w-full px-2.5 py-1.5 rounded bg-slate-900 border border-slate-800 text-slate-200 text-xs font-mono focus:border-slate-600 focus:outline-none"
                  placeholder="e.g. admin"
                />
              </div>
              <div>
                <label className="block text-[10px] font-semibold uppercase text-slate-400 mb-1">
                  Source Layer
                </label>
                <select
                  value={sourceType}
                  onChange={e => setSourceType(e.target.value)}
                  className="w-full px-2 py-1.5 rounded bg-slate-900 border border-slate-800 text-slate-200 text-xs font-mono focus:border-slate-600 focus:outline-none"
                >
                  <option value="endpoint">Endpoint OS</option>
                  <option value="network">Network Flow</option>
                  <option value="application">Application</option>
                </select>
              </div>
            </div>

            {/* Event Description / Raw Log */}
            <div className="flex-1 flex flex-col">
              <label className="block text-[10px] font-semibold uppercase text-slate-400 mb-1">
                Event Description / Raw Syslog Payload
              </label>
              <textarea
                rows={4}
                value={eventText}
                onChange={e => setEventText(e.target.value)}
                className="w-full p-2.5 rounded bg-slate-900 border border-slate-800 text-slate-200 text-xs font-mono focus:border-slate-600 focus:outline-none resize-none leading-relaxed flex-1"
                placeholder="Paste raw log lines or enter event description..."
              />
            </div>

            {/* Action Buttons */}
            <div className="flex items-center justify-between pt-2 border-t border-slate-800/80">
              <span className="text-[11px] text-slate-500 font-mono">
                API: POST /events
              </span>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={onClose}
                  className="px-3 py-1.5 text-xs font-medium text-slate-400 hover:text-white rounded bg-slate-900 hover:bg-slate-850 border border-slate-800 transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  disabled={isSubmitting || !eventText.trim()}
                  onClick={handleInject}
                  className="px-4 py-1.5 text-xs font-mono font-semibold text-slate-100 bg-slate-800 hover:bg-slate-700 border border-slate-600 rounded transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-1.5"
                >
                  {isSubmitting ? (
                    <>
                      <span className="w-2.5 h-2.5 border-2 border-slate-400 border-t-transparent rounded-full animate-spin" />
                      Analyzing…
                    </>
                  ) : (
                    'Inject & Analyze Stream'
                  )}
                </button>
              </div>
            </div>

            {error && (
              <div className="p-2.5 rounded bg-red-950/30 border border-red-500/30 text-red-400 text-xs font-mono">
                Pipeline error: {error}
              </div>
            )}
          </div>

          {/* Right Column: Pre-Classifier & Live Pipeline Verdict */}
          <div className="p-5 flex flex-col gap-4 bg-slate-900/40">
            <div>
              <div className="text-[10px] font-semibold uppercase tracking-wider text-slate-400 mb-2">
                Parsed Feature Vector
              </div>
              <div className="grid grid-cols-2 gap-2 text-xs font-mono">
                <div className="p-2 rounded bg-slate-900 border border-slate-800">
                  <div className="text-[10px] text-slate-500 uppercase">Event Type</div>
                  <div className="text-slate-200 font-semibold mt-0.5">
                    {parsedAnalysis.event_type}
                  </div>
                </div>
                <div className="p-2 rounded bg-slate-900 border border-slate-800">
                  <div className="text-[10px] text-slate-500 uppercase">Pre-Severity</div>
                  <div className="text-amber-400 font-semibold mt-0.5">
                    Level {parsedAnalysis.severity} / 5
                  </div>
                </div>
              </div>
            </div>

            {/* Feature values */}
            <div className="soc-panel p-3 bg-slate-950/60">
              <div className="text-[10px] text-slate-500 uppercase font-mono mb-2">
                Engine Extracted Indicators
              </div>
              <div className="space-y-1.5 font-mono text-[11px]">
                <div className="flex items-center justify-between text-slate-400">
                  <span>failed_login_count</span>
                  <span className="text-slate-200">{parsedAnalysis.features.failed_login_count}</span>
                </div>
                <div className="flex items-center justify-between text-slate-400">
                  <span>bytes_sent</span>
                  <span className="text-slate-200">{parsedAnalysis.features.bytes_sent} B</span>
                </div>
                <div className="flex items-center justify-between text-slate-400">
                  <span>privilege_change</span>
                  <span className="text-slate-200">{parsedAnalysis.features.privilege_change}</span>
                </div>
                <div className="flex items-center justify-between text-slate-400">
                  <span>lsass_access</span>
                  <span className="text-slate-200">{parsedAnalysis.features.lsass_access}</span>
                </div>
              </div>
            </div>

            {/* MITRE Mapping */}
            <div>
              <div className="text-[10px] font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
                Target MITRE ATT&CK Mapping
              </div>
              <div className="flex flex-wrap gap-1.5">
                {parsedAnalysis.mitre.length > 0 ? (
                  parsedAnalysis.mitre.map(code => (
                    <span key={code} className="mitre-tag">
                      {code}
                    </span>
                  ))
                ) : (
                  <span className="text-[11px] text-slate-500 font-mono">
                    Nominal baseline — 0 threat tags
                  </span>
                )}
              </div>
            </div>

            {/* Live Verdict from Backend Pipeline */}
            <div className="flex-1 flex flex-col justify-end">
              <div className="text-[10px] font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
                Pipeline Detection Verdict
              </div>
              {lastVerdict ? (
                <div className="p-3 rounded bg-slate-900 border border-slate-750 flex flex-col gap-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-emerald-400 flex items-center gap-1.5">
                      <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                      Injected to Real-Time Bus
                    </span>
                    {lastVerdict.incident_generated ? (
                      <span className="px-1.5 py-0.5 rounded bg-red-950/60 text-red-400 border border-red-500/30 text-[10px] font-mono font-bold">
                        INCIDENT GENERATED
                      </span>
                    ) : (
                      <span className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 text-[10px] font-mono">
                        STREAM STORED
                      </span>
                    )}
                  </div>
                  <div className="grid grid-cols-3 gap-2 text-center text-xs font-mono pt-1">
                    <div>
                      <div className="text-[10px] text-slate-500 uppercase">Anomaly</div>
                      <div className="text-slate-200 font-bold">{lastVerdict.anomaly_score}</div>
                    </div>
                    <div>
                      <div className="text-[10px] text-slate-500 uppercase">Rule</div>
                      <div className="text-slate-200 font-bold">{lastVerdict.rule_score}</div>
                    </div>
                    <div>
                      <div className="text-[10px] text-slate-500 uppercase">Risk</div>
                      <div className="text-orange-400 font-bold">{lastVerdict.risk_score}</div>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="p-3 rounded bg-slate-900/60 border border-slate-850 text-center text-slate-500 text-xs font-mono">
                  Awaiting injection dispatch…
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
