import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { injectEvent, downloadIncidentDossier } from '../api/incidents'
import SeverityBadge from './SeverityBadge'
import { IconZap, IconServer, IconLaptop, IconTarget, IconAlertTriangle, IconShieldAlert, IconCheckCircle, IconAlertCircle, IconBot } from './Icons'
import { resolveMitreTechnique, openMitreUrl } from '../utils/mitre'

function generateSafeUUID() {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    try {
      return crypto.randomUUID()
    } catch {
      // fallback
    }
  }
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    const r = Math.random() * 16 | 0
    const v = c === 'x' ? r : (r & 0x3 | 0x8)
    return v.toString(16)
  })
}

const SIMPLE_EXAMPLES = [
  {
    label: 'Brute Force (SSH / Auth)',
    title: 'SSH Brute Force Attack',
    desc: '18 failed consecutive login attempts on admin account',
    text: '18 consecutive failed SSH login attempts detected for user admin on port 22',
    host: 'friends-workstation.corp',
    user: 'admin',
    event_type: 'failed_login',
    severity: 4,
    features: { failed_login_count: 18, login_speed_sec: 0.4 },
    badge: 'HIGH RISK',
    badgeColor: 'text-amber-400 bg-amber-950/60 border-amber-500/40',
  },
  {
    label: 'Privilege Escalation',
    title: 'Sudo / Admin Abuse',
    desc: 'Standard user eve elevated to root administrator via sudo token',
    text: 'Privilege escalation: user eve elevated to root administrator via sudo token',
    host: 'friends-laptop-02.corp',
    user: 'eve.patel',
    event_type: 'privilege_escalation',
    severity: 5,
    features: { failed_login_count: 0, elevated_to: 'root', sudo_nopasswd: true, privilege_change: 1 },
    badge: 'CRITICAL',
    badgeColor: 'text-red-400 bg-red-950/60 border-red-500/40',
  },
  {
    label: 'Data Exfiltration',
    title: 'Data Egress Tunnel',
    desc: '2.5 GB database archive egress to untrusted external IP',
    text: 'Outbound flow spike: 2.5 GB database backup transferred to untrusted external IP over HTTPS',
    host: 'friends-srv-01',
    user: 'svc_backup',
    event_type: 'data_exfiltration',
    severity: 4,
    features: { bytes_transferred: 2684354560, bytes_sent: 2684354560, connection_rate: 35.0, destination_port: 443 },
    badge: 'HIGH RISK',
    badgeColor: 'text-amber-400 bg-amber-950/60 border-amber-500/40',
  },
  {
    label: 'Credential Dumping',
    title: 'LSASS Memory Dump',
    desc: 'EDR alert: Mimikatz injection targeting lsass.exe process',
    text: 'EDR alert: Unauthorized memory dump of lsass.exe process by mimikatz.exe',
    host: 'friends-devbox',
    user: 'SYSTEM',
    event_type: 'credential_access',
    severity: 5,
    features: { credential_dump_indicator: true, lsass_access: true, new_process: 1 },
    badge: 'CRITICAL',
    badgeColor: 'text-red-400 bg-red-950/60 border-red-500/40',
  },
  {
    label: 'Normal Activity (Baseline)',
    title: 'Clean Developer Workflow',
    desc: 'User logged in successfully and ran normal build tasks',
    text: 'User alice logged in successfully at 09:00 AM for workday session',
    host: 'friends-workstation.corp',
    user: 'alice.chen',
    event_type: 'normal_login',
    severity: 1,
    features: { failed_login_count: 0, success_count: 1 },
    badge: 'SAFE',
    badgeColor: 'text-emerald-400 bg-emerald-950/60 border-emerald-500/40',
  },
]

/**
 * Lightweight client-side extractor to ensure features are passed reliably for custom text edits.
 */
function extractFeatures(text) {
  if (!text) return {}
  const t = text.toLowerCase()
  const f = {}

  // Failed logins
  let m = t.match(/(\d+)\s*(?:consecutive\s*)?(?:failed|unsuccessful|invalid)[^0-9\n]{0,30}(?:login|auth|ssh|rdp|attempts?)/)
  if (!m) m = t.match(/(?:failed|unsuccessful)[^0-9\n]{0,30}(?:login|auth|attempts?)[^0-9\n]{0,10}(\d+)/)
  if (!m) m = t.match(/(\d+)\s*(?:failed\s*)?attempts?/)
  if (m) f.failed_login_count = parseInt(m[1], 10)
  else if (/\b(failed login|auth fail)\b/.test(t)) f.failed_login_count = 6

  // Bytes / data exfiltration
  const gb = t.match(/(\d+(?:\.\d+)?)\s*(?:gb|gigabytes?)\b/)
  const mb = t.match(/(\d+(?:\.\d+)?)\s*(?:mb|megabytes?)\b/)
  if (gb) {
    f.bytes_sent = Math.round(parseFloat(gb[1]) * 1024 * 1024 * 1024)
    f.connection_rate = 35.0
  } else if (mb) {
    f.bytes_sent = Math.round(parseFloat(mb[1]) * 1024 * 1024)
    f.connection_rate = 20.0
  } else if (/\b(exfiltrat|egress|bulk upload|data leak)\b/.test(t)) {
    f.bytes_sent = 1400000000
    f.connection_rate = 35.0
  }

  // Privilege escalation
  if (/\b(privilege escalation|escalat|sudo|elevated to root|became root)\b/.test(t)) {
    f.privilege_change = true
  }

  // LSASS / Credential dump
  if (/\b(lsass|mimikatz|sekurlsa|procdump|credential dump)\b/.test(t)) {
    f.credential_dump_indicator = true
    f.lsass_access = true
  }

  // Process / Living-off-the-land
  if (/\b(spawned|powershell|cmd\.exe|living-off-the-land)\b/.test(t)) {
    f.parent_process_change = true
    f.new_process = true
  }

  // Log wipe / Defense evasion
  if (/\b(wevtutil|clear-eventlog|cleared log|log wipe|wipe log)\b/.test(t)) {
    f.log_cleared = true
  }

  // Warning / security keywords fallback
  if (/\b(warning|alert|threat|suspicious|unauthorized|breach|intrusion|danger|attack|hacked)\b/.test(t)) {
    if (!f.failed_login_count && !f.bytes_sent && !f.privilege_change && !f.credential_dump_indicator) {
      f.failed_login_count = 10
      f.auth_failure_rate = 0.85
    }
  }

  return f
}

export default function EventInjectorModal({ isOpen, onClose }) {
  const navigate = useNavigate()

  const isServerBrowser = typeof window !== 'undefined' && (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1')
  const defaultServerHost = 'DESKTOP-8VSC7JT'
  const defaultFriendHost = 'friends-laptop.corp'

  // State
  const [selectedIdx, setSelectedIdx] = useState(0)
  const [eventText, setEventText] = useState(SIMPLE_EXAMPLES[0].text)
  const [isTextEdited, setIsTextEdited] = useState(false)
  const [host, setHost] = useState(isServerBrowser ? defaultServerHost : defaultFriendHost)
  const [user, setUser] = useState(SIMPLE_EXAMPLES[0].user)

  const [analyzing, setAnalyzing] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)

  if (!isOpen) return null

  function handlePickExample(ex, idx) {
    setSelectedIdx(idx)
    setEventText(ex.text)
    setIsTextEdited(false)
    if (ex.user) setUser(ex.user)
    setResult(null)
    setError(null)
  }

  async function handleAnalyze(overrideText, overrideHost, overrideUser, overrideEx) {
    const textToUse = overrideText !== undefined ? overrideText : eventText
    if (!textToUse || !textToUse.trim()) return

    setAnalyzing(true)
    setError(null)
    setResult(null)

    const ex = overrideEx || SIMPLE_EXAMPLES[selectedIdx]
    const isCustomText = ex ? textToUse.trim() !== ex.text.trim() : true

    const hostToUse = overrideHost || host || (isServerBrowser ? defaultServerHost : defaultFriendHost)
    const userToUse = overrideUser || user || (ex ? ex.user : 'admin')

    // Inherit base features and severity from the chosen threat scenario card
    let features = ex ? { ...ex.features } : {}
    let eventType = ex ? ex.event_type : 'security_event'
    let severity = ex ? ex.severity : 4

    if (isCustomText) {
      const parsedFeatures = extractFeatures(textToUse)
      features = { ...features, ...parsedFeatures }

      const isExplicitThreat = /\b(fail|attack|malicious|unauthorized|breach|exploit|exfiltrat|dump|elevat|lsass|warning|alert|suspicious|danger|intrusion|c2|payload|spray|flood)\b/i.test(textToUse)
      const isExplicitBenign = /\b(normal|routine|baseline|success|clean|regular|daily)\b/i.test(textToUse) && !isExplicitThreat

      if (isExplicitBenign && Object.keys(parsedFeatures).length === 0) {
        eventType = 'normal_login'
        severity = 1
      } else if (parsedFeatures.bytes_sent || /exfiltrat|egress|backup|leak|bytes/i.test(textToUse)) {
        eventType = 'data_exfiltration'
        severity = 4
      } else if (parsedFeatures.privilege_change || /sudo|root|privilege/i.test(textToUse)) {
        eventType = 'privilege_escalation'
        severity = 5
      } else if (parsedFeatures.credential_dump_indicator || /lsass|mimikatz|memory/i.test(textToUse)) {
        eventType = 'credential_access'
        severity = 5
      } else if (parsedFeatures.failed_login_count || /failed|login|auth/i.test(textToUse)) {
        eventType = 'failed_login'
        severity = 4
      } else if (isExplicitThreat) {
        severity = Math.max(severity, 4)
        if (eventType === 'normal_login') eventType = 'security_event'
      }
    }

    const payload = {
      event_id: generateSafeUUID(),
      timestamp: new Date().toISOString(),
      source_type: 'endpoint',
      host_id: hostToUse,
      user_id: userToUse,
      src_ip: hostToUse === defaultServerHost ? '10.211.2.190' : '10.211.2.142',
      dst_ip: '10.211.2.190',
      src_port: 49152,
      dst_port: 443,
      protocol: 'TCP',
      event_type: eventType,
      severity: severity,
      features: features,
      raw_data: { log: textToUse, user: userToUse, threat_type: eventType, host: hostToUse },
    }

    try {
      const res = await injectEvent(payload)
      setResult(res)
    } catch (err) {
      console.error('[Sentry] Injection failed:', err)
      setError(err.message || 'Failed to analyze event. Check network connection to SENTRY.')
    } finally {
      setAnalyzing(false)
    }
  }

  const incident = result?.incident

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in">
      <div className="relative w-full max-w-2xl bg-surface-850 border border-white/10 rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="px-6 py-4 border-b border-white/10 flex items-center justify-between bg-surface-800/80">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center text-white shadow-lg shadow-cyan-500/30">
              <IconZap className="w-4 h-4" />
            </div>
            <div>
              <h2 className="text-base font-bold text-white">Inject Security Event / Scenario</h2>
              <p className="text-xs text-slate-400">Select any threat scenario below to fire it live into SENTRY</p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close modal"
            className="text-slate-400 hover:text-white p-1.5 rounded-lg hover:bg-white/10 transition-colors cursor-pointer"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-5">
          {/* Target Host & User Quick Selection */}
          <div className="p-3.5 rounded-xl bg-surface-800/90 border border-white/10 space-y-2.5">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
                <IconTarget className="w-3.5 h-3.5 text-cyan-400" /> TARGET ENDPOINT COMPUTER & IDENTITY:
              </span>
              <span className="text-[10px] text-cyan-400 font-mono">
                Attributing to: <strong className="text-white underline">{host}</strong> ({user})
              </span>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={() => setHost(defaultServerHost)}
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all flex items-center gap-1.5 cursor-pointer ${
                  host === defaultServerHost
                    ? 'bg-cyan-500 text-black shadow-md shadow-cyan-500/25 ring-1 ring-cyan-400'
                    : 'bg-surface-900 text-slate-300 hover:text-white hover:bg-surface-700 border border-white/10'
                }`}
              >
                <IconServer className="w-3.5 h-3.5" /> Primary Server ({defaultServerHost})
              </button>

              <button
                type="button"
                onClick={() => setHost(defaultFriendHost)}
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all flex items-center gap-1.5 cursor-pointer ${
                  host === defaultFriendHost || (host.includes('friend') && host !== defaultServerHost)
                    ? 'bg-cyan-500 text-black shadow-md shadow-cyan-500/25 ring-1 ring-cyan-400'
                    : 'bg-surface-900 text-slate-300 hover:text-white hover:bg-surface-700 border border-white/10'
                }`}
              >
                <IconLaptop className="w-3.5 h-3.5" /> Friend's Laptop ({defaultFriendHost})
              </button>

              <div className="flex items-center gap-1.5 ml-auto">
                <span className="text-[10px] text-slate-400 font-mono">Host:</span>
                <input
                  type="text"
                  value={host}
                  onChange={(e) => setHost(e.target.value)}
                  placeholder="Host name..."
                  className="w-32 bg-surface-950 border border-white/10 rounded-lg px-2 py-1 text-xs text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="flex items-center gap-1.5">
                <span className="text-[10px] text-slate-400 font-mono">User:</span>
                <input
                  type="text"
                  value={user}
                  onChange={(e) => setUser(e.target.value)}
                  placeholder="Target user..."
                  className="w-24 bg-surface-950 border border-white/10 rounded-lg px-2 py-1 text-xs text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
                />
              </div>
            </div>
          </div>

          {/* Threat Scenario Cards Grid */}
          <div>
            <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider mb-2.5 flex items-center justify-between">
              <span>SELECT THREAT SCENARIO TO FIRE:</span>
              <span className="text-[10px] text-cyan-400 normal-case font-mono">1-click select & run</span>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
              {SIMPLE_EXAMPLES.map((ex, idx) => {
                const isSelected = selectedIdx === idx
                return (
                  <div
                    key={idx}
                    onClick={() => handlePickExample(ex, idx)}
                    className={`p-3 rounded-xl border transition-all cursor-pointer flex flex-col justify-between gap-2 text-left ${
                      isSelected
                        ? 'bg-cyan-950/60 border-cyan-400 shadow-lg shadow-cyan-500/20 ring-1 ring-cyan-500'
                        : 'bg-surface-800/80 hover:bg-surface-700/80 text-slate-300 border-white/10 hover:border-cyan-500/40'
                    }`}
                  >
                    <div>
                      <div className="flex items-center justify-between gap-1 mb-1">
                        <span className="font-bold text-xs text-white flex items-center gap-1.5">
                          {ex.label}
                        </span>
                        <span className={`text-[9px] px-1.5 py-0.5 rounded border font-semibold ${ex.badgeColor}`}>
                          {ex.badge}
                        </span>
                      </div>
                      <p className="text-[11px] text-slate-400 leading-snug line-clamp-2">
                        {ex.desc}
                      </p>
                    </div>

                    <div className="flex items-center justify-between pt-1 border-t border-white/5">
                      <span className="text-[10px] font-mono text-cyan-400 truncate max-w-[150px]">
                        Target: {host}
                      </span>
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation()
                          if (isSelected && isTextEdited && eventText.trim()) {
                            handleAnalyze(eventText, host, user, ex)
                          } else {
                            handlePickExample(ex, idx)
                            handleAnalyze(ex.text, host, ex.user || user, ex)
                          }
                        }}
                        disabled={analyzing}
                        className={`text-[10px] px-2 py-0.5 rounded font-bold transition-all flex items-center gap-1 cursor-pointer ${
                          isSelected
                            ? 'bg-cyan-500 text-black hover:bg-cyan-400 shadow-sm'
                            : 'bg-surface-700 text-slate-200 hover:bg-cyan-600 hover:text-white'
                        }`}
                      >
                        Fire Now
                      </button>
                    </div>
                  </div>
                )
              })}
            </div>
          </div>

          {/* Active Log Payload Description */}
          <div className="space-y-1.5">
            <div className="flex items-center justify-between">
              <label className="text-xs font-semibold text-slate-300">
                Active Scenario Log Payload:
              </label>
              <span className="text-[10px] text-slate-400">Editable for custom testing</span>
            </div>
            <textarea
              rows={2}
              value={eventText}
              onChange={(e) => {
                setEventText(e.target.value)
                setIsTextEdited(true)
              }}
              placeholder="e.g. 18 consecutive failed SSH login attempts detected..."
              className="w-full bg-surface-900 border border-white/10 rounded-xl p-2.5 text-xs text-slate-100 font-mono focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-all"
            />
          </div>

          {/* Big Dispatch & Analyze Button */}
          <button
            type="button"
            onClick={() => handleAnalyze()}
            disabled={analyzing || !eventText.trim()}
            className="w-full py-3.5 rounded-xl font-bold text-sm bg-gradient-to-r from-cyan-600 via-blue-600 to-indigo-600 hover:from-cyan-500 hover:to-indigo-500 text-white shadow-xl shadow-cyan-500/25 active:scale-[0.99] transition-all flex items-center justify-center gap-2 cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed"
          >
            {analyzing ? (
              <>
                <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                <span>Injecting & Running Detection Pipeline…</span>
              </>
            ) : (
              <>
                <IconZap className="w-4 h-4" />
                <span>Dispatch & Analyze Event into SENTRY</span>
              </>
            )}
          </button>

          {error && (
            <div className="p-3 rounded-xl bg-red-950/50 border border-red-500/50 text-red-300 text-xs flex items-center gap-2">
              <IconAlertTriangle className="w-5 h-5 text-rose-400 flex-shrink-0" />
              <div>
                <p className="font-bold">Dispatch Error</p>
                <p>{error}</p>
              </div>
            </div>
          )}

          {/* Result Card */}
          {result && (
            <div className="p-4 rounded-xl bg-surface-800 border border-cyan-500/40 shadow-xl space-y-3 animate-fade-in">
              {/* Verdict Header */}
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  {result.incident_generated ? (
                    <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-red-950 border border-red-500/50 text-red-400 flex items-center gap-1.5">
                      <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
                      <IconShieldAlert className="w-3.5 h-3.5 text-rose-400" /> Threat Flagged & Incident Created
                    </span>
                  ) : (
                    <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-emerald-950 border border-emerald-500/40 text-emerald-400 flex items-center gap-1.5">
                      <span className="w-2 h-2 rounded-full bg-emerald-400" />
                      <IconCheckCircle className="w-3.5 h-3.5 text-emerald-400" /> Benign Baseline Event (Safe)
                    </span>
                  )}
                </div>

                <div className="text-xs text-slate-300">
                  Risk Score:{' '}
                  <span className={`font-bold font-mono text-sm ${
                    result.risk_score >= 60 ? 'text-red-400' : result.risk_score >= 35 ? 'text-amber-400' : 'text-emerald-400'
                  }`}>
                    {result.risk_score}/100
                  </span>
                </div>
              </div>

              {/* What Was Detected */}
              <div>
                <div className="text-[10px] text-slate-400 uppercase tracking-wider font-semibold mb-0.5">
                  What Was Detected:
                </div>
                <div className="flex items-center gap-2.5">
                  <h3 className="text-sm font-bold text-white">
                    {incident?.title || (result.incident_generated ? 'Suspicious Security Activity' : 'Normal User Activity')}
                  </h3>
                  {incident && <SeverityBadge severity={incident.severity} />}
                </div>
              </div>

              {/* Why It Was Flagged */}
              <div className="p-3 rounded-lg bg-surface-900 border border-white/5 space-y-1">
                <div className="text-[11px] font-semibold text-cyan-400 flex items-center gap-1">
                  <IconAlertCircle className="w-3.5 h-3.5 text-cyan-400" /> Why SENTRY flagged this:
                </div>
                <p className="text-xs text-slate-200 leading-relaxed font-medium">
                  {result.explanation || 'No security rules breached. Activity appears benign.'}
                </p>

                {incident?.mitre_techniques?.length > 0 && (
                  <div className="pt-1.5 flex flex-wrap gap-1.5 items-center">
                    <span className="text-[10px] text-slate-400">MITRE:</span>
                    {incident.mitre_techniques.map((t, i) => {
                      const m = resolveMitreTechnique(t, i)
                      return (
                        <a
                          key={m.id + '-' + i}
                          href={m.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          onClick={(e) => openMitreUrl(m.url, e)}
                          title={`Open official MITRE ATT&CK definition for ${m.displayId} (${m.name}): ${m.url}`}
                          className="text-[10px] px-2 py-0.5 rounded bg-indigo-950/80 hover:bg-indigo-900 border border-indigo-500/30 hover:border-indigo-400 text-indigo-300 hover:text-cyan-300 font-mono transition-colors flex items-center gap-1 cursor-pointer"
                        >
                          <span>{m.displayId} · {m.name}</span>
                          <span className="text-[9px] opacity-70">↗</span>
                        </a>
                      )
                    })}
                  </div>
                )}
              </div>

              {/* AI Threat Analyst Intelligence Card */}
              {(result.ai_analysis || incident?.ai_analysis) && (() => {
                const ai = result.ai_analysis || incident.ai_analysis
                return (
                  <div className="p-3.5 rounded-xl bg-gradient-to-br from-indigo-950/40 via-surface-900 to-cyan-950/40 border border-cyan-500/40 space-y-2.5">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <IconBot className="w-4 h-4 text-cyan-400" />
                        <span className="text-xs font-bold text-cyan-300">AI Threat Analyst Intelligence</span>
                      </div>
                      <span className="text-[10px] px-2 py-0.5 rounded-full bg-cyan-950 border border-cyan-500/30 text-cyan-400 font-mono">
                        Confidence: {Math.round((ai.ai_confidence || 0.94) * 100)}%
                      </span>
                    </div>

                    {/* Kill Chain & Profile Tags */}
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px]">
                      <div className="p-2 rounded-lg bg-surface-950/70 border border-white/5">
                        <span className="text-slate-400 text-[10px] uppercase tracking-wider block font-semibold mb-0.5">Kill Chain Stage:</span>
                        <span className="font-semibold text-purple-300">{ai.kill_chain_stage}</span>
                      </div>
                      <div className="p-2 rounded-lg bg-surface-950/70 border border-white/5">
                        <span className="text-slate-400 text-[10px] uppercase tracking-wider block font-semibold mb-0.5">Threat Actor Profile:</span>
                        <span className="font-semibold text-amber-300">{ai.threat_actor_profile}</span>
                      </div>
                    </div>

                    {/* Executive Summary */}
                    <div className="text-xs text-slate-200 leading-relaxed font-medium bg-surface-950/60 p-2.5 rounded-lg border border-white/5">
                      <span className="text-cyan-400 font-semibold">Forensic Assessment: </span>
                      {ai.executive_summary}
                    </div>

                    {/* Blast Radius & Recommended Response */}
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pt-1">
                      <div className="text-[11px] text-slate-400">
                        Blast Radius: <span className="text-slate-200 font-semibold">{ai.blast_radius}</span>
                      </div>
                      {ai.recommended_actions?.length > 0 && (
                        <div className="flex flex-wrap gap-1">
                          {ai.recommended_actions.slice(0, 2).map((act, idx) => (
                            <span key={idx} className="text-[10px] px-2 py-0.5 rounded bg-emerald-950/70 border border-emerald-500/40 text-emerald-300">
                              {act}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                )
              })()}

              {/* Action Buttons */}
              <div className="flex items-center justify-between pt-1">
                {incident ? (
                  <button
                    type="button"
                    onClick={() => {
                      onClose()
                      navigate(`/incident/${incident.incident_id}`)
                    }}
                    className="px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white flex items-center gap-1.5 transition-colors cursor-pointer shadow-md"
                  >
                    <span>View Full Incident Report</span>
                    <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14 5l7 7m0 0l-7 7m7-7H3" />
                    </svg>
                  </button>
                ) : (
                  <span className="text-xs text-slate-400">Logged clean event in telemetry stream.</span>
                )}

                {incident && (
                  <button
                    type="button"
                    onClick={() => downloadIncidentDossier(incident)}
                    className="px-3 py-1.5 rounded-lg text-xs font-medium bg-surface-700 hover:bg-surface-600 text-slate-200 hover:text-white border border-white/10 flex items-center gap-1.5 transition-colors cursor-pointer"
                  >
                    <svg className="w-3.5 h-3.5 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                    </svg>
                    <span>Save Dossier (JSON)</span>
                  </button>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
