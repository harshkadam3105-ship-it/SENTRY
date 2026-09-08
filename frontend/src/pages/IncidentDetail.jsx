import { useState, useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import SeverityBadge from '../components/SeverityBadge'
import RiskScoreBreakdown from '../components/RiskScoreBreakdown'
import EvidenceTimeline from '../components/EvidenceTimeline'
import RemediationConsole from '../components/RemediationConsole'
import { IconBot, IconTarget, IconUser, IconShieldAlert, IconAlertCircle, IconZap } from '../components/Icons'
import { getIncidentById, isolateHost, downloadIncidentDossier } from '../api/incidents'
import { resolveMitreTechnique, openMitreUrl } from '../utils/mitre'

/**
 * IncidentDetail — deep-dive view for a single incident
 */

function MitreTag({ technique, index = 0 }) {
  const [copied, setCopied] = useState(false)
  const item = resolveMitreTechnique(technique, index)

  const handleCopy = (e) => {
    e.preventDefault()
    e.stopPropagation()
    if (typeof navigator !== 'undefined' && navigator.clipboard) {
      navigator.clipboard.writeText(item.url)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    }
  }

  const handleClick = (e) => {
    openMitreUrl(item.url, e)
  }

  return (
    <div className="p-3.5 rounded-xl bg-indigo-950/40 hover:bg-indigo-900/60 border border-indigo-500/30 hover:border-indigo-400/60 transition-all flex flex-col justify-between gap-1.5 group shadow-sm hover:shadow-indigo-500/10">
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <span className="font-mono font-bold text-xs px-2 py-0.5 rounded bg-indigo-900/80 text-indigo-300 border border-indigo-500/40">
            {item.displayId}
          </span>
          <span className="text-xs font-semibold text-white group-hover:text-cyan-300 transition-colors">
            {item.name}
          </span>
        </div>
        <div className="flex items-center gap-1.5">
          <button
            type="button"
            onClick={handleCopy}
            title="Copy verified MITRE URL to clipboard"
            className="text-[10px] text-slate-400 hover:text-white px-2 py-0.5 rounded bg-surface-900/80 hover:bg-surface-700 border border-white/5 transition-colors cursor-pointer"
          >
            {copied ? 'Copied' : 'Copy Link'}
          </button>
          <a
            href={item.url}
            target="_blank"
            rel="noopener noreferrer"
            onClick={handleClick}
            className="text-[11px] text-indigo-300 group-hover:text-cyan-300 font-mono flex items-center gap-0.5 hover:underline cursor-pointer"
            title={`Open official MITRE framework page for ${item.displayId}`}
          >
            <span>ATT&CK</span>
            <span className="text-xs">↗</span>
          </a>
        </div>
      </div>

      <div className="flex items-center justify-between gap-2 mt-0.5">
        <span className="text-[10px] px-1.5 py-0.5 rounded bg-surface-900 text-indigo-300/80 font-mono border border-white/5">
          {item.tactic}
        </span>
        <a
          href={item.url}
          target="_blank"
          rel="noopener noreferrer"
          onClick={handleClick}
          className="text-[10px] text-slate-400 hover:text-cyan-300 font-mono truncate max-w-[240px] hover:underline"
          title={item.url}
        >
          {item.url.replace('https://', '')}
        </a>
      </div>

      <p className="text-xs text-slate-300 leading-snug mt-1 border-t border-indigo-500/20 pt-1.5 font-sans">
        {item.desc}
      </p>
    </div>
  )
}

function formatFull(iso) {
  return new Date(iso).toLocaleString('en-US', {
    weekday: 'short', month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
    hour12: false
  })
}

export default function IncidentDetail() {
  const { id } = useParams()
  const navigate = useNavigate()
  const [incident, setIncident] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [isolateState, setIsolateState] = useState('idle') // idle | loading | done | error
  const [exportState, setExportState] = useState('idle') // idle | exporting | success | error

  useEffect(() => {
    getIncidentById(id)
      .then(data => {
        setIncident(data)
        setLoading(false)
      })
      .catch(err => {
        setError(err.message)
        setLoading(false)
      })
  }, [id])

  async function handleIsolate() {
    if (!incident || isolateState !== 'idle') return
    setIsolateState('loading')
    try {
      await isolateHost(incident.host)
      setIsolateState('done')
    } catch {
      setIsolateState('error')
    }
  }

  function handleExportDossier() {
    if (!incident || exportState === 'exporting') return
    setExportState('exporting')
    try {
      downloadIncidentDossier(incident)
      setExportState('success')
      setTimeout(() => setExportState('idle'), 3000)
    } catch (err) {
      console.error('[Sentry] Failed to export incident dossier:', err)
      setExportState('error')
      setTimeout(() => setExportState('idle'), 3500)
    }
  }

  if (loading) {
    return (
      <div className="min-h-screen bg-surface-900 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin w-10 h-10 border-2 border-cyan-500 border-t-transparent rounded-full mx-auto mb-4" />
          <p className="text-slate-500">Loading incident…</p>
        </div>
      </div>
    )
  }

  if (error || !incident) {
    return (
      <div className="min-h-screen bg-surface-900 flex items-center justify-center">
        <div className="glass-card p-8 text-center max-w-md">
          <IconShieldAlert className="w-12 h-12 text-amber-400 mx-auto mb-3" />
          <div className="text-red-400 font-medium mb-2">Incident Not Found</div>
          <div className="text-slate-500 text-sm mb-4">{error || `No incident with ID: ${id}`}</div>
          <button onClick={() => navigate('/')} className="text-cyan-400 hover:text-cyan-300 text-sm transition-colors">
            ← Back to Overview
          </button>
        </div>
      </div>
    )
  }

  const riskPct = Math.round(incident.risk_score * 100)
  const riskColor =
    incident.risk_score >= 0.8 ? 'text-red-400' :
    incident.risk_score >= 0.6 ? 'text-orange-400' :
    incident.risk_score >= 0.4 ? 'text-yellow-400' :
                                  'text-slate-400'

  return (
    <div className="min-h-screen bg-surface-900 flex flex-col">
      {/* Header */}
      <header className="border-b border-white/5 bg-surface-800/60 backdrop-blur-sm sticky top-0 z-20">
        <div className="max-w-screen-xl mx-auto px-6 py-4 flex items-center gap-4">
          <button
            onClick={() => navigate('/')}
            className="text-slate-400 hover:text-white transition-colors flex items-center gap-1.5 text-sm"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
            </svg>
            Overview
          </button>
          <div className="w-px h-4 bg-white/10" />
          <div className="flex items-center gap-2">
            <div className="w-5 h-5 rounded bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center text-xs font-bold text-white">S</div>
            <span className="text-sm text-slate-300 font-medium">Sentry</span>
          </div>
          <span className="text-slate-600">/ Incident Detail</span>
        </div>
      </header>

      <main className="flex-1 max-w-screen-xl mx-auto w-full px-6 py-6 space-y-6 animate-fade-in">
        {/* Incident header card */}
        <div className={`glass-card p-6 ${
          incident.severity === 'critical' ? 'border border-red-500/30 bg-red-950/10' : ''
        }`}>
          <div className="flex flex-col lg:flex-row lg:items-center gap-4 justify-between">
            <div className="flex-1 space-y-3">
              <div className="flex items-center gap-3 flex-wrap">
                <SeverityBadge severity={incident.severity} size="lg" />
                <span className="font-mono text-cyan-400 text-sm">{incident.incident_id}</span>
              </div>

              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div>
                  <div className="text-xs text-slate-500 mb-0.5">Host</div>
                  <div className="text-sm font-medium text-slate-100 font-mono">{incident.host}</div>
                </div>
                <div>
                  <div className="text-xs text-slate-500 mb-0.5">User</div>
                  <div className="text-sm font-medium text-slate-100">{incident.user}</div>
                </div>
                <div>
                  <div className="text-xs text-slate-500 mb-0.5">Detected</div>
                  <div className="text-sm font-mono text-slate-300">{formatFull(incident.created_at)}</div>
                </div>
                <div>
                  <div className="text-xs text-slate-500 mb-0.5">Events Correlated</div>
                  <div className="text-sm font-medium text-slate-100">{incident.correlated_events?.length || 0}</div>
                </div>
              </div>
            </div>

            {/* Risk score + Quick Actions */}
            <div className="flex items-center gap-6 lg:flex-col lg:items-end lg:justify-between">
              <div className="text-center lg:text-right">
                <div className="text-xs text-slate-500 mb-1">Risk Score</div>
                <div className={`text-5xl font-bold font-mono ${riskColor}`}>{riskPct}</div>
                <div className="text-xs text-slate-600">/100</div>
              </div>

              <div className="flex items-center gap-2">
                <button
                  id="print-report-btn"
                  onClick={() => window.print()}
                  title="Print or Save as PDF Incident Report"
                  className="px-3.5 py-2 rounded-lg text-xs font-semibold bg-surface-700/80 hover:bg-surface-700 text-slate-200 hover:text-white border border-white/10 hover:border-cyan-500/50 hover:shadow-cyan-500/10 active:scale-95 transition-all flex items-center gap-2 shadow-sm cursor-pointer"
                >
                  <svg className="w-4 h-4 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 17h2a2 2 0 002-2v-4a2 2 0 00-2-2H5a2 2 0 00-2 2v4a2 2 0 002 2h2m2 4h6a2 2 0 002-2v-4a2 2 0 00-2-2H9a2 2 0 00-2 2v4a2 2 0 002 2zm8-12V5a2 2 0 00-2-2H9a2 2 0 00-2 2v4h10z" />
                  </svg>
                  <span>Save / Print PDF</span>
                </button>

                <button
                  id="export-dossier-btn"
                  onClick={handleExportDossier}
                  disabled={exportState === 'exporting'}
                  title="Download comprehensive forensic JSON dossier"
                  className={`px-3.5 py-2 rounded-lg text-xs font-semibold transition-all flex items-center gap-2 shadow-sm cursor-pointer ${
                    exportState === 'success'
                      ? 'bg-emerald-950/70 border border-emerald-500/60 text-emerald-300 shadow-emerald-500/20 ring-1 ring-emerald-500/40'
                      : exportState === 'error'
                      ? 'bg-red-950/70 border border-red-500/60 text-red-300'
                      : 'bg-surface-700/80 hover:bg-surface-700 text-slate-200 hover:text-white border border-white/10 hover:border-cyan-500/50 hover:shadow-cyan-500/10 active:scale-95'
                  }`}
                >
                  {exportState === 'exporting' ? (
                    <>
                      <div className="w-3.5 h-3.5 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin" />
                      <span>Exporting Dossier…</span>
                    </>
                  ) : exportState === 'success' ? (
                    <>
                      <svg className="w-4 h-4 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M5 13l4 4L19 7" />
                      </svg>
                      <span className="font-semibold text-emerald-300">Dossier Exported (.json)</span>
                    </>
                  ) : exportState === 'error' ? (
                    <>
                      <span className="text-red-400 font-bold font-mono">Failed</span>
                      <span>Export Failed</span>
                    </>
                  ) : (
                    <>
                      <svg className="w-4 h-4 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                      </svg>
                      <span>Export Dossier (JSON)</span>
                    </>
                  )}
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* SOAR Remediation & Response Playbook Console */}
        <RemediationConsole incident={incident} onIncidentUpdate={setIncident} />

        {/* AI Threat Analyst Intelligence Briefing */}
        {incident.ai_analysis && (
          <div className="glass-card p-6 border border-cyan-500/30 bg-gradient-to-br from-indigo-950/30 via-surface-800 to-cyan-950/30 space-y-4 animate-fade-in">
            <div className="flex items-center justify-between border-b border-white/10 pb-3">
              <div className="flex items-center gap-2.5">
                <div className="w-7 h-7 rounded-lg bg-cyan-500/20 border border-cyan-500/40 flex items-center justify-center text-cyan-300">
                  <IconBot className="w-4 h-4" />
                </div>
                <div>
                  <h3 className="text-sm font-bold text-white flex items-center gap-2">
                    <span>AI Threat Analyst Intelligence Briefing</span>
                    <span className="text-[10px] px-2 py-0.5 rounded-full bg-cyan-950 border border-cyan-500/40 text-cyan-300 font-mono">
                      {incident.ai_analysis.ai_engine_mode || 'Sentry AI Reasoner'}
                    </span>
                  </h3>
                  <p className="text-xs text-slate-400">Autonomous Tier-3 forensic reasoning & kill-chain correlation</p>
                </div>
              </div>

              <div className="text-xs text-right">
                <span className="text-slate-400 block text-[10px] uppercase tracking-wider">AI Confidence</span>
                <span className="text-emerald-400 font-bold font-mono text-sm">
                  {Math.round((incident.ai_analysis.ai_confidence || 0.94) * 100)}%
                </span>
              </div>
            </div>

            {/* Grid of Key AI Insights */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <div className="p-3 rounded-xl bg-surface-900/80 border border-white/5 space-y-1">
                <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">Kill Chain Progression</span>
                <div className="text-xs font-bold text-purple-300 flex items-center gap-1.5">
                  <IconTarget className="w-3.5 h-3.5 text-purple-400" />
                  <span>{incident.ai_analysis.kill_chain_stage}</span>
                </div>
              </div>

              <div className="p-3 rounded-xl bg-surface-900/80 border border-white/5 space-y-1">
                <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">Threat Actor Persona</span>
                <div className="text-xs font-bold text-amber-300 flex items-center gap-1.5">
                  <IconUser className="w-3.5 h-3.5 text-amber-400" />
                  <span>{incident.ai_analysis.threat_actor_profile}</span>
                </div>
              </div>

              <div className="p-3 rounded-xl bg-surface-900/80 border border-white/5 space-y-1">
                <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">Estimated Blast Radius</span>
                <div className="text-xs font-bold text-red-300 flex items-center gap-1.5">
                  <IconShieldAlert className="w-3.5 h-3.5 text-red-400" />
                  <span>{incident.ai_analysis.blast_radius}</span>
                </div>
              </div>
            </div>

            {/* AI Executive Forensic Narrative */}
            <div className="p-4 rounded-xl bg-surface-900/90 border border-white/10 space-y-2">
              <div className="text-xs font-semibold text-cyan-400 flex items-center gap-1.5 uppercase tracking-wider">
                <IconAlertCircle className="w-3.5 h-3.5 text-cyan-400" /> Executive Threat Assessment & Intent
              </div>
              <p className="text-sm text-slate-100 leading-relaxed font-medium">
                {incident.ai_analysis.executive_summary}
              </p>
              {incident.ai_analysis.threat_intent && (
                <p className="text-xs text-slate-400 italic">
                  Adversary Objective: {incident.ai_analysis.threat_intent}
                </p>
              )}
            </div>

            {/* Prescribed Containment Actions */}
            {incident.ai_analysis.recommended_actions?.length > 0 && (
              <div className="space-y-1.5">
                <span className="text-xs text-slate-400 font-semibold uppercase tracking-wider block">
                  AI Prescribed Containment Playbook
                </span>
                <div className="flex flex-wrap gap-2">
                  {incident.ai_analysis.recommended_actions.map((act, i) => (
                    <span key={i} className="px-2.5 py-1 rounded-lg bg-emerald-950/70 border border-emerald-500/40 text-emerald-300 text-xs font-medium flex items-center gap-1.5">
                      <IconZap className="w-3.5 h-3.5 text-emerald-400" /> {act}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Why flagged — explanation + MITRE */}
        <div className="glass-card p-5 space-y-4">
          <h3 className="text-sm font-semibold text-slate-200 uppercase tracking-wider">Why This Was Flagged</h3>

          <div className="p-4 rounded-lg bg-surface-700/50 border border-white/5">
            <p className="text-sm text-slate-200 leading-relaxed">{incident.explanation}</p>
          </div>

          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                MITRE ATT&CK Techniques & Threat Taxonomy
              </span>
              <span className="text-[11px] text-indigo-400 font-mono">
                Click technique to view official MITRE framework docs ↗
              </span>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {incident.mitre_techniques?.map((t, idx) => {
                const code = typeof t === 'string' ? t : (t?.mitre_id || t?.technique || `T-${idx}`)
                return <MitreTag key={code + '-' + idx} technique={t} index={idx} />
              })}
            </div>
          </div>
        </div>

        {/* Two-column: risk breakdown + timeline */}
        <div className="grid grid-cols-1 xl:grid-cols-[380px_1fr] gap-6">
          <RiskScoreBreakdown incident={incident} />
          <EvidenceTimeline events={incident.correlated_events || []} />
        </div>
      </main>

      <footer className="border-t border-white/5 px-6 py-3">
        <div className="max-w-screen-xl mx-auto flex items-center justify-between text-xs text-slate-600">
          <span>Sentry — Real-Time Threat Detection</span>
          <span className="font-mono">PS19 · Rohan's Track</span>
        </div>
      </footer>
    </div>
  )
}
