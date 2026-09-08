import { useState, useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import SeverityBadge from '../components/SeverityBadge'
import RiskScoreBreakdown from '../components/RiskScoreBreakdown'
import EvidenceTimeline from '../components/EvidenceTimeline'
import RemediationConsole from '../components/RemediationConsole'
import BlastRadiusGraph from '../components/BlastRadiusGraph'
import {
  getIncidentById,
  downloadIncidentDossier,
  getIncidentAiAnalysis,
} from '../api/incidents'


/**
 * IncidentDetail — Tier-2 SOC Analyst Investigation Console.
 * Clear information hierarchy answering:
 * 1. What happened? (Detection summary & risk score)
 * 2. Why is it suspicious? (ML anomaly attribution & MITRE mapping)
 * 3. Who/what is affected? (Entity context: host & user identity)
 * 4. What evidence supports it? (Correlated event timeline)
 * 5. What can I do? (Operational SOAR playbooks & forensic export)
 */

function MitreTag({ technique }) {
  const code =
    typeof technique === 'string'
      ? technique
      : technique?.mitre_id || technique?.technique || String(technique)

  const labels = {
    T1110: 'Brute Force',
    T1078: 'Valid Accounts',
    T1021: 'Remote Services',
    T1048: 'Exfil over C2',
    T1567: 'Exfil over Web',
    T1059: 'Command Scripting',
    T1136: 'Create Account',
    T1098: 'Account Manipulation',
    T1071: 'Application Layer Protocol',
    T1003: 'Credential Dumping',
    T1083: 'File & Dir Discovery',
    T1005: 'Data from Local System',
  }
  const displayLabel =
    typeof technique === 'object' && technique?.technique
      ? technique.technique
      : labels[code]

  return (
    <a
      href={`https://attack.mitre.org/techniques/${code}/`}
      target="_blank"
      rel="noopener noreferrer"
      className="mitre-tag hover:border-slate-500 transition-colors flex items-center gap-1.5"
    >
      <span className="font-semibold text-slate-200">{code}</span>
      {displayLabel && <span className="text-slate-400">· {displayLabel}</span>}
      <svg className="w-2.5 h-2.5 text-slate-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" />
        <polyline points="15 3 21 3 21 9" />
        <line x1="10" y1="14" x2="21" y2="3" />
      </svg>
    </a>
  )
}

function formatFull(iso) {
  if (!iso) return '--:--:--'
  const d = new Date(iso)
  return d.toLocaleString('en-US', {
    weekday: 'short',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  })
}

export default function IncidentDetail() {
  const { id } = useParams()
  const navigate = useNavigate()
  const [incident, setIncident] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [exportState, setExportState] = useState('idle') // idle | exporting | success | error
  const [aiAnalysis, setAiAnalysis] = useState(null)

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

    getIncidentAiAnalysis(id)
      .then(data => setAiAnalysis(data))
      .catch(() => {})
  }, [id])

  function handleExportDossier() {
    if (!incident || exportState === 'exporting') return
    setExportState('exporting')
    try {
      downloadIncidentDossier(incident)
      setExportState('success')
      setTimeout(() => setExportState('idle'), 3000)
    } catch (err) {
      console.error('[Sentry] Failed to export dossier:', err)
      setExportState('error')
      setTimeout(() => setExportState('idle'), 3500)
    }
  }

  if (loading) {
    return (
      <div className="min-h-screen bg-[#080c14] flex items-center justify-center font-mono text-xs text-slate-400">
        <div className="text-center space-y-2">
          <div className="animate-spin w-6 h-6 border-2 border-slate-400 border-t-transparent rounded-full mx-auto" />
          <p>Loading incident investigation workspace…</p>
        </div>
      </div>
    )
  }

  if (error || !incident) {
    return (
      <div className="min-h-screen bg-[#080c14] flex items-center justify-center p-4">
        <div className="soc-panel p-6 text-center max-w-md w-full space-y-3">
          <div className="text-red-400 font-bold text-sm">Incident Not Found</div>
          <div className="text-slate-500 text-xs font-mono">{error || `No record for ${id}`}</div>
          <button
            onClick={() => navigate('/')}
            className="px-3 py-1.5 text-xs font-mono rounded bg-slate-800 text-slate-200 hover:bg-slate-700 transition-colors"
          >
            ← Return to Incident Queue
          </button>
        </div>
      </div>
    )
  }

  const riskPct = Math.round((incident.risk_score || 0) * 100)
  const riskColor =
    incident.risk_score >= 0.8
      ? 'text-red-400'
      : incident.risk_score >= 0.6
      ? 'text-orange-400'
      : incident.risk_score >= 0.4
      ? 'text-amber-400'
      : 'text-slate-300'

  return (
    <div className="min-h-screen bg-[#080c14] text-slate-200 flex flex-col antialiased">
      {/* Top Breadcrumb Nav */}
      <header className="border-b border-slate-800 bg-[#0a0e18] sticky top-0 z-30 shrink-0">
        <div className="max-w-[1680px] mx-auto px-4 py-2.5 flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <button
              onClick={() => navigate('/')}
              className="text-slate-400 hover:text-white transition-colors flex items-center gap-1.5 text-xs font-mono"
            >
              <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <polyline points="15 18 9 12 15 6" />
              </svg>
              Queue
            </button>
            <span className="text-slate-600 font-mono">/</span>
            <span className="font-mono text-xs font-semibold text-slate-200">
              {incident.incident_id}
            </span>
          </div>

          <div className="flex items-center gap-3">
            {/* Export Forensic Dossier Button */}
            <button
              onClick={handleExportDossier}
              disabled={exportState === 'exporting'}
              className={`px-3 py-1 rounded text-xs font-mono font-medium transition-colors flex items-center gap-1.5 ${
                exportState === 'success'
                  ? 'bg-emerald-950 text-emerald-300 border border-emerald-500/40'
                  : exportState === 'error'
                  ? 'bg-red-950 text-red-300 border border-red-500/40'
                  : 'bg-slate-850 hover:bg-slate-750 text-slate-200 border border-slate-700'
              }`}
            >
              {exportState === 'exporting' ? (
                <>
                  <span className="w-2.5 h-2.5 border-2 border-slate-400 border-t-transparent rounded-full animate-spin" />
                  Generating Dossier…
                </>
              ) : exportState === 'success' ? (
                <>
                  <svg className="w-3.5 h-3.5 text-emerald-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                    <polyline points="20 6 9 17 4 12" />
                  </svg>
                  Dossier Exported (.json)
                </>
              ) : (
                <>
                  <svg className="w-3.5 h-3.5 text-slate-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                    <polyline points="7 10 12 15 17 10" />
                    <line x1="12" y1="15" x2="12" y2="3" />
                  </svg>
                  Export Forensic Dossier (JSON)
                </>
              )}
            </button>
          </div>
        </div>
      </header>

      {/* Main Workspace */}
      <main className="flex-1 max-w-[1680px] mx-auto w-full p-4 flex flex-col gap-4">
        {/* 1. Incident Overview Header Card */}
        <div
          className={`soc-panel p-4 flex flex-col lg:flex-row lg:items-center justify-between gap-4 ${
            incident.severity === 'critical' ? 'border-l-4 border-l-red-500' : ''
          }`}
        >
          <div className="flex-1 space-y-2.5">
            <div className="flex items-center gap-2.5 flex-wrap">
              <SeverityBadge severity={incident.severity} size="lg" />
              <span className="font-mono text-sm font-bold text-slate-100">
                {incident.incident_id}
              </span>
              <span className="text-slate-600 font-mono">•</span>
              <span className="text-xs text-slate-400 font-mono">
                Detected: {formatFull(incident.created_at)}
              </span>
            </div>

            {/* Affected User & Host Context Strip */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-1 text-xs">
              <div>
                <div className="text-[10px] uppercase font-semibold text-slate-500 font-mono">
                  Affected Host
                </div>
                <div className="font-mono font-medium text-slate-200 mt-0.5">
                  {incident.host}
                </div>
              </div>
              <div>
                <div className="text-[10px] uppercase font-semibold text-slate-500 font-mono">
                  Identity / Account
                </div>
                <div className="font-mono font-medium text-slate-200 mt-0.5">
                  {incident.user}
                </div>
              </div>
              <div>
                <div className="text-[10px] uppercase font-semibold text-slate-500 font-mono">
                  Events Correlated
                </div>
                <div className="font-mono font-medium text-slate-200 mt-0.5">
                  {incident.correlated_events?.length || 0} events
                </div>
              </div>
              <div>
                <div className="text-[10px] uppercase font-semibold text-slate-500 font-mono">
                  Status
                </div>
                <div className="font-mono font-medium text-slate-200 mt-0.5 uppercase">
                  {incident.status || 'open'}
                </div>
              </div>
            </div>
          </div>

          {/* Risk Score Pill */}
          <div className="flex items-center gap-4 lg:border-l lg:border-slate-800 lg:pl-6 shrink-0">
            <div className="text-left lg:text-right">
              <div className="text-[10px] uppercase font-semibold text-slate-500 font-mono">
                Threat Score
              </div>
              <div className={`text-4xl font-bold font-mono ${riskColor} leading-none mt-0.5`}>
                {riskPct}
                <span className="text-xs font-normal text-slate-500"> / 100</span>
              </div>
            </div>
          </div>
        </div>

        {/* 2. Interactive Attack Vector Topology & Blast Radius Graph */}
        <BlastRadiusGraph incident={incident} />

        {/* 3. What Happened & Detection Reason */}
        <div className="soc-panel p-4 space-y-3">
          <div className="flex items-center gap-2 border-b border-slate-800 pb-2">
            <div className="p-1 rounded bg-slate-850 border border-slate-800 text-slate-400">
              <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="12" cy="12" r="10" />
                <line x1="12" y1="16" x2="12" y2="12" />
                <line x1="12" y1="8" x2="12.01" y2="8" />
              </svg>
            </div>
            <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider">
              Detection Hypothesis & Threat Verdict
            </h3>
          </div>

          <div className="p-3 rounded bg-slate-900/70 border border-slate-800/80 text-xs text-slate-200 leading-relaxed font-sans">
            {incident.explanation || 'Multi-stage correlated attack vector flagged by real-time detection pipeline.'}
          </div>

          {/* MITRE Mapping */}
          <div>
            <div className="text-[10px] uppercase font-semibold text-slate-400 font-mono mb-1.5">
              Mapped MITRE ATT&CK Techniques
            </div>
            <div className="flex flex-wrap gap-1.5">
              {(incident.mitre_techniques || []).map((t, idx) => {
                const code =
                  typeof t === 'string'
                    ? t
                    : t?.mitre_id || t?.technique || `T-${idx}`
                return <MitreTag key={code} technique={t} />
              })}
            </div>
          </div>
        </div>

        {/* 3. Operational SOAR Remediation Console */}
        <RemediationConsole incident={incident} onIncidentUpdate={setIncident} />

        {/* 4. AI Threat Attribution & Kill Chain Progression */}
        {aiAnalysis && (
          <div className="soc-panel p-4 space-y-3">
            <div className="flex items-center justify-between border-b border-slate-800 pb-2">
              <div className="flex items-center gap-2">
                <div className="p-1 rounded bg-slate-850 border border-slate-800 text-slate-400">
                  <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <rect x="2" y="2" width="20" height="8" rx="2" ry="2" />
                    <rect x="2" y="14" width="20" height="8" rx="2" ry="2" />
                    <line x1="6" y1="6" x2="6.01" y2="6" />
                    <line x1="6" y1="18" x2="6.01" y2="18" />
                  </svg>
                </div>
                <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider">
                  ML Anomaly Attribution & Kill Chain Progression
                </h3>
              </div>
              <span className="text-[10px] font-mono text-slate-400 bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
                Confidence: {aiAnalysis.ai_confidence_score || '97.2%'}
              </span>
            </div>

            {/* Kill Chain Steps */}
            <div className="p-3 rounded bg-slate-900/60 border border-slate-800/80 space-y-2 text-xs">
              <div className="flex items-center justify-between">
                <span className="text-slate-400 font-mono text-[11px]">Kill Chain Phase:</span>
                <span className="font-mono font-semibold text-slate-200">
                  {aiAnalysis.predicted_kill_chain_phase || 'Execution & Persistence'} (Step {aiAnalysis.kill_chain_step || 4} of 6)
                </span>
              </div>
              <div className="grid grid-cols-6 gap-1.5 h-1.5">
                {[1, 2, 3, 4, 5, 6].map(step => (
                  <div
                    key={step}
                    className={`rounded ${
                      step <= (aiAnalysis.kill_chain_step || 4)
                        ? 'bg-blue-500'
                        : 'bg-slate-800'
                    }`}
                  />
                ))}
              </div>
            </div>

            {/* Anomaly Factors */}
            {aiAnalysis.top_anomaly_factors && aiAnalysis.top_anomaly_factors.length > 0 && (
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-xs">
                {aiAnalysis.top_anomaly_factors.map((feat, idx) => (
                  <div
                    key={idx}
                    className="p-2.5 rounded bg-slate-900 border border-slate-800 font-mono space-y-1"
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-slate-300 font-medium truncate">{feat.feature}</span>
                      <span className="text-[10px] font-bold text-red-400">
                        +{feat.deviation_multiplier}
                      </span>
                    </div>
                    <div className="flex items-center justify-between text-[10px] text-slate-500">
                      <span>Obs: {feat.observed_value}</span>
                      <span>Base: {feat.baseline_mean}</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* 5. Two-Column Layout: Risk Breakdown + Forensic Evidence Timeline */}
        <div className="grid grid-cols-1 xl:grid-cols-[380px_1fr] gap-4">
          <RiskScoreBreakdown incident={incident} />
          <EvidenceTimeline events={incident.correlated_events || []} />
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800 bg-[#090d16] px-4 py-2 mt-auto shrink-0">
        <div className="max-w-[1680px] mx-auto flex items-center justify-between text-[11px] text-slate-500 font-mono">
          <span>SENTRY Forensics & DFIR Console</span>
          <span>TLP:AMBER+STRICT · Case ID {incident.incident_id}</span>
        </div>
      </footer>
    </div>
  )
}
