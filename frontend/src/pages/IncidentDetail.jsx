import { useState, useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import SeverityBadge from '../components/SeverityBadge'
import RiskScoreBreakdown from '../components/RiskScoreBreakdown'
import EvidenceTimeline from '../components/EvidenceTimeline'
import { getIncidentById, isolateHost } from '../api/incidents'

/**
 * IncidentDetail — deep-dive view for a single incident
 */

function MitreTag({ technique }) {
  // Map common techniques to labels
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
  return (
    <a
      href={`https://attack.mitre.org/techniques/${technique}/`}
      target="_blank"
      rel="noopener noreferrer"
      className="mitre-tag hover:bg-indigo-900/40 transition-colors flex items-center gap-1"
    >
      <span>{technique}</span>
      {labels[technique] && <span className="text-indigo-400 opacity-70">· {labels[technique]}</span>}
    </a>
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
          <div className="text-4xl mb-3">⚠️</div>
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
            <span className="text-sm text-slate-300 font-medium">SentinelX</span>
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

            {/* Risk score + Isolate button */}
            <div className="flex items-center gap-6 lg:flex-col lg:items-end">
              <div className="text-center">
                <div className="text-xs text-slate-500 mb-1">Risk Score</div>
                <div className={`text-5xl font-bold font-mono ${riskColor}`}>{riskPct}</div>
                <div className="text-xs text-slate-600">/100</div>
              </div>

              <button
                onClick={handleIsolate}
                disabled={isolateState !== 'idle'}
                className={`
                  px-4 py-2 rounded-lg text-sm font-semibold transition-all duration-200
                  ${isolateState === 'done'
                    ? 'bg-green-900/40 text-green-400 border border-green-500/30 cursor-default'
                    : isolateState === 'error'
                    ? 'bg-red-900/40 text-red-400 border border-red-500/30 cursor-default'
                    : isolateState === 'loading'
                    ? 'bg-orange-900/40 text-orange-400 border border-orange-500/30 cursor-wait animate-pulse'
                    : 'bg-red-950/60 text-red-300 border border-red-500/40 hover:bg-red-950 hover:border-red-400/60 hover:text-red-200 active:scale-95'
                  }
                `}
              >
                {isolateState === 'done' ? '✓ Host Isolated' :
                 isolateState === 'error' ? '✗ Isolate Failed' :
                 isolateState === 'loading' ? 'Isolating…' :
                 '🔒 Isolate Host'}
              </button>
            </div>
          </div>
        </div>

        {/* Why flagged — explanation + MITRE */}
        <div className="glass-card p-5 space-y-4">
          <h3 className="text-sm font-semibold text-slate-200 uppercase tracking-wider">Why This Was Flagged</h3>

          <div className="p-4 rounded-lg bg-surface-700/50 border border-white/5">
            <p className="text-sm text-slate-200 leading-relaxed">{incident.explanation}</p>
          </div>

          <div>
            <div className="text-xs text-slate-500 mb-2 uppercase tracking-wider">MITRE ATT&CK Techniques</div>
            <div className="flex flex-wrap gap-2">
              {incident.mitre_techniques?.map(t => (
                <MitreTag key={t} technique={t} />
              ))}
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
          <span>SentinelX — Real-Time Threat Detection</span>
          <span className="font-mono">PS19 · Rohan's Track</span>
        </div>
      </footer>
    </div>
  )
}
