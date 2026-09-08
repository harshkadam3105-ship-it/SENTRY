/**
 * RiskScoreBreakdown — 4-Factor Composite Risk Decomposition Panel.
 * Decomposes incident threat score into ML Anomaly, Rule Signatures, Severity, and Correlation Depth.
 */

function ScoreBar({ value, label, description, iconSvg }) {
  const pct = Math.round((value || 0) * 100)
  const barColor =
    value >= 0.8
      ? 'bg-red-500'
      : value >= 0.6
      ? 'bg-orange-500'
      : value >= 0.4
      ? 'bg-amber-400'
      : 'bg-slate-500'

  const textColor =
    value >= 0.8
      ? 'text-red-400'
      : value >= 0.6
      ? 'text-orange-400'
      : value >= 0.4
      ? 'text-amber-400'
      : 'text-slate-300'

  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          {iconSvg}
          <span className="text-xs font-semibold text-slate-200 uppercase tracking-wide">
            {label}
          </span>
        </div>
        <span className={`text-xs font-bold font-mono ${textColor}`}>
          {pct}
          <span className="text-[10px] font-normal text-slate-500"> / 100</span>
        </span>
      </div>
      <div className="w-full h-1.5 rounded bg-slate-800 overflow-hidden">
        <div className={`h-full rounded ${barColor}`} style={{ width: `${pct}%` }} />
      </div>
      <p className="text-[11px] text-slate-500">{description}</p>
    </div>
  )
}

function SeverityScore({ severity }) {
  const map = { critical: 1.0, high: 0.75, medium: 0.5, low: 0.25 }
  const value = map[severity] || 0
  return (
    <ScoreBar
      value={value}
      label="Severity Weight"
      description="Classification tier multiplier (Level 1–5)"
      iconSvg={
        <svg className="w-3.5 h-3.5 text-slate-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" />
        </svg>
      }
    />
  )
}

function CorrelationScore({ eventCount }) {
  const value = Math.min(1, eventCount / 5)
  return (
    <ScoreBar
      value={value}
      label="Correlation Depth"
      description={`${eventCount} correlated event${eventCount !== 1 ? 's' : ''} in sliding window`}
      iconSvg={
        <svg className="w-3.5 h-3.5 text-slate-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <circle cx="6" cy="6" r="3" />
          <circle cx="18" cy="18" r="3" />
          <line x1="8.59" y1="8.59" x2="15.42" y2="15.42" />
        </svg>
      }
    />
  )
}

export default function RiskScoreBreakdown({ incident }) {
  if (!incident) return null

  const events = incident.correlated_events || []
  const avgAnomaly = events.length
    ? events.reduce((s, e) => s + (e.anomaly_score || 0), 0) / events.length
    : (incident.risk_score || 0.5)
  const avgRule = events.length
    ? events.reduce((s, e) => s + (e.rule_score || 0), 0) / events.length
    : (incident.risk_score || 0.5)

  const overallPct = Math.round((incident.risk_score || 0) * 100)
  const overallColor =
    incident.risk_score >= 0.8
      ? 'text-red-400'
      : incident.risk_score >= 0.6
      ? 'text-orange-400'
      : incident.risk_score >= 0.4
      ? 'text-amber-400'
      : 'text-slate-300'

  return (
    <div className="soc-panel p-5 space-y-4">
      <div className="flex items-center justify-between border-b border-slate-800 pb-3">
        <div className="flex items-center gap-2">
          <div className="p-1 rounded bg-slate-850 border border-slate-800 text-slate-300">
            <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="12" cy="12" r="10" />
              <polyline points="12 6 12 12 14 14" />
            </svg>
          </div>
          <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider">
            Risk Score Decomposition
          </h3>
        </div>
        <div className="flex items-baseline gap-1">
          <span className={`text-2xl font-bold font-mono ${overallColor}`}>
            {overallPct}
          </span>
          <span className="text-slate-500 text-xs font-mono">/100</span>
        </div>
      </div>

      {/* Main Bar */}
      <div className="w-full h-2 rounded bg-slate-800 overflow-hidden">
        <div
          className={`h-full rounded ${
            incident.risk_score >= 0.8
              ? 'bg-red-500'
              : incident.risk_score >= 0.6
              ? 'bg-orange-500'
              : incident.risk_score >= 0.4
              ? 'bg-amber-400'
              : 'bg-slate-500'
          }`}
          style={{ width: `${overallPct}%` }}
        />
      </div>

      <div className="pt-2 space-y-3.5">
        <ScoreBar
          value={avgAnomaly}
          label="Anomaly Weight"
          description="Isolation Forest ML anomaly feature deviation"
          iconSvg={
            <svg className="w-3.5 h-3.5 text-slate-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <rect x="2" y="2" width="20" height="8" rx="2" ry="2" />
              <rect x="2" y="14" width="20" height="8" rx="2" ry="2" />
              <line x1="6" y1="6" x2="6.01" y2="6" />
              <line x1="6" y1="18" x2="6.01" y2="18" />
            </svg>
          }
        />
        <ScoreBar
          value={avgRule}
          label="Signature Match"
          description="Deterministic MITRE pattern rules triggered"
          iconSvg={
            <svg className="w-3.5 h-3.5 text-slate-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
              <polyline points="14 2 14 8 20 8" />
              <line x1="16" y1="13" x2="8" y2="13" />
              <line x1="16" y1="17" x2="8" y2="17" />
              <polyline points="10 9 9 9 8 9" />
            </svg>
          }
        />
        <SeverityScore severity={incident.severity} />
        <CorrelationScore eventCount={events.length} />
      </div>

      <div className="text-[10px] text-slate-500 border-t border-slate-800 pt-2.5 font-mono">
        Aggregated using weighted formula (Anomaly 35% + Rules 35% + Correlation 20% + Severity 10%)
      </div>
    </div>
  )
}
