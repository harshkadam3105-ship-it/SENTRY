/**
 * RiskScoreBreakdown — visual breakdown of risk score components
 */

const COMPONENTS = [
  { key: 'anomaly_score', label: 'Anomaly Score', description: 'ML anomaly detection confidence', icon: '🧠' },
  { key: 'rule_score',    label: 'Rule Match',     description: 'Signature & rule-based detection', icon: '📋' },
]

function ScoreBar({ value, label, description, icon }) {
  const pct = Math.round((value || 0) * 100)
  const color =
    value >= 0.8 ? 'from-red-600 via-red-500 to-red-400' :
    value >= 0.6 ? 'from-orange-600 via-orange-500 to-orange-400' :
    value >= 0.4 ? 'from-yellow-600 via-yellow-500 to-yellow-400' :
                   'from-slate-600 via-slate-500 to-slate-400'

  const textColor =
    value >= 0.8 ? 'text-red-400' :
    value >= 0.6 ? 'text-orange-400' :
    value >= 0.4 ? 'text-yellow-400' :
                   'text-slate-400'

  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="text-sm">{icon}</span>
          <span className="text-sm font-medium text-slate-200">{label}</span>
        </div>
        <div className="flex items-center gap-2">
          <span className={`text-sm font-bold font-mono ${textColor}`}>
            {pct}<span className="text-xs font-normal text-slate-500">/100</span>
          </span>
        </div>
      </div>
      <div className="risk-bar-track">
        <div
          className={`risk-bar-fill bg-gradient-to-r ${color}`}
          style={{ width: `${pct}%` }}
        />
      </div>
      <p className="text-xs text-slate-500">{description}</p>
    </div>
  )
}

function SeverityScore({ severity }) {
  const map = { critical: 1.0, high: 0.75, medium: 0.5, low: 0.25 }
  const value = map[severity] || 0
  return <ScoreBar value={value} label="Severity Weight" description="Classification severity multiplier" icon="⚡" />
}

function CorrelationScore({ eventCount }) {
  const value = Math.min(1, eventCount / 5)
  return <ScoreBar value={value} label="Correlation Depth" description={`${eventCount} correlated event${eventCount !== 1 ? 's' : ''} linked`} icon="🔗" />
}

export default function RiskScoreBreakdown({ incident }) {
  if (!incident) return null

  const events = incident.correlated_events || []
  // Average scores across correlated events
  const avgAnomaly = events.length
    ? events.reduce((s, e) => s + (e.anomaly_score || 0), 0) / events.length
    : 0
  const avgRule = events.length
    ? events.reduce((s, e) => s + (e.rule_score || 0), 0) / events.length
    : 0

  const overallPct = Math.round(incident.risk_score * 100)
  const overallColor =
    incident.risk_score >= 0.8 ? 'text-red-400' :
    incident.risk_score >= 0.6 ? 'text-orange-400' :
    incident.risk_score >= 0.4 ? 'text-yellow-400' :
                                  'text-slate-400'

  return (
    <div className="glass-card p-5 space-y-5">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold text-slate-200 uppercase tracking-wider">Risk Score Breakdown</h3>
        <div className="flex items-center gap-1">
          <span className={`text-2xl font-bold font-mono ${overallColor}`}>{overallPct}</span>
          <span className="text-slate-500 text-sm">/100</span>
        </div>
      </div>

      {/* Overall bar */}
      <div className="risk-bar-track h-3">
        <div
          className={`risk-bar-fill h-full bg-gradient-to-r ${
            incident.risk_score >= 0.8 ? 'from-red-800 via-red-600 to-red-400' :
            incident.risk_score >= 0.6 ? 'from-orange-800 via-orange-600 to-orange-400' :
            incident.risk_score >= 0.4 ? 'from-yellow-800 via-yellow-600 to-yellow-400' :
                                          'from-slate-700 via-slate-600 to-slate-400'
          }`}
          style={{ width: `${overallPct}%` }}
        />
      </div>

      <div className="border-t border-white/5 pt-4 space-y-4">
        <ScoreBar value={avgAnomaly} label="Anomaly Score" description="ML anomaly detection confidence (avg across events)" icon="🧠" />
        <ScoreBar value={avgRule}    label="Rule Match Score" description="Signature & rule-based detection (avg across events)" icon="📋" />
        <SeverityScore severity={incident.severity} />
        <CorrelationScore eventCount={events.length} />
      </div>

      <div className="text-xs text-slate-600 border-t border-white/5 pt-3">
        Final score is a weighted composite of the above components.
      </div>
    </div>
  )
}
