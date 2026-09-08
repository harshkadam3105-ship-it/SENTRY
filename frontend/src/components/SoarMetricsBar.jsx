/**
 * SoarMetricsBar — Automation & Response Performance KPI Bar
 * Directly inspired by the enterprise SOAR Automation ROI summary (Reference Image 3):
 * Highlights MTTD, MTTR, automated containment efficiency, and dwell time reduction.
 */

export default function SoarMetricsBar({ incidents = [] }) {
  const activeCount = incidents.filter(i => i.status !== 'resolved').length
  const criticalCount = incidents.filter(i => i.severity === 'critical').length

  const metrics = [
    {
      label: 'Mean Time to Detect (MTTD)',
      value: '1.2m',
      sub: 'vs 4.5m baseline',
      icon: '⏱️',
      color: 'text-cyan-400',
    },
    {
      label: 'Mean Time to Remediate (MTTR)',
      value: '38s',
      sub: '-88% automated dwell',
      icon: '⚡',
      color: 'text-green-400',
    },
    {
      label: 'Automated Defense Rate',
      value: '92.4%',
      sub: 'Playbook success rate',
      icon: '🤖',
      color: 'text-cyan-300',
    },
    {
      label: 'Active Threat Containment',
      value: `${criticalCount} / ${activeCount}`,
      sub: 'Critical under response',
      icon: '🛡️',
      color: criticalCount > 0 ? 'text-red-400' : 'text-slate-300',
    },
    {
      label: 'Protected Fleet Assets',
      value: '24 hosts',
      sub: '0 compromised bridges',
      icon: '💻',
      color: 'text-indigo-300',
    },
  ]

  return (
    <div className="glass-card p-3.5 border border-cyan-500/15 shadow-lg shadow-cyan-500/5">
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-3 divide-y md:divide-y-0 md:divide-x divide-white/5">
        {metrics.map((m, idx) => (
          <div key={m.label} className={`flex items-center gap-3 ${idx !== 0 ? 'pt-2 md:pt-0 md:pl-4' : ''}`}>
            <span className="text-xl flex-shrink-0 opacity-80">{m.icon}</span>
            <div className="min-w-0">
              <div className="text-[11px] text-slate-400 uppercase tracking-tight truncate font-medium">
                {m.label}
              </div>
              <div className="flex items-baseline gap-2 mt-0.5">
                <span className={`text-base font-bold font-mono ${m.color} leading-none`}>
                  {m.value}
                </span>
                <span className="text-[10px] text-slate-500 truncate font-mono">
                  {m.sub}
                </span>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
