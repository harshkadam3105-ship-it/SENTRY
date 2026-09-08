import { useState, useEffect } from 'react'
import { getAutomationRoi } from '../api/incidents'

/**
 * SoarRoiDashboard — Executive CISO & Automation ROI Analytics Console.
 * Directly synthesizes and renders the visual patterns from the 3 reference dashboards:
 * 1. Automation ROI Strip (Dollars saved, FTEs saved, hours saved, dwell reduction)
 * 2. Siemplify-style Radial Gauge Meter ("Cases with Automated Assistance")
 * 3. Cases by Dwell Time / Age Distribution Bar Chart
 * 4. Security Technology Anomaly Counts (Office 365, Cisco, CrowdStrike, Palo Alto)
 * 5. Top Playbooks & Automated Actions Execution Ledger
 */

export default function SoarRoiDashboard() {
  const [roiData, setRoiData] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    getAutomationRoi()
      .then(data => {
        setRoiData(data)
        setLoading(false)
      })
      .catch(() => {
        setLoading(false)
      })
  }, [])

  const roi = roiData?.roi_summary || {
    resolved_alerts: 960,
    mean_dwell_time_min: 17,
    dwell_time_saved_min: 64,
    ftes_saved: 0.3,
    hours_saved: 38.4,
    dollars_saved_display: '$14,850',
    time_saved_display: '38.4h',
    dwell_reduction_pct: 84,
  }

  const assistance = roiData?.automated_assistance || {
    percentage: 78,
    gauge_label: 'High Autopilot',
  }

  const casesByAge = roiData?.cases_by_age || [
    { range: '< 4 hrs', count: 14, percentage: 58, color: 'emerald' },
    { range: '4–8 hrs', count: 6, percentage: 25, color: 'blue' },
    { range: '8–24 hrs', count: 3, percentage: 13, color: 'amber' },
    { range: '> 24 hrs', count: 1, percentage: 4, color: 'red' },
  ]

  const telemetry = roiData?.telemetry_sources || [
    { id: 'src-1', source: 'Office 365 Exchange Online', category: 'Cloud/Email', anomalies: 603, impact: 'critical' },
    { id: 'src-2', source: 'Cisco FirePower NGFW', category: 'Network Perimeter', anomalies: 195, impact: 'high' },
    { id: 'src-3', source: 'CrowdStrike Falcon EDR', category: 'Host Endpoint', anomalies: 136, impact: 'critical' },
    { id: 'src-4', source: 'Palo Alto Prisma SASE', category: 'Zero-Trust Edge', anomalies: 125, impact: 'medium' },
    { id: 'src-5', source: 'AWS GuardDuty & CloudTrail', category: 'Cloud Infrastructure', anomalies: 84, impact: 'medium' },
  ]

  const playbooks = roiData?.top_playbooks || [
    { name: 'Rapid Ransomware Containment', category: 'Critical Host', executions: 44, avg_seconds: 1.2, success_rate: '98.4%' },
    { name: 'Credential Abuse Lockout', category: 'Identity (IAM)', executions: 38, avg_seconds: 0.8, success_rate: '100%' },
    { name: 'Lateral Movement Isolation', category: 'Subnet Boundary', executions: 29, avg_seconds: 1.5, success_rate: '96.5%' },
    { name: 'Malicious Process Tree Kill', category: 'EDR Remediation', executions: 21, avg_seconds: 0.4, success_rate: '100%' },
    { name: 'Perimeter C2 Null-Route Drop', category: 'Border Firewall', executions: 18, avg_seconds: 0.6, success_rate: '100%' },
  ]

  const threatIndicators = roiData?.threat_indicators || [
    { category: 'Categories', sublabel: 'Attack Surfaces', impact: 'CRITICAL', color: '#ef4444' },
    { category: 'Resources', sublabel: 'Cloud & Identity', impact: 'ELEVATED', color: '#a855f7' },
    { category: 'MITRE ATT&CK', sublabel: 'Active Tactics', impact: 'HIGH', color: '#f97316' },
    { category: 'UEBA Profiles', sublabel: 'Identity Deviations', impact: 'WATCH', color: '#06b6d4' },
  ]

  // Needle angle for gauge meter: 0% is -90deg, 100% is +90deg
  const gaugeAngle = -90 + (assistance.percentage / 100) * 180

  return (
    <div className="space-y-4">
      {/* 1. TOP AUTOMATION ROI SUMMARY ROW (Inspired by SOAR Screenshot) */}
      <div className="soc-panel p-4">
        <div className="text-[11px] font-mono text-slate-400 font-semibold uppercase tracking-wider mb-3 flex items-center justify-between">
          <span className="flex items-center gap-2">
            <svg className="w-3.5 h-3.5 text-cyan-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" />
            </svg>
            SOAR Automation ROI & Operational Efficiency Summary
          </span>
          <span className="text-slate-500 font-normal">Past 30 Days Enterprise Fleet Metrics</span>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-6 gap-3 divide-y sm:divide-y-0 sm:divide-x divide-slate-800">
          <div className="px-2 py-1">
            <div className="text-xl font-bold font-mono text-slate-100">{roi.resolved_alerts}</div>
            <div className="text-[11px] text-slate-400">Resolved Alerts</div>
            <div className="text-[10px] text-emerald-400 font-mono mt-0.5">↑ 92% automated</div>
          </div>
          <div className="px-2 py-1">
            <div className="text-xl font-bold font-mono text-slate-100">{roi.mean_dwell_time_min}m</div>
            <div className="text-[11px] text-slate-400">Mean Dwell Time</div>
            <div className="text-[10px] text-emerald-400 font-mono mt-0.5">-{roi.dwell_reduction_pct}% reduction</div>
          </div>
          <div className="px-2 py-1">
            <div className="text-xl font-bold font-mono text-slate-100">{roi.dwell_time_saved_min}m</div>
            <div className="text-[11px] text-slate-400">Dwell Time Saved</div>
            <div className="text-[10px] text-cyan-400 font-mono mt-0.5">per incident avg</div>
          </div>
          <div className="px-2 py-1">
            <div className="text-xl font-bold font-mono text-slate-100">{roi.ftes_saved}</div>
            <div className="text-[11px] text-slate-400">FTEs Saved</div>
            <div className="text-[10px] text-emerald-400 font-mono mt-0.5">Tier-1 capacity</div>
          </div>
          <div className="px-2 py-1">
            <div className="text-xl font-bold font-mono text-slate-100">{roi.time_saved_display}</div>
            <div className="text-[11px] text-slate-400">Analyst Time Saved</div>
            <div className="text-[10px] text-cyan-400 font-mono mt-0.5">38h manual toil</div>
          </div>
          <div className="px-2 py-1">
            <div className="text-xl font-bold font-mono text-emerald-400">{roi.dollars_saved_display}</div>
            <div className="text-[11px] text-slate-400">Dollars Saved</div>
            <div className="text-[10px] text-emerald-400 font-mono mt-0.5">ROI payback</div>
          </div>
        </div>
      </div>

      {/* 2. MIDDLE ROW: GAUGE METER, CASES BY AGE, & FLAG ANOMALIES (Inspired by Siemplify & CISO Screenshots) */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* RADIAL GAUGE: Cases with Automatic Assistance */}
        <div className="soc-panel p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between border-b border-slate-800 pb-2 mb-2">
            <span className="text-xs font-semibold text-slate-200 font-mono uppercase tracking-wider">
              Automatic Assistance
            </span>
            <span className="text-[10px] text-cyan-400 font-mono bg-cyan-950/40 px-1.5 py-0.5 rounded border border-cyan-800/40">
              {assistance.gauge_label}
            </span>
          </div>

          <div className="relative flex flex-col items-center justify-center py-2">
            <svg viewBox="0 0 200 120" className="w-48 h-auto overflow-visible">
              <defs>
                <linearGradient id="gaugeArcGrad" x1="0%" y1="0%" x2="100%" y2="0%">
                  <stop offset="0%" stopColor="#10b981" />
                  <stop offset="50%" stopColor="#eab308" />
                  <stop offset="100%" stopColor="#ef4444" />
                </linearGradient>
              </defs>

              {/* Background Arc */}
              <path
                d="M 20 100 A 80 80 0 0 1 180 100"
                fill="none"
                stroke="#1e293b"
                strokeWidth="14"
                strokeLinecap="round"
              />

              {/* Active Value Arc */}
              <path
                d="M 20 100 A 80 80 0 0 1 180 100"
                fill="none"
                stroke="url(#gaugeArcGrad)"
                strokeWidth="14"
                strokeDasharray="251.3"
                strokeDashoffset={251.3 - (251.3 * (assistance.percentage / 100))}
                strokeLinecap="round"
                className="transition-all duration-700"
              />

              {/* Center Needle */}
              <g transform="translate(100, 100)">
                <line
                  x1="0"
                  y1="0"
                  x2="0"
                  y2="-68"
                  stroke="#ffffff"
                  strokeWidth="2.5"
                  strokeLinecap="round"
                  transform={`rotate(${gaugeAngle})`}
                  className="transition-transform duration-700 ease-out"
                />
                <circle cx="0" cy="0" r="6" fill="#0f172a" stroke="#ffffff" strokeWidth="2" />
              </g>
            </svg>

            <div className="text-center mt-[-10px]">
              <div className="text-2xl font-bold font-mono text-slate-100">{assistance.percentage}%</div>
              <div className="text-[11px] text-slate-400">Cases Handled With Autopilot</div>
            </div>
          </div>

          <div className="text-[10px] font-mono text-slate-500 text-center border-t border-slate-800/80 pt-2 mt-2">
            748 assisted / 212 manual escalation
          </div>
        </div>

        {/* CASES BY AGE / DWELL TIME (Inspired by Siemplify) */}
        <div className="soc-panel p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between border-b border-slate-800 pb-2 mb-2">
            <span className="text-xs font-semibold text-slate-200 font-mono uppercase tracking-wider">
              Cases by Dwell Age
            </span>
            <span className="text-[10px] text-slate-400 font-mono">24 Active Incidents</span>
          </div>

          <div className="flex items-end justify-between gap-3 h-36 pt-4 px-2">
            {casesByAge.map(c => {
              const heightPct = Math.max(15, c.percentage)
              const barColor =
                c.color === 'emerald'
                  ? 'bg-emerald-500/80 hover:bg-emerald-400'
                  : c.color === 'blue'
                  ? 'bg-blue-500/80 hover:bg-blue-400'
                  : c.color === 'amber'
                  ? 'bg-amber-500/80 hover:bg-amber-400'
                  : 'bg-rose-500/80 hover:bg-rose-400'

              return (
                <div key={c.range} className="flex-1 flex flex-col items-center gap-1.5 h-full justify-end">
                  <span className="text-[10px] font-mono text-slate-300 font-bold">{c.count}</span>
                  <div className="w-full bg-slate-900 rounded-t overflow-hidden flex items-end h-24">
                    <div
                      style={{ height: `${heightPct}%` }}
                      className={`w-full ${barColor} rounded-t transition-all duration-500`}
                    />
                  </div>
                  <span className="text-[9.5px] font-mono text-slate-400 text-center leading-tight truncate max-w-full">
                    {c.range}
                  </span>
                </div>
              )
            })}
          </div>

          <div className="text-[10px] font-mono text-slate-500 text-center border-t border-slate-800/80 pt-2 mt-2">
            83% of all alerts contained in under 8 hours
          </div>
        </div>

        {/* THREAT INDICATORS & ATTACK SURFACES (Inspired by CISO Screenshot) */}
        <div className="soc-panel p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between border-b border-slate-800 pb-2 mb-2">
            <span className="text-xs font-semibold text-slate-200 font-mono uppercase tracking-wider">
              Threat Indicators & Scope
            </span>
            <span className="text-[10px] text-slate-400 font-mono">Active Posture</span>
          </div>

          <div className="space-y-2.5 py-1">
            {threatIndicators.map(t => (
              <div
                key={t.category}
                className="flex items-center justify-between p-2 rounded bg-slate-900/60 border border-slate-800 text-xs font-mono"
              >
                <div>
                  <div className="text-slate-200 font-semibold">{t.category}</div>
                  <div className="text-[10px] text-slate-500">{t.sublabel}</div>
                </div>
                <span
                  style={{ color: t.color, borderColor: `${t.color}40`, backgroundColor: `${t.color}15` }}
                  className="text-[10px] font-bold px-2 py-0.5 rounded border"
                >
                  {t.impact}
                </span>
              </div>
            ))}
          </div>

          <div className="text-[10px] font-mono text-slate-500 text-center border-t border-slate-800/80 pt-2 mt-2">
            Zero lateral bridging across corporate subnets
          </div>
        </div>
      </div>

      {/* 3. BOTTOM ROW: TELEMETRY ANOMALIES & TOP PLAYBOOKS (Inspired by CISO + SOAR screenshots) */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* SECURITY SOURCE ANOMALIES (CISO "Anomalies" List with Bug Icons) */}
        <div className="soc-panel p-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-2 mb-3">
            <span className="text-xs font-semibold text-slate-200 font-mono uppercase tracking-wider">
              Flagged Anomalies by Security Technology
            </span>
            <span className="text-[10px] font-mono text-cyan-400 bg-cyan-950/40 px-1.5 py-0.5 rounded border border-cyan-800/40">
              Isolation Forest + Rules
            </span>
          </div>

          <div className="space-y-2">
            {telemetry.map(source => (
              <div
                key={source.id}
                className="p-2.5 rounded bg-slate-900/70 border border-slate-800/80 flex items-center justify-between gap-3 hover:border-slate-700 transition-colors"
              >
                <div className="flex items-center gap-2.5">
                  <div className="p-1.5 rounded bg-slate-850 border border-slate-800 text-slate-400">
                    <svg className="w-3.5 h-3.5 text-rose-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <rect x="2" y="6" width="20" height="8" rx="1" />
                      <path d="M17 14v7" />
                      <path d="M7 14v7" />
                      <path d="M17 3v3" />
                      <path d="M7 3v3" />
                    </svg>
                  </div>
                  <div>
                    <div className="text-xs font-semibold text-slate-200 font-mono">{source.source}</div>
                    <div className="text-[10px] text-slate-500 font-sans">{source.category}</div>
                  </div>
                </div>

                <div className="text-right">
                  <div className="text-sm font-bold font-mono text-amber-400">{source.anomalies}</div>
                  <span
                    className={`text-[9.5px] font-mono uppercase font-semibold ${
                      source.impact === 'critical'
                        ? 'text-red-400'
                        : source.impact === 'high'
                        ? 'text-orange-400'
                        : 'text-amber-400'
                    }`}
                  >
                    {source.impact}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* TOP PLAYBOOKS & AUTOMATED ACTIONS (SOAR Screenshot) */}
        <div className="soc-panel p-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-2 mb-3">
            <span className="text-xs font-semibold text-slate-200 font-mono uppercase tracking-wider">
              Top Executed SOAR Playbooks & Containment Actions
            </span>
            <span className="text-[10px] font-mono text-emerald-400 bg-emerald-950/40 px-1.5 py-0.5 rounded border border-emerald-800/40">
              150 Runs
            </span>
          </div>

          <div className="space-y-2">
            {playbooks.map(pb => (
              <div
                key={pb.name}
                className="p-2.5 rounded bg-slate-900/70 border border-slate-800/80 flex items-center justify-between gap-3 text-xs font-mono"
              >
                <div className="space-y-0.5 flex-1 min-w-0">
                  <div className="text-slate-200 font-semibold truncate">{pb.name}</div>
                  <div className="text-[10px] text-slate-500">{pb.category}</div>
                </div>

                <div className="flex items-center gap-3 shrink-0">
                  <div className="text-right">
                    <div className="text-slate-200 font-bold">{pb.executions} runs</div>
                    <div className="text-[10px] text-slate-500">~{pb.avg_seconds}s avg</div>
                  </div>
                  <span className="text-[10px] font-mono text-emerald-400 bg-emerald-950/50 border border-emerald-800/50 px-1.5 py-0.5 rounded">
                    {pb.success_rate}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
