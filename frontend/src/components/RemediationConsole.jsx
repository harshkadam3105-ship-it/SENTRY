import { useState } from 'react'
import {
  isolateHost,
  revokeUser,
  blockIp,
  captureForensics,
  triggerPlaybook,
  updateIncidentStatus,
} from '../api/incidents'

/**
 * RemediationConsole — Operational SOAR Playbook & Containment Console.
 * Real security controls with confirmation states, clear operational feedback,
 * and chronological action audit log.
 */

export default function RemediationConsole({ incident, onIncidentUpdate }) {
  const [activeTab, setActiveTab] = useState('actions') // 'actions' | 'playbooks' | 'audit'
  const [actionStates, setActionStates] = useState({})
  const [confirmingAction, setConfirmingAction] = useState(null)
  const [auditLog, setAuditLog] = useState([
    {
      id: 'log-0',
      action: 'Correlation Engine Baseline',
      target: incident?.host || 'host',
      status: 'completed',
      time: 'At detection',
      detail: 'Correlated event sequence into threat graph and assigned ML anomaly score.',
    },
  ])
  const [currentStatus, setCurrentStatus] = useState(incident?.status || 'open')
  const [statusLoading, setStatusLoading] = useState(false)

  // Status transitions
  const STATUS_FLOW = [
    { key: 'open', label: 'Open', color: 'bg-red-950/40 text-red-400 border-red-500/30' },
    { key: 'investigating', label: 'Investigating', color: 'bg-blue-950/40 text-blue-300 border-blue-500/30' },
    { key: 'contained', label: 'Contained', color: 'bg-amber-950/40 text-amber-300 border-amber-500/30' },
    { key: 'resolved', label: 'Resolved', color: 'bg-emerald-950/40 text-emerald-400 border-emerald-500/30' },
  ]

  async function handleStatusChange(newStatus) {
    if (newStatus === currentStatus || statusLoading) return
    setStatusLoading(true)
    try {
      await updateIncidentStatus(incident.incident_id, newStatus)
      setCurrentStatus(newStatus)
      addAuditEntry(
        `STATUS CHANGED -> ${newStatus.toUpperCase()}`,
        incident.incident_id,
        'Completed',
        `Analyst updated incident lifecycle state.`
      )
      if (onIncidentUpdate) {
        onIncidentUpdate({ ...incident, status: newStatus })
      }
    } catch (err) {
      console.error('Failed to update status:', err)
    } finally {
      setStatusLoading(false)
    }
  }

  function addAuditEntry(action, target, status, detail) {
    const entry = {
      id: `log-${Date.now()}`,
      action,
      target,
      status,
      time: new Date().toLocaleTimeString('en-US', { hour12: false }),
      detail,
    }
    setAuditLog(prev => [entry, ...prev])
  }

  async function executeAction(actionObj) {
    const key = actionObj.key
    if (actionStates[key] === 'running' || actionStates[key] === 'done') return
    setConfirmingAction(null)
    setActionStates(prev => ({ ...prev, [key]: 'running' }))

    try {
      const res = await actionObj.run()
      setActionStates(prev => ({ ...prev, [key]: 'done' }))
      addAuditEntry(actionObj.name, actionObj.target, 'Completed', res.message || actionObj.successMsg)
    } catch (err) {
      setActionStates(prev => ({ ...prev, [key]: 'error' }))
      addAuditEntry(actionObj.name, actionObj.target, 'Failed', err.message || 'Execution error')
    }
  }

  const actions = [
    {
      key: 'isolate',
      name: 'Isolate Host',
      target: incident.host || 'target-endpoint',
      desc: 'Sever all network interfaces on target endpoint except SOC C2 bridge.',
      run: () => isolateHost(incident.host),
      successMsg: `Host network adapter quarantined to zero-trust vLAN.`,
      icon: (
        <svg className="w-4 h-4 text-slate-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
          <path d="M7 11V7a5 5 0 0 1 10 0v4" />
        </svg>
      ),
    },
    {
      key: 'revoke',
      name: 'Revoke User Session',
      target: incident.user || 'target-identity',
      desc: 'Invalidate active OAuth/Kerberos tokens and lock directory account.',
      run: () => revokeUser(incident.user, `Incident ${incident.incident_id}`),
      successMsg: `Active sessions terminated; identity locked in IAM provider.`,
      icon: (
        <svg className="w-4 h-4 text-slate-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M16 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" />
          <circle cx="8.5" cy="7" r="4" />
          <line x1="18" y1="8" x2="23" y2="13" />
          <line x1="23" y1="8" x2="18" y2="13" />
        </svg>
      ),
    },
    {
      key: 'block_ip',
      name: 'Block Perimeter Indicator',
      target: '198.51.100.44',
      desc: 'Deploy automated egress drop rule to edge firewalls and security groups.',
      run: () => blockIp('198.51.100.44', `Auto block for ${incident.incident_id}`),
      successMsg: 'Perimeter firewall null-route rule deployed.',
      icon: (
        <svg className="w-4 h-4 text-slate-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <circle cx="12" cy="12" r="10" />
          <line x1="4.93" y1="4.93" x2="19.07" y2="19.07" />
        </svg>
      ),
    },
    {
      key: 'forensics',
      name: 'Capture Volatile Forensics',
      target: incident.host || 'target-endpoint',
      desc: 'Acquire live RAM snapshot and process execution tree for analysis.',
      run: () => captureForensics(incident.host),
      successMsg: `Volatile memory dump and triage package acquired (512 MB).`,
      icon: (
        <svg className="w-4 h-4 text-slate-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <rect x="4" y="4" width="16" height="16" rx="2" />
          <rect x="9" y="4" width="6" height="6" />
          <line x1="9" y1="20" x2="15" y2="20" />
        </svg>
      ),
    },
  ]

  const playbooks = [
    {
      name: 'Rapid Ransomware Containment',
      estTime: '1.2s',
      steps: ['Host Network Quarantine', 'User Token Invalidation', 'C2 IP Block Rule', 'Memory Triage Dump'],
      run: () => triggerPlaybook('Rapid Ransomware Containment', incident.incident_id, incident.host, incident.user),
    },
    {
      name: 'Credential Abuse Lockout',
      estTime: '0.8s',
      steps: ['Lock User Directory Account', 'Kill Active Web Sessions', 'Require MFA Step-up', 'Notify Security Lead'],
      run: () => triggerPlaybook('Credential Abuse Lockout', incident.incident_id, incident.host, incident.user),
    },
    {
      name: 'Lateral Movement Isolation',
      estTime: '1.5s',
      steps: ['Isolate Source Endpoint', 'Block Subnet SMB/RDP Traffic', 'Export WinEvent Security Logs'],
      run: () => triggerPlaybook('Lateral Movement Isolation', incident.incident_id, incident.host, incident.user),
    },
  ]

  return (
    <div className="soc-panel p-5 flex flex-col gap-4">
      {/* Header & Status Lifecycle */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-4">
        <div>
          <div className="flex items-center gap-2">
            <div className="p-1 rounded bg-slate-850 border border-slate-800 text-slate-300">
              <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              </svg>
            </div>
            <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider">
              SOAR Remediation & Response Console
            </h3>
          </div>
          <p className="text-[11px] text-slate-500 mt-0.5">
            Execute active containment controls and automated multi-step response playbooks
          </p>
        </div>

        {/* Status Lifecycle Selector */}
        <div className="flex items-center gap-1 bg-slate-900 p-1 rounded border border-slate-800">
          <span className="text-[10px] text-slate-500 px-2 font-mono uppercase font-semibold">
            Status:
          </span>
          {STATUS_FLOW.map(s => {
            const isSelected = currentStatus === s.key
            return (
              <button
                key={s.key}
                disabled={statusLoading}
                onClick={() => handleStatusChange(s.key)}
                className={`
                  px-2.5 py-1 rounded text-[11px] font-mono font-medium transition-colors
                  ${
                    isSelected
                      ? `${s.color} border shadow-xs`
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
                  }
                `}
              >
                {s.label}
              </button>
            )
          })}
        </div>
      </div>

      {/* Tabs */}
      <div className="flex items-center gap-2 border-b border-slate-800 text-xs font-mono pb-2">
        <button
          onClick={() => setActiveTab('actions')}
          className={`px-3 py-1 rounded transition-colors ${
            activeTab === 'actions'
              ? 'bg-slate-800 text-slate-100 font-semibold'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          Immediate Controls ({actions.length})
        </button>
        <button
          onClick={() => setActiveTab('playbooks')}
          className={`px-3 py-1 rounded transition-colors ${
            activeTab === 'playbooks'
              ? 'bg-slate-800 text-slate-100 font-semibold'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          Automated Playbooks ({playbooks.length})
        </button>
        <button
          onClick={() => setActiveTab('audit')}
          className={`px-3 py-1 rounded transition-colors ${
            activeTab === 'audit'
              ? 'bg-slate-800 text-slate-100 font-semibold'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          Audit Trail ({auditLog.length})
        </button>
      </div>

      {/* TAB 1: Immediate Controls */}
      {activeTab === 'actions' && (
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          {actions.map(action => {
            const state = actionStates[action.key] || 'idle'
            const isConfirming = confirmingAction === action.key

            return (
              <div
                key={action.key}
                className="soc-panel-subtle p-3.5 flex flex-col justify-between gap-3 border border-slate-800"
              >
                <div>
                  <div className="flex items-center justify-between gap-2 mb-1.5">
                    <div className="flex items-center gap-2">
                      <div className="p-1 rounded bg-slate-900 border border-slate-800">
                        {action.icon}
                      </div>
                      <span className="text-xs font-semibold text-slate-200 font-mono">
                        {action.name}
                      </span>
                    </div>
                    <span className="text-[10px] font-mono text-slate-500 truncate max-w-[120px]">
                      {action.target}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400 leading-relaxed">{action.desc}</p>
                </div>

                <div className="flex items-center justify-between pt-2 border-t border-slate-850">
                  {state === 'done' ? (
                    <span className="text-[11px] text-emerald-400 font-mono flex items-center gap-1">
                      <svg className="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <polyline points="20 6 9 17 4 12" />
                      </svg>
                      Executed & Active
                    </span>
                  ) : state === 'error' ? (
                    <span className="text-[11px] text-red-400 font-mono">Action Failed</span>
                  ) : isConfirming ? (
                    <div className="flex items-center gap-1.5 ml-auto">
                      <button
                        onClick={() => setConfirmingAction(null)}
                        className="px-2 py-1 text-[10px] font-mono rounded bg-slate-800 text-slate-400 hover:text-slate-200"
                      >
                        Cancel
                      </button>
                      <button
                        onClick={() => executeAction(action)}
                        className="px-2 py-1 text-[10px] font-mono rounded bg-red-950 text-red-400 border border-red-500/40 hover:bg-red-900"
                      >
                        Confirm Execute
                      </button>
                    </div>
                  ) : (
                    <button
                      disabled={state === 'running'}
                      onClick={() => setConfirmingAction(action.key)}
                      className="ml-auto px-3 py-1 text-[11px] font-mono font-medium rounded bg-slate-850 hover:bg-slate-750 text-slate-200 border border-slate-700 transition-colors flex items-center gap-1.5"
                    >
                      {state === 'running' ? (
                        <>
                          <span className="w-2.5 h-2.5 border-2 border-slate-400 border-t-transparent rounded-full animate-spin" />
                          Executing…
                        </>
                      ) : (
                        'Deploy Control'
                      )}
                    </button>
                  )}
                </div>
              </div>
            )
          })}
        </div>
      )}

      {/* TAB 2: Automated Playbooks */}
      {activeTab === 'playbooks' && (
        <div className="space-y-3">
          {playbooks.map(pb => {
            const state = actionStates[pb.name] || 'idle'

            return (
              <div
                key={pb.name}
                className="soc-panel-subtle p-3.5 border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3"
              >
                <div className="space-y-1.5 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-semibold text-slate-200 font-mono">
                      {pb.name}
                    </span>
                    <span className="text-[10px] font-mono text-slate-500 bg-slate-900 px-1.5 py-0.5 rounded border border-slate-800">
                      SLA: ~{pb.estTime}
                    </span>
                  </div>
                  <div className="flex flex-wrap items-center gap-1.5">
                    {pb.steps.map((step, idx) => (
                      <span
                        key={step}
                        className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-900 text-slate-400 border border-slate-800"
                      >
                        {idx + 1}. {step}
                      </span>
                    ))}
                  </div>
                </div>

                <div className="shrink-0">
                  {state === 'done' ? (
                    <span className="text-xs font-mono text-emerald-400 flex items-center gap-1">
                      <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <polyline points="20 6 9 17 4 12" />
                      </svg>
                      Sequence Completed
                    </span>
                  ) : (
                    <button
                      disabled={state === 'running'}
                      onClick={async () => {
                        setActionStates(prev => ({ ...prev, [pb.name]: 'running' }))
                        try {
                          await pb.run()
                          setActionStates(prev => ({ ...prev, [pb.name]: 'done' }))
                          addAuditEntry(
                            pb.name,
                            incident.incident_id,
                            'Completed',
                            `Executed automated sequence (${pb.steps.length} containment steps)`
                          )
                        } catch (err) {
                          setActionStates(prev => ({ ...prev, [pb.name]: 'error' }))
                          addAuditEntry(pb.name, incident.incident_id, 'Failed', err.message)
                        }
                      }}
                      className="px-3.5 py-1.5 text-xs font-mono font-semibold rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-650 transition-colors flex items-center gap-1.5"
                    >
                      {state === 'running' ? (
                        <>
                          <span className="w-2.5 h-2.5 border-2 border-slate-400 border-t-transparent rounded-full animate-spin" />
                          Running Sequence…
                        </>
                      ) : (
                        'Run Playbook'
                      )}
                    </button>
                  )}
                </div>
              </div>
            )
          })}
        </div>
      )}

      {/* TAB 3: Audit Trail */}
      {activeTab === 'audit' && (
        <div className="soc-panel overflow-hidden border border-slate-800">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-900/80 text-[10px] uppercase font-semibold text-slate-400 font-mono">
                <th className="py-2 px-3">Timestamp</th>
                <th className="py-2 px-3">Control / Action</th>
                <th className="py-2 px-3">Target</th>
                <th className="py-2 px-3">Result</th>
                <th className="py-2 px-3">Detail</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-850 font-mono text-[11px]">
              {auditLog.map(item => (
                <tr key={item.id} className="hover:bg-slate-850/40">
                  <td className="py-2 px-3 text-slate-400 whitespace-nowrap">{item.time}</td>
                  <td className="py-2 px-3 text-slate-200 font-semibold">{item.action}</td>
                  <td className="py-2 px-3 text-slate-400">{item.target}</td>
                  <td className="py-2 px-3">
                    <span
                      className={`px-1.5 py-0.5 rounded text-[10px] ${
                        item.status === 'Completed'
                          ? 'bg-emerald-950/40 text-emerald-400 border border-emerald-500/30'
                          : 'bg-red-950/40 text-red-400 border border-red-500/30'
                      }`}
                    >
                      {item.status}
                    </span>
                  </td>
                  <td className="py-2 px-3 text-slate-400 font-sans text-xs max-w-[280px] truncate">
                    {item.detail}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
