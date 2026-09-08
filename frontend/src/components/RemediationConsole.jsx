import { useState } from 'react'
import {
  isolateHost,
  restoreHost,
  revokeUser,
  blockIp,
  captureForensics,
  killProcess,
  enforceMfa,
  rotateCredentials,
  deployDeception,
  rollbackFiles,
  triggerPlaybook,
  updateIncidentStatus,
} from '../api/incidents'

/**
 * RemediationConsole — Operational SOAR Playbook & Containment Console.
 * Full-spectrum security operations suite with 10 immediate controls,
 * 5 multi-step automated response playbooks with animated step progression,
 * and chronological remediation audit log.
 */

export default function RemediationConsole({ incident, onIncidentUpdate }) {
  const [activeTab, setActiveTab] = useState('actions') // 'actions' | 'playbooks' | 'audit'
  const [actionStates, setActionStates] = useState({})
  const [confirmingAction, setConfirmingAction] = useState(null)
  const [activePlaybookSteps, setActivePlaybookSteps] = useState({})
  const [auditLog, setAuditLog] = useState([
    {
      id: 'log-0',
      action: 'Correlation Engine Baseline',
      target: incident?.host || 'host',
      status: 'completed',
      time: 'At detection',
      detail: 'Correlated multi-stage attack sequence into threat graph and assigned ML anomaly attribution.',
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
        `Analyst transitioned incident lifecycle state to ${newStatus}.`
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
      id: `log-${Date.now()}-${Math.random().toString(36).substr(2, 4)}`,
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

  async function executePlaybook(pb) {
    const name = pb.name
    if (actionStates[name] === 'running') return
    setActionStates(prev => ({ ...prev, [name]: 'running' }))
    setActivePlaybookSteps(prev => ({ ...prev, [name]: 0 }))

    // Animate step progression
    for (let i = 0; i < pb.steps.length; i++) {
      await new Promise(r => setTimeout(r, 280))
      setActivePlaybookSteps(prev => ({ ...prev, [name]: i + 1 }))
    }

    try {
      const res = await pb.run()
      setActionStates(prev => ({ ...prev, [name]: 'done' }))
      addAuditEntry(name, incident.incident_id, 'Completed', res.message || `All ${pb.steps.length} playbook containment actions confirmed.`)
    } catch (err) {
      setActionStates(prev => ({ ...prev, [name]: 'error' }))
      addAuditEntry(name, incident.incident_id, 'Failed', err.message || 'Playbook execution error')
    }
  }

  const hostTarget = incident?.host || 'workstation-14.corp'
  const userTarget = incident?.user || 'alice.chen'

  const actions = [
    {
      key: 'isolate',
      name: 'Isolate Host',
      target: hostTarget,
      desc: 'Sever all network adapters on endpoint except SOC management bridge.',
      run: () => isolateHost(hostTarget),
      successMsg: `Host ${hostTarget} network adapter quarantined to zero-trust vLAN.`,
      icon: (
        <svg className="w-4 h-4 text-rose-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
          <path d="M7 11V7a5 5 0 0 1 10 0v4" />
        </svg>
      ),
    },
    {
      key: 'restore',
      name: 'Restore Host Network',
      target: hostTarget,
      desc: 'Re-enable production network adapters and restore standard connectivity.',
      run: () => restoreHost(hostTarget),
      successMsg: `Host ${hostTarget} network interfaces restored to sentry-net.`,
      icon: (
        <svg className="w-4 h-4 text-emerald-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
          <path d="M7 11V7a5 5 0 0 1 9.9-1" />
        </svg>
      ),
    },
    {
      key: 'kill_proc',
      name: 'Kill Malicious Process Tree',
      target: `${hostTarget} (PID 4912)`,
      desc: 'Terminate suspicious process PID and all spawned child worker threads.',
      run: () => killProcess(hostTarget, 4912, 'powershell.exe -enc SQBFAFgA'),
      successMsg: `Terminated process powershell.exe (PID 4912) and 3 child threads on ${hostTarget}.`,
      icon: (
        <svg className="w-4 h-4 text-amber-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <circle cx="12" cy="12" r="10" />
          <line x1="15" y1="9" x2="9" y2="15" />
          <line x1="9" y1="9" x2="15" y2="15" />
        </svg>
      ),
    },
    {
      key: 'revoke',
      name: 'Revoke User Session',
      target: userTarget,
      desc: 'Invalidate active OAuth/Kerberos tokens and lock IAM directory account.',
      run: () => revokeUser(userTarget, `Incident ${incident.incident_id}`),
      successMsg: `Active sessions terminated; identity locked in IAM provider.`,
      icon: (
        <svg className="w-4 h-4 text-orange-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M16 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" />
          <circle cx="8.5" cy="7" r="4" />
          <line x1="18" y1="8" x2="23" y2="13" />
          <line x1="23" y1="8" x2="18" y2="13" />
        </svg>
      ),
    },
    {
      key: 'enforce_mfa',
      name: 'Enforce Step-Up Hardware MFA',
      target: userTarget,
      desc: 'Trigger FIDO2 / WebAuthn token challenge before any subsequent authentication.',
      run: () => enforceMfa(userTarget),
      successMsg: `Step-up FIDO2 hardware MFA enforced for ${userTarget}.`,
      icon: (
        <svg className="w-4 h-4 text-cyan-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M12 2a10 10 0 0 0-10 10v3a5 5 0 0 0 5 5h10a5 5 0 0 0 5-5v-3a10 10 0 0 0-10-10z" />
          <circle cx="12" cy="12" r="3" />
        </svg>
      ),
    },
    {
      key: 'block_ip',
      name: 'Block Perimeter C2 IP',
      target: '198.51.100.44',
      desc: 'Deploy automated egress drop rule to edge firewalls and security groups.',
      run: () => blockIp('198.51.100.44', `Auto block for ${incident.incident_id}`),
      successMsg: 'Perimeter firewall null-route rule deployed.',
      icon: (
        <svg className="w-4 h-4 text-red-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <circle cx="12" cy="12" r="10" />
          <line x1="4.93" y1="4.93" x2="19.07" y2="19.07" />
        </svg>
      ),
    },
    {
      key: 'rotate_creds',
      name: 'Rotate Credentials & SSH Keys',
      target: userTarget,
      desc: 'Invalidate and reissue Kerberos TGT, deployment SSH keys, and cloud API secrets.',
      run: () => rotateCredentials(userTarget, hostTarget),
      successMsg: `Reissued SSH authorized keys and Kerberos TGT ticket for ${userTarget}.`,
      icon: (
        <svg className="w-4 h-4 text-indigo-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M21 2l-2 2m-1-1l-3 3m-2-2l-3 3m0 0l-4 4a5 5 0 1 1-7-7l4-4" />
        </svg>
      ),
    },
    {
      key: 'forensics',
      name: 'Capture Volatile Forensics',
      target: hostTarget,
      desc: 'Acquire live RAM snapshot and process socket execution tree for DFIR triage.',
      run: () => captureForensics(hostTarget),
      successMsg: `Volatile memory dump and triage package acquired (512 MB).`,
      icon: (
        <svg className="w-4 h-4 text-purple-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <rect x="4" y="4" width="16" height="16" rx="2" />
          <rect x="9" y="4" width="6" height="6" />
          <line x1="9" y1="20" x2="15" y2="20" />
        </svg>
      ),
    },
    {
      key: 'deception',
      name: 'Deploy Honeytoken Canary',
      target: hostTarget,
      desc: 'Plant decoy Domain Admin Kerberos tickets in LSASS memory to trap lateral moves.',
      run: () => deployDeception(hostTarget),
      successMsg: `Honeytoken canary deployed on ${hostTarget}. Any access triggers high alert.`,
      icon: (
        <svg className="w-4 h-4 text-yellow-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2" />
        </svg>
      ),
    },
    {
      key: 'rollback',
      name: 'Rollback Ransomware Files',
      target: hostTarget,
      desc: 'Restore Volume Shadow Copies (VSS) and reverse unauthorized file encryptions.',
      run: () => rollbackFiles(hostTarget),
      successMsg: `Volume Shadow Copy restored on ${hostTarget}. 142 encrypted files recovered.`,
      icon: (
        <svg className="w-4 h-4 text-teal-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <polyline points="1 4 1 10 7 10" />
          <path d="M3.51 15a9 9 0 1 0 2.13-9.36L1 10" />
        </svg>
      ),
    },
  ]

  const playbooks = [
    {
      name: 'Rapid Ransomware Containment',
      estTime: '1.2s',
      category: 'Critical Containment',
      steps: ['Host Network Quarantine', 'User Token Invalidation', 'C2 IP Block Rule', 'Memory Triage Dump'],
      run: () => triggerPlaybook('Rapid Ransomware Containment', incident.incident_id, hostTarget, userTarget),
    },
    {
      name: 'Credential Abuse Lockout',
      estTime: '0.8s',
      category: 'Identity Protection',
      steps: ['Lock User Directory Account', 'Kill Active Web Sessions', 'Require MFA Step-up', 'Notify Security Lead'],
      run: () => triggerPlaybook('Credential Abuse Lockout', incident.incident_id, hostTarget, userTarget),
    },
    {
      name: 'Lateral Movement Isolation',
      estTime: '1.5s',
      category: 'Subnet Boundary',
      steps: ['Isolate Source Endpoint', 'Block Subnet SMB/RDP Traffic', 'Export WinEvent Security Logs'],
      run: () => triggerPlaybook('Lateral Movement Isolation', incident.incident_id, hostTarget, userTarget),
    },
    {
      name: 'Data Exfiltration Emergency Stop',
      estTime: '0.6s',
      category: 'Data Protection',
      steps: ['Null-Route C2 Egress IP', 'Sever Active WebSockets & TLS', 'Capture DNS Proxy Queries'],
      run: () => triggerPlaybook('Data Exfiltration Emergency Stop', incident.incident_id, hostTarget, userTarget),
    },
    {
      name: 'Endpoint Malware Purge & Memory Triage',
      estTime: '1.1s',
      category: 'EDR Forensic',
      steps: ['Terminate Process Tree', 'Acquire Volatile RAM Dump', 'Quarantine Binary Hash', 'Trigger AV Rescan'],
      run: () => triggerPlaybook('Endpoint Malware Purge & Memory Triage', incident.incident_id, hostTarget, userTarget),
    },
  ]

  return (
    <div className="soc-panel p-5 flex flex-col gap-4">
      {/* Header & Status Lifecycle */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-4">
        <div>
          <div className="flex items-center gap-2">
            <div className="p-1 rounded bg-slate-850 border border-slate-800 text-slate-300">
              <svg className="w-3.5 h-3.5 text-cyan-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              </svg>
            </div>
            <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider">
              SOAR Remediation & Active Containment Console
            </h3>
          </div>
          <p className="text-[11px] text-slate-400 mt-0.5">
            Full-spectrum incident response toolkit: granular endpoint actions, perimeter blocks, and automated playbooks
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
          Remediation Ledger ({auditLog.length})
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
                className="soc-panel-subtle p-3.5 flex flex-col justify-between gap-3 border border-slate-800 hover:border-slate-700 transition-colors"
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
                    <span className="text-[10px] font-mono text-slate-400 bg-slate-900/60 px-1.5 py-0.5 rounded border border-slate-800 truncate max-w-[140px]">
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
                      Executed & Enforced
                    </span>
                  ) : state === 'error' ? (
                    <span className="text-[11px] text-rose-400 font-mono">Action Failed</span>
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
            const completedStepIndex = activePlaybookSteps[pb.name] || 0

            return (
              <div
                key={pb.name}
                className="soc-panel-subtle p-3.5 border border-slate-800 flex flex-col gap-3"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-semibold text-slate-200 font-mono">
                      {pb.name}
                    </span>
                    <span className="text-[10px] font-mono text-cyan-400 bg-cyan-950/40 px-1.5 py-0.5 rounded border border-cyan-800/40">
                      {pb.category}
                    </span>
                    <span className="text-[10px] font-mono text-slate-500 bg-slate-900 px-1.5 py-0.5 rounded border border-slate-800">
                      SLA: ~{pb.estTime}
                    </span>
                  </div>

                  <div className="flex items-center gap-2">
                    {state === 'done' ? (
                      <span className="text-xs text-emerald-400 font-mono flex items-center gap-1 bg-emerald-950/30 px-2.5 py-1 rounded border border-emerald-500/30">
                        <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                          <polyline points="20 6 9 17 4 12" />
                        </svg>
                        Playbook Executed (100%)
                      </span>
                    ) : (
                      <button
                        disabled={state === 'running'}
                        onClick={() => executePlaybook(pb)}
                        className="px-3 py-1 text-xs font-mono font-medium rounded bg-slate-850 hover:bg-slate-750 text-slate-200 border border-slate-700 transition-colors flex items-center gap-1.5"
                      >
                        {state === 'running' ? (
                          <>
                            <span className="w-2.5 h-2.5 border-2 border-slate-400 border-t-transparent rounded-full animate-spin" />
                            Running Step {completedStepIndex} of {pb.steps.length}…
                          </>
                        ) : (
                          <>
                            <svg className="w-3 h-3 text-cyan-400" viewBox="0 0 24 24" fill="currentColor">
                              <polygon points="5 3 19 12 5 21 5 3" />
                            </svg>
                            Execute Playbook
                          </>
                        )}
                      </button>
                    )}
                  </div>
                </div>

                {/* Animated Step Progression Indicator */}
                <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-2 pt-1 border-t border-slate-850">
                  {pb.steps.map((step, idx) => {
                    const isStepDone = state === 'done' || completedStepIndex > idx
                    const isStepActive = state === 'running' && completedStepIndex === idx

                    return (
                      <div
                        key={step}
                        className={`text-[10px] font-mono px-2 py-1.5 rounded flex items-center gap-1.5 transition-colors ${
                          isStepDone
                            ? 'bg-emerald-950/30 text-emerald-300 border border-emerald-800/40'
                            : isStepActive
                            ? 'bg-cyan-950/40 text-cyan-200 border border-cyan-500/40 animate-pulse'
                            : 'bg-slate-900 text-slate-400 border border-slate-800'
                        }`}
                      >
                        <span className="w-3.5 h-3.5 rounded-full bg-slate-800 flex items-center justify-center font-bold text-[9px]">
                          {isStepDone ? '✓' : idx + 1}
                        </span>
                        <span className="truncate">{step}</span>
                      </div>
                    )
                  })}
                </div>
              </div>
            )
          })}
        </div>
      )}

      {/* TAB 3: Remediation Ledger */}
      {activeTab === 'audit' && (
        <div className="space-y-2">
          {auditLog.map(entry => (
            <div
              key={entry.id}
              className="soc-panel-subtle p-3 border border-slate-800 flex items-start justify-between gap-3 text-xs font-mono"
            >
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className="text-slate-200 font-semibold">{entry.action}</span>
                  <span className="text-[10px] text-slate-500 bg-slate-900 px-1 rounded border border-slate-800">
                    Target: {entry.target}
                  </span>
                </div>
                <p className="text-[11px] text-slate-400 font-sans">{entry.detail}</p>
              </div>
              <div className="text-right shrink-0">
                <span className="text-[10px] text-emerald-400 bg-emerald-950/40 border border-emerald-800/40 px-1.5 py-0.5 rounded">
                  {entry.status}
                </span>
                <div className="text-[10px] text-slate-500 mt-1">{entry.time}</div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
