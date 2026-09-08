import { useState } from 'react'
import { isolateHost, revokeUser, blockIp, captureForensics, triggerPlaybook, updateIncidentStatus } from '../api/incidents'
import { IconSettings, IconTarget, IconZap, IconFileText, IconLock, IconUser, IconShield, IconDatabase, IconKey, IconNetwork } from './Icons'

/**
 * RemediationConsole — SOAR Response & Playbook Control Center
 * Provides multi-vector remediation actions, playbook execution, and incident lifecycle management.
 */

export default function RemediationConsole({ incident, onIncidentUpdate }) {
  const [activeTab, setActiveTab] = useState('actions') // 'actions' | 'playbooks' | 'audit'
  const [actionStates, setActionStates] = useState({})
  const [auditLog, setAuditLog] = useState([
    {
      id: 'log-0',
      action: 'Automated Correlation',
      target: incident?.host || 'host',
      status: 'completed',
      time: 'At detection',
      detail: 'Events correlated into single threat graph with risk scoring.'
    }
  ])
  const [currentStatus, setCurrentStatus] = useState(incident?.status || 'open')
  const [statusLoading, setStatusLoading] = useState(false)

  // Status transitions
  const STATUS_FLOW = [
    { key: 'open', label: 'Open', color: 'bg-red-500/20 text-red-400 border-red-500/30' },
    { key: 'investigating', label: 'Investigating', color: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30' },
    { key: 'contained', label: 'Contained', color: 'bg-orange-500/20 text-orange-400 border-orange-500/30' },
    { key: 'resolved', label: 'Resolved', color: 'bg-green-500/20 text-green-400 border-green-500/30' },
  ]

  async function handleStatusChange(newStatus) {
    if (newStatus === currentStatus || statusLoading) return
    setStatusLoading(true)
    try {
      await updateIncidentStatus(incident.incident_id, newStatus)
      setCurrentStatus(newStatus)
      addAuditEntry(`Status Changed to ${newStatus.toUpperCase()}`, incident.incident_id, 'Completed', 'Incident lifecycle updated.')
      if (onIncidentUpdate) {
        onIncidentUpdate({ ...incident, status: newStatus })
      }
    } catch (err) {
      console.error(err)
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

  // Execute single action
  async function runAction(key, actionFn, target, name, successDetail) {
    if (actionStates[key] === 'running' || actionStates[key] === 'done') return
    setActionStates(prev => ({ ...prev, [key]: 'running' }))
    try {
      const res = await actionFn()
      setActionStates(prev => ({ ...prev, [key]: 'done' }))
      addAuditEntry(name, target, 'Completed', res.message || successDetail)
    } catch (err) {
      setActionStates(prev => ({ ...prev, [key]: 'error' }))
      addAuditEntry(name, target, 'Failed', err.message || 'Action error')
    }
  }

  const actions = [
    {
      key: 'isolate',
      name: 'Isolate Host',
      target: incident.host,
      icon: <IconLock className="w-4 h-4 text-rose-400" />,
      desc: 'Sever all network interfaces on target endpoint except SOC C2 bridge.',
      color: 'red',
      run: () => isolateHost(incident.host),
      successMsg: `Endpoint ${incident.host} successfully quarantined to isolated bridge.`,
    },
    {
      key: 'revoke',
      name: 'Revoke User Session',
      target: incident.user,
      icon: <IconUser className="w-4 h-4 text-amber-400" />,
      desc: 'Invalidate active OAuth/Kerberos tokens and lock user directory account.',
      color: 'orange',
      run: () => revokeUser(incident.user, `Incident ${incident.incident_id}`),
      successMsg: `Credentials for ${incident.user} revoked across identity provider.`,
    },
    {
      key: 'block_ip',
      name: 'Block Perimeter IP',
      target: '198.51.100.44',
      icon: <IconShield className="w-4 h-4 text-yellow-400" />,
      desc: 'Deploy automated egress drop ACL to edge firewalls & security groups.',
      color: 'yellow',
      run: () => blockIp('198.51.100.44', `Auto block for ${incident.incident_id}`),
      successMsg: 'Malicious external IP 198.51.100.44 added to drop list.',
    },
    {
      key: 'forensics',
      name: 'Capture Memory Triage',
      target: incident.host,
      icon: <IconDatabase className="w-4 h-4 text-cyan-400" />,
      desc: 'Acquire volatile memory snapshot and process execution tree for analysis.',
      color: 'cyan',
      run: () => captureForensics(incident.host),
      successMsg: `Memory triage package acquired from ${incident.host} (512 MB).`,
    },
  ]

  const playbooks = [
    {
      name: 'Rapid Ransomware Containment',
      icon: <IconZap className="w-4 h-4 text-amber-400" />,
      estTime: '1.2s',
      steps: ['Host Network Quarantine', 'User Token Invalidation', 'C2 IP Block Rule', 'Memory Triage Dump'],
      run: () => triggerPlaybook('Rapid Ransomware Containment', incident.incident_id, incident.host, incident.user),
    },
    {
      name: 'Credential Abuse Lockout',
      icon: <IconKey className="w-4 h-4 text-yellow-400" />,
      estTime: '0.8s',
      steps: ['Lock User Directory Account', 'Kill Active Web Sessions', 'Require MFA Step-up', 'Notify Security Lead'],
      run: () => triggerPlaybook('Credential Abuse Lockout', incident.incident_id, incident.host, incident.user),
    },
    {
      name: 'Lateral Movement Isolation',
      icon: <IconNetwork className="w-4 h-4 text-blue-400" />,
      estTime: '1.5s',
      steps: ['Isolate Source Endpoint', 'Block Subnet SMB/RDP Traffic', 'Export WinEvent Security Logs'],
      run: () => triggerPlaybook('Lateral Movement Isolation', incident.incident_id, incident.host, incident.user),
    }
  ]

  return (
    <div className="glass-card p-5 space-y-5 border border-white/10 bg-surface-900/90 shadow-xl">
      {/* Header & Status Lifecycle */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-white/10 pb-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="p-1 rounded-lg bg-surface-800 border border-white/10 text-cyan-400">
              <IconSettings className="w-4 h-4" />
            </span>
            <h3 className="text-sm font-bold text-white tracking-wider uppercase font-mono">SOAR Remediation Console</h3>
          </div>
          <p className="text-xs text-slate-400 mt-1">Automated response playbooks & containment workflows</p>
        </div>

        {/* Status Lifecycle selector */}
        <div className="flex items-center gap-1 bg-surface-800/80 p-1 rounded-lg border border-white/5">
          <span className="text-xs text-slate-500 px-2 font-mono">STATUS:</span>
          {STATUS_FLOW.map(s => {
            const isSelected = currentStatus === s.key
            return (
              <button
                key={s.key}
                disabled={statusLoading}
                onClick={() => handleStatusChange(s.key)}
                className={`
                  text-xs px-2.5 py-1 rounded transition-all font-medium capitalize
                  ${isSelected
                    ? `${s.color} border shadow-sm`
                    : 'text-slate-400 hover:text-slate-200 hover:bg-white/5'
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
      <div className="flex items-center gap-2 border-b border-white/10 pb-2 text-xs">
        <button
          onClick={() => setActiveTab('actions')}
          className={`px-3 py-1.5 rounded-lg transition-colors font-medium flex items-center gap-1.5 ${
            activeTab === 'actions' ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30' : 'text-slate-400 hover:text-white'
          }`}
        >
          <IconTarget className="w-3.5 h-3.5" />
          <span>Immediate Actions</span>
        </button>
        <button
          onClick={() => setActiveTab('playbooks')}
          className={`px-3 py-1.5 rounded-lg transition-colors font-medium flex items-center gap-1.5 ${
            activeTab === 'playbooks' ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30' : 'text-slate-400 hover:text-white'
          }`}
        >
          <IconZap className="w-3.5 h-3.5" />
          <span>Automated Playbooks</span>
        </button>
        <button
          onClick={() => setActiveTab('audit')}
          className={`px-3 py-1.5 rounded-lg transition-colors font-medium flex items-center gap-1.5 ${
            activeTab === 'audit' ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30' : 'text-slate-400 hover:text-white'
          }`}
        >
          <IconFileText className="w-3.5 h-3.5" />
          <span>Remediation Log ({auditLog.length})</span>
        </button>
      </div>

      {/* Tab 1: Individual Response Actions */}
      {activeTab === 'actions' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {actions.map(act => {
            const state = actionStates[act.key] || 'idle'
            const isDone = state === 'done'
            const isRunning = state === 'running'

            return (
              <div
                key={act.key}
                className="p-4 rounded-lg bg-surface-800/40 border border-white/5 flex flex-col justify-between gap-3 hover:border-white/10 transition-colors"
              >
                <div className="space-y-1">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2 font-medium text-sm text-slate-200">
                      <span>{act.icon}</span>
                      <span>{act.name}</span>
                    </div>
                    <span className="text-xs font-mono text-cyan-400/90 bg-cyan-950/40 px-2 py-0.5 rounded border border-cyan-800/30 truncate max-w-[140px]">
                      {act.target}
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 leading-relaxed">{act.desc}</p>
                </div>

                <div className="flex items-center justify-between pt-2 border-t border-white/5">
                  <span className="text-xs text-slate-400 font-mono">
                    {isDone ? 'Executed' : isRunning ? 'Executing…' : 'Ready'}
                  </span>
                  <button
                    disabled={isRunning || isDone}
                    onClick={() => runAction(act.key, act.run, act.target, act.name, act.successMsg)}
                    className={`
                      px-3 py-1.5 text-xs font-semibold rounded-md transition-all duration-200 flex items-center gap-1.5
                      ${isDone
                        ? 'bg-green-950/50 text-green-400 border border-green-500/40 cursor-default'
                        : isRunning
                        ? 'bg-orange-950/50 text-orange-400 border border-orange-500/40 cursor-wait animate-pulse'
                        : 'bg-red-950/40 hover:bg-red-900/60 text-red-300 hover:text-white border border-red-500/30 hover:border-red-400 active:scale-95'
                      }
                    `}
                  >
                    {isDone ? 'Applied' : isRunning ? 'Running…' : `Execute ${act.name}`}
                  </button>
                </div>
              </div>
            )
          })}
        </div>
      )}

      {/* Tab 2: Automated Playbooks */}
      {activeTab === 'playbooks' && (
        <div className="space-y-3">
          {playbooks.map((pb, idx) => {
            const state = actionStates[`pb_${idx}`] || 'idle'
            const isDone = state === 'done'
            const isRunning = state === 'running'

            return (
              <div
                key={pb.name}
                className="p-4 rounded-lg bg-surface-800/40 border border-white/5 flex flex-col sm:flex-row sm:items-center justify-between gap-4"
              >
                <div className="space-y-2 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="text-base">{pb.icon}</span>
                    <h4 className="text-sm font-semibold text-white">{pb.name}</h4>
                    <span className="text-xs text-slate-500 font-mono bg-surface-700/50 px-2 py-0.5 rounded">
                      ~{pb.estTime}
                    </span>
                  </div>
                  <div className="flex items-center gap-2 flex-wrap text-xs text-slate-400">
                    {pb.steps.map((step, sIdx) => (
                      <span key={step} className="flex items-center gap-1">
                        <span className="text-cyan-400 text-xs">{(sIdx + 1)}.</span> {step}
                        {sIdx < pb.steps.length - 1 && <span className="text-slate-600">→</span>}
                      </span>
                    ))}
                  </div>
                </div>

                <button
                  disabled={isRunning || isDone}
                  onClick={() => runAction(`pb_${idx}`, pb.run, incident.host, pb.name, `Playbook ${pb.name} completed successfully.`)}
                  className={`
                    px-4 py-2 text-xs font-semibold rounded-lg transition-all duration-200 flex-shrink-0 flex items-center gap-1.5
                    ${isDone
                      ? 'bg-green-950/60 text-green-400 border border-green-500/40'
                      : isRunning
                      ? 'bg-orange-950/60 text-orange-400 border border-orange-500/40 animate-pulse'
                      : 'bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white shadow-lg shadow-cyan-500/20 active:scale-95'
                    }
                  `}
                >
                  {isDone ? 'Playbook Completed' : isRunning ? 'Orchestrating…' : 'Run Full Playbook'}
                </button>
              </div>
            )
          })}
        </div>
      )}

      {/* Tab 3: Remediation Audit Log */}
      {activeTab === 'audit' && (
        <div className="space-y-2 max-h-60 overflow-y-auto pr-1">
          {auditLog.map(entry => (
            <div
              key={entry.id}
              className="p-2.5 rounded bg-surface-800/30 border border-white/5 flex items-start justify-between gap-3 text-xs"
            >
              <div className="space-y-0.5">
                <div className="flex items-center gap-2">
                  <span className="font-semibold text-slate-200">{entry.action}</span>
                  <span className="font-mono text-cyan-400 bg-cyan-950/40 px-1.5 rounded">{entry.target}</span>
                  <span className="text-green-400 font-medium">{entry.status}</span>
                </div>
                <p className="text-slate-400 text-xs">{entry.detail}</p>
              </div>
              <span className="text-slate-600 font-mono text-xs flex-shrink-0">{entry.time}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
