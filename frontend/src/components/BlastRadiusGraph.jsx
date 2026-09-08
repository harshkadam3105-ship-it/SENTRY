import { useState } from 'react'

/**
 * BlastRadiusGraph — Interactive Visual Cyber Threat Topology & Blast Radius.
 * Renders an enterprise threat map displaying:
 * External C2 Actor ⟷ Compromised Identity ⟷ Weaponized Host ⟷ Active Process ⟷ Subnet Targets
 * Supports interactive node inspection and 1-click contextual containment triggers.
 */

export default function BlastRadiusGraph({ incident, onExecuteAction }) {
  const [selectedNode, setSelectedNode] = useState(null)
  const [containedNodes, setContainedNodes] = useState(new Set())

  const hostName = incident?.host || 'workstation-14.corp'
  const userName = incident?.user || 'alice.chen'
  const c2Ip = '198.51.100.44'
  const processName = 'powershell.exe (PID 4912)'

  function toggleContained(nodeId) {
    setContainedNodes(prev => {
      const next = new Set(prev)
      if (next.has(nodeId)) next.delete(nodeId)
      else next.add(nodeId)
      return next
    })
  }

  const nodes = [
    {
      id: 'c2',
      type: 'adversary',
      label: 'Adversary C2',
      sublabel: c2Ip,
      geo: 'RO (Romania) · AS9009',
      status: containedNodes.has('c2') ? 'Null-Routed' : 'Active Ingress',
      x: 80,
      y: 110,
      color: '#ef4444',
      badge: 'APT29 / Cobalt Strike',
      actionLabel: 'Null-Route C2 IP',
    },
    {
      id: 'identity',
      type: 'user',
      label: 'Compromised User',
      sublabel: userName,
      geo: 'DevOps Engineering',
      status: containedNodes.has('identity') ? 'Tokens Revoked' : 'Active Session',
      x: 280,
      y: 60,
      color: '#f97316',
      badge: 'Privilege Escalation',
      actionLabel: 'Revoke IAM Session',
    },
    {
      id: 'host',
      type: 'endpoint',
      label: 'Weaponized Host',
      sublabel: hostName,
      geo: 'VLAN-Corp (10.0.4.14)',
      status: containedNodes.has('host') ? 'Isolated (Zero-Trust)' : 'Exposed to LAN',
      x: 280,
      y: 170,
      color: '#ec4899',
      badge: 'Ransomware Staging',
      actionLabel: 'Quarantine Host',
    },
    {
      id: 'process',
      type: 'process',
      label: 'Malicious Execution',
      sublabel: processName,
      geo: 'Memory Injection / LSASS',
      status: containedNodes.has('process') ? 'Killed & Quarantined' : 'Running',
      x: 480,
      y: 60,
      color: '#eab308',
      badge: 'PowerShell Beacon',
      actionLabel: 'Kill Process Tree',
    },
    {
      id: 'lateral1',
      type: 'target',
      label: 'Lateral Target 1',
      sublabel: 'srv-finance-02',
      geo: 'Subnet Storage (10.0.8.22)',
      status: 'Segmented / Shielded',
      x: 480,
      y: 170,
      color: '#06b6d4',
      badge: 'SMB Probe Blocked',
      actionLabel: 'Enforce Egress Rule',
    },
  ]

  const links = [
    { from: 'c2', to: 'identity', label: 'T1078 Valid Accounts' },
    { from: 'c2', to: 'host', label: 'T1021 Remote SSH' },
    { from: 'identity', to: 'process', label: 'T1059 Command Exec' },
    { from: 'host', to: 'process', label: 'Host Process Fork' },
    { from: 'host', to: 'lateral1', label: 'T1021 Lateral SMB' },
  ]

  return (
    <div className="soc-panel p-4 flex flex-col gap-3">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
        <div className="flex items-center gap-2">
          <div className="p-1 rounded bg-slate-850 border border-slate-800 text-cyan-400">
            <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="12" cy="12" r="10" />
              <line x1="2" y1="12" x2="22" y2="12" />
              <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
            </svg>
          </div>
          <div>
            <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider">
              Interactive Attack Vector Topology & Blast Radius
            </h3>
            <p className="text-[11px] text-slate-400">
              Live graph visualization of attacker infrastructure, compromised identity, and subnet exposure
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3 text-[11px] font-mono text-slate-400">
          <span className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-rose-500 animate-ping" />
            Active Threat Wave
          </span>
          <span className="text-slate-600">|</span>
          <span className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-emerald-400" />
            Contained Vector
          </span>
        </div>
      </div>

      {/* SVG Canvas */}
      <div className="relative w-full overflow-x-auto bg-slate-950/60 rounded border border-slate-850 p-2">
        <svg viewBox="0 0 580 230" className="w-full h-auto min-w-[540px] select-none">
          <defs>
            <linearGradient id="linkGradRed" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#ef4444" stopOpacity="0.8" />
              <stop offset="100%" stopColor="#f97316" stopOpacity="0.8" />
            </linearGradient>
            <linearGradient id="linkGradCyan" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#ec4899" stopOpacity="0.8" />
              <stop offset="100%" stopColor="#06b6d4" stopOpacity="0.8" />
            </linearGradient>
            <filter id="glow">
              <feGaussianBlur stdDeviation="3" result="coloredBlur" />
              <feMerge>
                <feMergeNode in="coloredBlur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>

          {/* Links */}
          {links.map((link, idx) => {
            const source = nodes.find(n => n.id === link.from)
            const target = nodes.find(n => n.id === link.to)
            if (!source || !target) return null

            const isContained = containedNodes.has(link.from) || containedNodes.has(link.to)

            return (
              <g key={idx}>
                <line
                  x1={source.x + 35}
                  y1={source.y + 20}
                  x2={target.x - 35}
                  y2={target.y + 20}
                  stroke={isContained ? '#10b981' : idx % 2 === 0 ? 'url(#linkGradRed)' : 'url(#linkGradCyan)'}
                  strokeWidth="2"
                  strokeDasharray={isContained ? 'none' : '4 4'}
                  className={isContained ? '' : 'animate-pulse'}
                />
                <text
                  x={(source.x + target.x) / 2}
                  y={(source.y + target.y) / 2 + 15}
                  textAnchor="middle"
                  fill="#64748b"
                  fontSize="8"
                  fontFamily="monospace"
                >
                  {link.label}
                </text>
              </g>
            )
          })}

          {/* Nodes */}
          {nodes.map(node => {
            const isContained = containedNodes.has(node.id)
            const isSelected = selectedNode?.id === node.id

            return (
              <g
                key={node.id}
                onClick={() => setSelectedNode(node)}
                className="cursor-pointer transition-transform duration-200"
                transform={`translate(${node.x - 55}, ${node.y - 15})`}
              >
                {/* Node Box */}
                <rect
                  width="110"
                  height="70"
                  rx="6"
                  fill="#0b111e"
                  stroke={isContained ? '#10b981' : isSelected ? '#38bdf8' : node.color}
                  strokeWidth={isSelected ? '2' : '1.5'}
                  filter={isSelected ? 'url(#glow)' : undefined}
                />

                {/* Status bar */}
                <rect
                  x="0"
                  y="0"
                  width="4"
                  height="70"
                  rx="2"
                  fill={isContained ? '#10b981' : node.color}
                />

                {/* Node Text */}
                <text x="12" y="16" fill="#94a3b8" fontSize="8" fontFamily="monospace" fontWeight="bold">
                  {node.label.toUpperCase()}
                </text>
                <text x="12" y="30" fill="#f1f5f9" fontSize="10" fontFamily="monospace" fontWeight="bold">
                  {node.sublabel}
                </text>
                <text x="12" y="44" fill="#64748b" fontSize="8" fontFamily="sans-serif">
                  {node.geo}
                </text>

                {/* Status pill inside node */}
                <rect
                  x="10"
                  y="52"
                  width="90"
                  height="12"
                  rx="3"
                  fill={isContained ? '#064e3b' : '#1e1b4b'}
                />
                <text
                  x="55"
                  y="61"
                  textAnchor="middle"
                  fill={isContained ? '#34d399' : '#c7d2fe'}
                  fontSize="7.5"
                  fontFamily="monospace"
                  fontWeight="bold"
                >
                  {node.status}
                </text>
              </g>
            )
          })}
        </svg>
      </div>

      {/* Selected Node Details & Quick Containment Trigger */}
      {selectedNode && (
        <div className="soc-panel-subtle p-3 rounded border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs font-mono">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span className="text-slate-200 font-bold">{selectedNode.label}:</span>
              <span className="text-cyan-400 font-semibold">{selectedNode.sublabel}</span>
              <span className="text-[10px] text-slate-400 bg-slate-900 px-1.5 py-0.5 rounded border border-slate-800">
                {selectedNode.badge}
              </span>
            </div>
            <p className="text-[11px] text-slate-400 font-sans">
              Context: {selectedNode.geo} · Current Posture: <span className={containedNodes.has(selectedNode.id) ? 'text-emerald-400 font-bold' : 'text-amber-400 font-bold'}>{selectedNode.status}</span>
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => toggleContained(selectedNode.id)}
              className={`px-3 py-1.5 rounded text-[11px] font-mono font-medium transition-colors border ${
                containedNodes.has(selectedNode.id)
                  ? 'bg-slate-850 hover:bg-slate-800 text-slate-300 border-slate-700'
                  : 'bg-red-950/70 hover:bg-red-900 text-red-300 border-red-500/40'
              }`}
            >
              {containedNodes.has(selectedNode.id) ? '↺ Release Quarantine' : `⚡ ${selectedNode.actionLabel}`}
            </button>
            <button
              onClick={() => setSelectedNode(null)}
              className="px-2 py-1.5 text-slate-500 hover:text-slate-300"
            >
              ✕
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
