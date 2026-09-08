import { useState, useEffect, useMemo } from 'react'
import { getConnectedDevices } from '../api/incidents'
import { IconLaptop, IconServer } from './Icons'

export default function ConnectedDevicesPanel({ incidents = [], streamedEvents = [] }) {
  const [apiDevices, setApiDevices] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let mounted = true
    getConnectedDevices()
      .then(devs => {
        if (mounted) {
          setApiDevices(devs || [])
          setLoading(false)
        }
      })
      .catch(() => {
        if (mounted) setLoading(false)
      })
    return () => { mounted = false }
  }, [incidents.length, streamedEvents.length])

  // Merge API devices with any real-time hosts seen in incidents/events
  const devices = useMemo(() => {
    const map = new Map()

    // 1. Devices from API
    for (const d of apiDevices) {
      if (d && d.host) map.set(d.host, { ...d })
    }

    // 2. Devices from live incidents
    for (const inc of incidents) {
      const h = inc.host || inc.host_id
      if (!h) continue

      const riskVal = typeof inc.risk_score === 'number'
        ? (inc.risk_score <= 1.0 ? Math.round(inc.risk_score * 100) : Math.round(inc.risk_score))
        : 50

      if (!map.has(h)) {
        map.set(h, {
          host: h,
          role: 'Connected Client Endpoint',
          ip: inc.ip || '10.211.2.200',
          status: riskVal >= 60 ? 'compromised' : 'investigating',
          last_seen: 'Live Telemetry',
          event_count: 1,
          max_risk: riskVal,
        })
      } else {
        const item = map.get(h)
        item.event_count = (item.event_count || 0) + 1
        item.max_risk = Math.max(item.max_risk || 0, riskVal)
        if (riskVal >= 60) item.status = 'compromised'
      }
    }

    return Array.from(map.values())
  }, [apiDevices, incidents, streamedEvents])

  return (
    <div className="glass-card p-4 flex flex-col h-full">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-white/5 pb-3 mb-3">
        <div className="flex items-center gap-2">
          <IconLaptop className="w-4 h-4 text-cyan-400" /><div><h3 className="text-sm font-semibold text-slate-200">Connected Fleet Devices</h3>
            <p className="text-xs text-slate-500">Live network hosts communicating with SENTRY</p>
          </div>
        </div>
        <span className="text-xs font-mono text-cyan-400 bg-cyan-950/40 px-2 py-0.5 rounded border border-cyan-800/30">
          {devices.length} {devices.length === 1 ? 'Device' : 'Devices'}
        </span>
      </div>

      {/* Devices List */}
      <div className="flex-1 overflow-y-auto space-y-2.5 pr-1">
        {loading && devices.length === 0 ? (
          <div className="flex items-center justify-center h-40 text-xs text-slate-500">
            Detecting connected network devices…
          </div>
        ) : devices.length === 0 ? (
          <div className="text-center py-10 text-xs text-slate-500">
            No devices currently transmitting telemetry.
          </div>
        ) : (
          devices.map((d) => {
            const isCompromised = d.status === 'compromised'
            const isNominal = d.status === 'nominal'
            return (
              <div
                key={d.host}
                className={`p-3 rounded-xl border transition-all ${
                  isCompromised
                    ? 'bg-red-950/20 border-red-500/30 shadow-sm shadow-red-500/10'
                    : 'bg-surface-800/40 border-white/5 hover:border-white/10'
                }`}
              >
                <div className="flex items-center justify-between mb-1.5">
                  <div className="flex items-center gap-2">
                    {d.role?.includes("Server") ? <IconServer className="w-4 h-4 text-cyan-400" /> : <IconLaptop className="w-4 h-4 text-indigo-400" />}
                    <div>
                      <h4 className="text-xs font-bold text-white font-mono">{d.host}</h4>
                      <p className="text-[10px] text-slate-400">{d.role}</p>
                    </div>
                  </div>

                  <div className="text-right">
                    {isCompromised ? (
                      <span className="text-[10px] px-2 py-0.5 rounded font-bold bg-red-950 text-red-400 border border-red-500/40 flex items-center gap-1">
                        <span className="w-1.5 h-1.5 rounded-full bg-red-400 animate-pulse" />
                        THREAT DETECTED
                      </span>
                    ) : isNominal ? (
                      <span className="text-[10px] px-2 py-0.5 rounded font-bold bg-emerald-950 text-emerald-400 border border-emerald-500/40 flex items-center gap-1">
                        <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                        HEALTHY / NOMINAL
                      </span>
                    ) : (
                      <span className="text-[10px] px-2 py-0.5 rounded font-bold bg-amber-950 text-amber-400 border border-amber-500/40 flex items-center gap-1">
                        <span className="w-1.5 h-1.5 rounded-full bg-amber-400" />
                        MONITORED
                      </span>
                    )}
                  </div>
                </div>

                <div className="flex items-center justify-between pt-2 border-t border-white/5 text-[11px] text-slate-400">
                  <span className="font-mono text-cyan-400/80">IP: {d.ip || '10.211.2.x'}</span>
                  <span>{d.event_count || 1} {d.event_count === 1 ? 'event' : 'events'} logged</span>
                  <span className="text-slate-500">{d.last_seen || 'Active'}</span>
                </div>
              </div>
            )
          })
        )}
      </div>
    </div>
  )
}
