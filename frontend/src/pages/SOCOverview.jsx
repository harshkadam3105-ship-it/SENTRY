import { useState, useEffect, useCallback, useRef } from 'react'
import StatCard from '../components/StatCard'
import IncidentTable from '../components/IncidentTable'
import LiveFeedPanel from '../components/LiveFeedPanel'
import SoarMetricsBar from '../components/SoarMetricsBar'
import AttackTrendChart from '../components/AttackTrendChart'
import SeverityDonutChart from '../components/SeverityDonutChart'
import RiskyUsersPanel from '../components/RiskyUsersPanel'
import { getIncidents } from '../api/incidents'
import { createIncidentSocket } from '../ws/incidentSocket'

/**
 * SOCOverview — main dashboard page
 * Shows stat cards, incident table, live event feed, and enterprise SOAR analytics.
 */

export default function SOCOverview() {
  const [incidents, setIncidents] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [wsStatus, setWsStatus] = useState('disconnected')
  const [newIds, setNewIds] = useState(new Set())
  const [streamedEvents, setStreamedEvents] = useState([])
  const [rightPanelTab, setRightPanelTab] = useState('feed') // 'feed' | 'ueba'
  const socketRef = useRef(null)

  // Load initial incidents
  useEffect(() => {
    getIncidents()
      .then(data => {
        setIncidents(data)
        setLoading(false)
      })
      .catch(err => {
        setError(err.message)
        setLoading(false)
      })
  }, [])

  // WebSocket: prepend new incidents
  const handleIncident = useCallback((incident) => {
    setIncidents(prev => {
      const exists = prev.find(i => i.incident_id === incident.incident_id)
      if (exists) {
        // Update existing
        return prev.map(i => i.incident_id === incident.incident_id ? incident : i)
      }
      // New — prepend and mark for animation
      setNewIds(ids => {
        const next = new Set(ids)
        next.add(incident.incident_id)
        // Clear the animation marker after 1s
        setTimeout(() => {
          setNewIds(current => {
            const cleared = new Set(current)
            cleared.delete(incident.incident_id)
            return cleared
          })
        }, 1000)
        return next
      })
      return [incident, ...prev]
    })
  }, [])

  // WebSocket: handle real-time telemetry events
  const handleEvent = useCallback((event) => {
    setStreamedEvents(prev => [event, ...prev.slice(0, 49)])
  }, [])

  useEffect(() => {
    const socket = createIncidentSocket({
      onIncident: handleIncident,
      onEvent: handleEvent,
      onStatus: setWsStatus,
    })
    socket.connect()
    socketRef.current = socket

    return () => socket.disconnect()
  }, [handleIncident, handleEvent])

  // Compute stats
  const totalIncidents = incidents.length
  const criticalCount = incidents.filter(i => i.severity === 'critical').length
  const highCount = incidents.filter(i => i.severity === 'high').length
  const avgRisk = incidents.length
    ? (incidents.reduce((s, i) => s + i.risk_score, 0) / incidents.length)
    : 0

  return (
    <div className="min-h-screen bg-surface-900 flex flex-col">
      {/* Top nav */}
      <header className="border-b border-white/5 bg-surface-800/60 backdrop-blur-sm sticky top-0 z-20">
        <div className="max-w-screen-2xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center text-sm font-bold text-white shadow-lg shadow-cyan-500/30">
              S
            </div>
            <div>
              <span className="text-base font-bold text-white tracking-tight">Sentry</span>
              <span className="text-xs text-slate-500 ml-2">SOC Dashboard</span>
            </div>
          </div>

          <div className="flex items-center gap-4">
            {/* WS Status */}
            <div className="flex items-center gap-1.5">
              <span className={`w-2 h-2 rounded-full ${
                wsStatus === 'connected' ? 'bg-green-400 animate-pulse' :
                wsStatus === 'connecting' ? 'bg-yellow-400 animate-pulse' :
                'bg-slate-600'
              }`} />
              <span className="text-xs text-slate-400">
                {wsStatus === 'connected' ? 'Live' : wsStatus === 'connecting' ? 'Connecting…' : 'Offline'}
              </span>
            </div>

            <div className="text-xs text-slate-500 font-mono">
              {new Date().toLocaleDateString('en-US', { weekday: 'short', month: 'short', day: 'numeric' })}
            </div>
          </div>
        </div>
      </header>

      <main className="flex-1 max-w-screen-2xl mx-auto w-full px-6 py-6 flex flex-col gap-6">
        {/* Page title */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-xl font-bold text-white">Incident Overview</h1>
            <p className="text-sm text-slate-500 mt-0.5">Real-time security incident monitoring</p>
          </div>
          {criticalCount > 0 && (
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-red-950/50 border border-red-500/30 animate-pulse">
              <span className="w-2 h-2 rounded-full bg-red-500" />
              <span className="text-sm font-semibold text-red-400">{criticalCount} CRITICAL</span>
            </div>
          )}
        </div>

        {/* SOAR Performance & Automation KPI Bar */}
        <SoarMetricsBar incidents={incidents} />

        {/* Stat cards */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <StatCard
            label="Total Incidents"
            value={totalIncidents}
            sub="all time"
            icon="📊"
            accentColor="cyber"
          />
          <StatCard
            label="Critical"
            value={criticalCount}
            sub="need immediate action"
            icon="🚨"
            accentColor="red"
            highlight={criticalCount > 0}
          />
          <StatCard
            label="High Severity"
            value={highCount}
            sub="need review"
            icon="⚠️"
            accentColor="orange"
          />
          <StatCard
            label="Avg Risk Score"
            value={`${Math.round(avgRisk * 100)}`}
            sub="out of 100"
            icon="🎯"
            accentColor={avgRisk >= 0.7 ? 'red' : avgRisk >= 0.5 ? 'orange' : 'green'}
          />
        </div>

        {/* Visual Analytics Row: 24h Attack Flow + Severity Donut */}
        <div className="grid grid-cols-1 lg:grid-cols-[1fr_360px] gap-4">
          <AttackTrendChart incidents={incidents} events={streamedEvents} />
          <SeverityDonutChart incidents={incidents} />
        </div>

        {/* Main content: table + tabbed right column (Live Feed / UEBA Risky Users) */}
        <div className="flex-1 grid grid-cols-1 xl:grid-cols-[1fr_380px] gap-4" style={{ minHeight: 0 }}>
          {/* Incident table */}
          <div className="flex flex-col gap-3">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold text-slate-300">
                Incidents
                <span className="ml-2 text-slate-600 font-normal">({totalIncidents})</span>
              </h2>
            </div>

            {loading && (
              <div className="glass-card p-8 text-center text-slate-500">
                <div className="animate-spin w-8 h-8 border-2 border-cyan-500 border-t-transparent rounded-full mx-auto mb-3" />
                Loading incidents…
              </div>
            )}

            {error && (
              <div className="glass-card p-6 border border-red-500/20 text-center">
                <div className="text-red-400 font-medium mb-1">Failed to load incidents</div>
                <div className="text-slate-500 text-sm">{error}</div>
              </div>
            )}

            {!loading && !error && (
              <IncidentTable incidents={incidents} newIds={newIds} />
            )}
          </div>

          {/* Right column: Tabbed between Live Feed and Risky Users (UEBA) */}
          <div className="flex flex-col gap-3" style={{ maxHeight: '78vh' }}>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-1 bg-surface-800 p-0.5 rounded-lg border border-white/5 text-xs">
                <button
                  onClick={() => setRightPanelTab('feed')}
                  className={`px-3 py-1 rounded transition-colors font-medium flex items-center gap-1.5 ${
                    rightPanelTab === 'feed' ? 'bg-cyan-500/20 text-cyan-300' : 'text-slate-400 hover:text-white'
                  }`}
                >
                  <span className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse" />
                  Live Event Feed
                </button>
                <button
                  onClick={() => setRightPanelTab('ueba')}
                  className={`px-3 py-1 rounded transition-colors font-medium flex items-center gap-1.5 ${
                    rightPanelTab === 'ueba' ? 'bg-cyan-500/20 text-cyan-300' : 'text-slate-400 hover:text-white'
                  }`}
                >
                  <span>👤</span> Risky Users
                </button>
              </div>
            </div>

            <div className="flex-1" style={{ minHeight: 0, maxHeight: '68vh' }}>
              {rightPanelTab === 'feed' ? (
                <LiveFeedPanel incidents={incidents} streamedEvents={streamedEvents} wsStatus={wsStatus} />
              ) : (
                <RiskyUsersPanel />
              )}
            </div>
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-white/5 px-6 py-3">
        <div className="max-w-screen-2xl mx-auto flex items-center justify-between text-xs text-slate-600">
          <span>Sentry — Real-Time Threat Detection</span>
          <span className="font-mono">PS19 · Rohan's Track</span>
        </div>
      </footer>
    </div>
  )
}
