/**
 * WebSocket client for real-time incident streaming.
 *
 * Supports both /ws/incidents (default stub) and /ws (Tanmay's backend)
 * with automatic endpoint fallback and exponential backoff.
 *
 * Usage:
 *   const socket = createIncidentSocket({
 *     onIncident: (incident) => { ... },
 *     onStatus: (status) => { ... },  // 'connecting' | 'connected' | 'disconnected' | 'error'
 *   })
 *   socket.connect()
 *   // later:
 *   socket.disconnect()
 */

import { normalizeIncident } from '../api/incidents'

const defaultWsBase = typeof window !== 'undefined'
  ? `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.hostname}:8000`
  : 'ws://localhost:8000'
const WS_BASE = import.meta.env.VITE_WS_URL || defaultWsBase
const WS_PATHS = ['/ws/incidents', '/ws']

const BACKOFF_DELAYS = [1000, 2000, 4000, 8000, 15000, 30000]

export function createIncidentSocket({ onIncident, onEvent, onAction, onStatus }) {
  let ws = null
  let retryCount = 0
  let pathIndex = 0
  let shouldReconnect = true
  let reconnectTimer = null

  function getDelay() {
    return BACKOFF_DELAYS[Math.min(retryCount, BACKOFF_DELAYS.length - 1)]
  }

  function getWsUrl() {
    const path = WS_PATHS[pathIndex % WS_PATHS.length]
    return `${WS_BASE}${path}`
  }

  function connect() {
    if (ws && ws.readyState === WebSocket.CONNECTING) return

    onStatus?.('connecting')

    const currentUrl = getWsUrl()

    try {
      ws = new WebSocket(currentUrl)

      ws.onopen = () => {
        retryCount = 0
        onStatus?.('connected')
        console.log('[IncidentSocket] Connected to', currentUrl)
      }

      ws.onmessage = (event) => {
        try {
          const raw = JSON.parse(event.data)

          // 1. Host isolation / action response
          if (raw.type === 'action') {
            onAction?.(raw.data || raw)
            return
          }

          // 2. Real-time telemetry event from generators (Tanmay backend)
          if (raw.type === 'event') {
            const ev = raw.data || raw
            const normalizedEvent = {
              event_id: String(ev.event_id || ev.id || Math.random().toString(36).slice(2)),
              type: ev.event_type || ev.type || 'anomaly_detected',
              timestamp: ev.timestamp || new Date().toISOString(),
              host: ev.host_id || ev.host || 'unknown-host',
              severity: typeof ev.severity === 'number'
                ? (ev.severity >= 4 ? 'critical' : ev.severity === 3 ? 'high' : ev.severity === 2 ? 'medium' : 'low')
                : (ev.severity || 'low'),
              detail: ev.features?.message || ev.raw_data?.log || ev.detail || `${ev.event_type || 'Event'} on ${ev.host_id || 'host'}`,
              anomaly_score: ev.anomaly_score != null ? (ev.anomaly_score > 1 ? ev.anomaly_score / 100 : ev.anomaly_score) : 0.75,
              rule_score: ev.rule_score != null ? (ev.rule_score > 1 ? ev.rule_score / 100 : ev.rule_score) : 0.8,
              incident_id: ev.incident_id || 'LIVE-FEED',
            }
            onEvent?.(normalizedEvent)
            return
          }

          // 3. Security incident object
          const payload = raw?.data || raw
          if (payload) {
            const normalized = normalizeIncident(payload)
            if (normalized) {
              onIncident?.(normalized)
            }
          }
        } catch (err) {
          console.warn('[IncidentSocket] Failed to parse message:', err)
        }
      }

      ws.onclose = (event) => {
        onStatus?.('disconnected')
        console.log('[IncidentSocket] Disconnected from', currentUrl, event.code, event.reason)

        if (shouldReconnect) {
          // If we failed without establishing connection, try alternative path
          if (retryCount % 2 === 1) {
            pathIndex++
          }
          const delay = getDelay()
          retryCount++
          console.log(`[IncidentSocket] Reconnecting in ${delay}ms (attempt ${retryCount})`)
          reconnectTimer = setTimeout(connect, delay)
        }
      }

      ws.onerror = (err) => {
        onStatus?.('error')
        console.error('[IncidentSocket] WebSocket error on', currentUrl, err)
        // ws.onclose will fire after onerror, which handles reconnect
      }
    } catch (err) {
      onStatus?.('error')
      console.error('[IncidentSocket] Failed to create WebSocket:', err)

      if (shouldReconnect) {
        pathIndex++
        const delay = getDelay()
        retryCount++
        reconnectTimer = setTimeout(connect, delay)
      }
    }
  }

  function disconnect() {
    shouldReconnect = false
    if (reconnectTimer) clearTimeout(reconnectTimer)
    if (ws) {
      ws.close(1000, 'Client disconnected')
      ws = null
    }
    onStatus?.('disconnected')
  }

  function getStatus() {
    if (!ws) return 'disconnected'
    switch (ws.readyState) {
      case WebSocket.CONNECTING: return 'connecting'
      case WebSocket.OPEN: return 'connected'
      case WebSocket.CLOSING: return 'disconnected'
      case WebSocket.CLOSED: return 'disconnected'
      default: return 'unknown'
    }
  }

  return { connect, disconnect, getStatus }
}
