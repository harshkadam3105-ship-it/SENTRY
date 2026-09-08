/**
 * WebSocket client for real-time incident streaming.
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

const WS_BASE = import.meta.env.VITE_WS_URL || 'ws://localhost:8000'
const WS_URL = `${WS_BASE}/ws/incidents`

const BACKOFF_DELAYS = [1000, 2000, 4000, 8000, 15000, 30000]

export function createIncidentSocket({ onIncident, onStatus }) {
  let ws = null
  let retryCount = 0
  let shouldReconnect = true
  let reconnectTimer = null

  function getDelay() {
    return BACKOFF_DELAYS[Math.min(retryCount, BACKOFF_DELAYS.length - 1)]
  }

  function connect() {
    if (ws && ws.readyState === WebSocket.CONNECTING) return

    onStatus?.('connecting')

    try {
      ws = new WebSocket(WS_URL)

      ws.onopen = () => {
        retryCount = 0
        onStatus?.('connected')
        console.log('[IncidentSocket] Connected to', WS_URL)
      }

      ws.onmessage = (event) => {
        try {
          const incident = JSON.parse(event.data)
          onIncident?.(incident)
        } catch (err) {
          console.warn('[IncidentSocket] Failed to parse message:', err)
        }
      }

      ws.onclose = (event) => {
        onStatus?.('disconnected')
        console.log('[IncidentSocket] Disconnected:', event.code, event.reason)

        if (shouldReconnect) {
          const delay = getDelay()
          retryCount++
          console.log(`[IncidentSocket] Reconnecting in ${delay}ms (attempt ${retryCount})`)
          reconnectTimer = setTimeout(connect, delay)
        }
      }

      ws.onerror = (err) => {
        onStatus?.('error')
        console.error('[IncidentSocket] WebSocket error:', err)
        // ws.onclose will fire after onerror, which handles reconnect
      }
    } catch (err) {
      onStatus?.('error')
      console.error('[IncidentSocket] Failed to create WebSocket:', err)

      if (shouldReconnect) {
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
