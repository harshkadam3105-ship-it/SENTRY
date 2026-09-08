/**
 * API module for incidents data — live backend only.
 *
 * All requests go to the FastAPI backend at VITE_API_URL (default: http://localhost:8000).
 * Normalization layer handles schema drift between backend DB models and frontend components
 * (integer vs string severity, 0–100 vs 0–1 risk score, MITRE objects vs strings).
 */

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000'

/**
 * Normalizes any backend incident payload to the exact schema
 * expected by the Sentry frontend components.
 *
 * @param {Object} inc Raw incident object from backend
 * @returns {Object} Normalized incident object
 */
export function normalizeIncident(inc) {
  if (!inc) return null

  // 1. Incident ID
  const incident_id = String(inc.incident_id || inc.id || 'INC-UNKNOWN')

  // 2. Severity: handle integer (0–5) or string ('critical', 'high', 'medium', 'low')
  let severity = 'low'
  if (typeof inc.severity === 'number') {
    if (inc.severity >= 4) severity = 'critical'
    else if (inc.severity === 3) severity = 'high'
    else if (inc.severity === 2) severity = 'medium'
    else severity = 'low'
  } else if (typeof inc.severity === 'string') {
    const s = inc.severity.toLowerCase()
    if (['critical', 'high', 'medium', 'low'].includes(s)) severity = s
  }

  // 3. Risk Score: normalize to 0.0–1.0 range
  let risk_score = 0.0
  if (typeof inc.risk_score === 'number') {
    risk_score = inc.risk_score > 1 ? inc.risk_score / 100 : inc.risk_score
  } else if (typeof inc.risk_score === 'string') {
    const parsed = parseFloat(inc.risk_score)
    risk_score = !isNaN(parsed) ? (parsed > 1 ? parsed / 100 : parsed) : 0.0
  }
  risk_score = Math.max(0, Math.min(1, Math.round(risk_score * 100) / 100))

  // 4. Host & User
  const host = inc.host || inc.host_id || inc.hostname || 'workstation-1'
  const user = inc.user || inc.user_id || 'analyst'

  // 5. Timestamp
  const created_at = inc.created_at || inc.timestamp || new Date().toISOString()

  // 6. MITRE techniques: handle array of strings or objects ({ mitre_id, technique })
  const mitre_techniques = Array.isArray(inc.mitre_techniques)
    ? inc.mitre_techniques.map(t => {
        if (typeof t === 'string') return t
        if (t && typeof t === 'object') return t.mitre_id || t.technique || String(t)
        return String(t)
      })
    : []

  // 7. Correlated events
  const correlated_events = Array.isArray(inc.correlated_events)
    ? inc.correlated_events.map((e, idx) => ({
        event_id: e.event_id || e.id || `EVT-${incident_id}-${idx + 1}`,
        type: e.type || e.event_type || 'anomaly_detected',
        timestamp: e.timestamp || created_at,
        anomaly_score: e.anomaly_score != null ? (e.anomaly_score > 1 ? e.anomaly_score / 100 : e.anomaly_score) : 0,
        rule_score: e.rule_score != null ? (e.rule_score > 1 ? e.rule_score / 100 : e.rule_score) : 0,
        detail: e.detail || e.message || e.event_type || 'Security event detected',
      }))
    : Array.isArray(inc.event_ids)
    ? inc.event_ids.map((id) => ({
        event_id: String(id),
        type: 'anomaly_detected',
        timestamp: created_at,
        anomaly_score: 0.8,
        rule_score: 0.85,
        detail: `Correlated event ${id}`,
      }))
    : []

  // 8. Explanation
  const explanation = inc.explanation || inc.title || 'Security incident detected by correlation engine.'

  return {
    ...inc,
    incident_id,
    severity,
    risk_score,
    host,
    user,
    created_at,
    mitre_techniques,
    correlated_events,
    explanation,
  }
}

/**
 * Fetch all incidents from the backend.
 * @returns {Promise<Array>} Normalized incident array
 */
export async function getIncidents() {
  const response = await fetch(`${API_BASE}/incidents`)
  if (!response.ok) {
    throw new Error(`Failed to fetch incidents: ${response.status} ${response.statusText}`)
  }
  const data = await response.json()
  return Array.isArray(data) ? data.map(normalizeIncident) : []
}

/**
 * Fetch a single incident by ID.
 * Falls back to scanning the full list if a dedicated endpoint isn't available.
 * @param {string} incidentId
 * @returns {Promise<Object>} Normalized incident object
 */
export async function getIncidentById(incidentId) {
  // 1. Try dedicated GET /incidents/{id} endpoint
  try {
    const response = await fetch(`${API_BASE}/incidents/${incidentId}`)
    if (response.ok) {
      return normalizeIncident(await response.json())
    }
  } catch {
    // Fall through to list scan
  }

  // 2. Fallback: scan full list
  try {
    const all = await getIncidents()
    const found = all.find(i => i.incident_id === incidentId || i.id === incidentId)
    if (found) return found
  } catch {
    // Fall through to error
  }

  throw new Error(`Incident '${incidentId}' not found`)
}

/**
 * Trigger host isolation action.
 * Compatible with both /actions/isolate-host and /actions/isolate.
 * @param {string} host
 * @returns {Promise<Object>}
 */
export async function isolateHost(host) {
  // Try /actions/isolate-host first
  try {
    const response = await fetch(`${API_BASE}/actions/isolate-host`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ host, container_name: host }),
    })
    if (response.ok) return await response.json()
  } catch {
    // Fall through
  }

  // Fallback to /actions/isolate
  const response = await fetch(`${API_BASE}/actions/isolate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ container_name: host, host }),
  })
  if (!response.ok) {
    throw new Error(`Failed to isolate host: ${response.status}`)
  }
  return response.json()
}
