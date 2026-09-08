/**
 * API seam for incidents data.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * PHASE 4 SWAP INSTRUCTIONS:
 *   1. Set USE_LIVE_API = true (line below)
 *   2. Ensure VITE_API_URL env var points to the backend (e.g. http://localhost:8000)
 *   That's it. No other changes needed.
 * ─────────────────────────────────────────────────────────────────────────────
 */

// ← ONE-LINE SWAP: change to true when backend is live
const USE_LIVE_API = false

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000'

// Mock data import — only used when USE_LIVE_API = false
import mockIncidents from '../mocks/incidents.mock.json'

/**
 * Fetch all incidents.
 * @returns {Promise<Array>} Array of incident objects
 */
export async function getIncidents() {
  if (!USE_LIVE_API) {
    // Simulate network delay for realistic feel
    await new Promise(resolve => setTimeout(resolve, 120))
    return mockIncidents
  }

  const response = await fetch(`${API_BASE}/incidents`)
  if (!response.ok) {
    throw new Error(`Failed to fetch incidents: ${response.status} ${response.statusText}`)
  }
  return response.json()
}

/**
 * Fetch a single incident by ID.
 * @param {string} incidentId
 * @returns {Promise<Object>} Incident object
 */
export async function getIncidentById(incidentId) {
  if (!USE_LIVE_API) {
    await new Promise(resolve => setTimeout(resolve, 80))
    const incident = mockIncidents.find(i => i.incident_id === incidentId)
    if (!incident) throw new Error(`Incident ${incidentId} not found`)
    return incident
  }

  const response = await fetch(`${API_BASE}/incidents/${incidentId}`)
  if (!response.ok) {
    throw new Error(`Failed to fetch incident: ${response.status} ${response.statusText}`)
  }
  return response.json()
}

/**
 * Trigger host isolation action.
 * @param {string} host
 * @returns {Promise<Object>}
 */
export async function isolateHost(host) {
  if (!USE_LIVE_API) {
    await new Promise(resolve => setTimeout(resolve, 300))
    return { status: 'isolated', host, timestamp: new Date().toISOString() }
  }

  const response = await fetch(`${API_BASE}/actions/isolate-host`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ host }),
  })
  if (!response.ok) {
    throw new Error(`Failed to isolate host: ${response.status}`)
  }
  return response.json()
}
