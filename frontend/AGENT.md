# AGENT.md — SENTRY Frontend Architecture & Guide

> **Authoritative Context Document** for any AI agent or engineer developing, extending, or maintaining the SENTRY frontend application.

---

## 1. Architecture & Stack Overview

The **SENTRY Frontend** is an enterprise-grade, real-time Security Operations Center (SOC) dashboard. It provides continuous incident monitoring, hybrid ML + signature anomaly visualization, User & Entity Behavior Analytics (UEBA), dynamic fleet discovery, and automated SOAR response playbooks.

| Layer | Technology | Purpose |
|---|---|---|
| **Framework** | **React 18** (`react`, `react-dom`) | Component-driven UI, state management, hooks |
| **Build Tool** | **Vite 8** (`@vitejs/plugin-react`) | Sub-second HMR, optimized production asset bundling |
| **Routing** | **React Router v6** (`HashRouter`) | Client-side routing: `/` (Overview), `/incident/:id` (Deep Dive) |
| **Styling** | **Tailwind CSS v3** + PostCSS | Dark SIEM theme, custom glassmorphism, responsive grid |
| **Visualizations**| **Pure Responsive SVG** | Zero heavy charting libraries; lightweight Bézier area charts, radial donuts & sparklines |
| **Live Telemetry**| **Native WebSocket** | Push-based event and incident streaming with reconnect backoff |
| **API Client** | **Fetch API + Normalization** | Resilient schema adapter connecting to FastAPI backend |

---

## 2. Directory Tree

```
frontend/
├── Dockerfile
├── package.json
├── vite.config.js               # Proxy /api → backend:8000, host 0.0.0.0, PostCSS Tailwind
├── tailwind.config.js           # Dark SIEM theme, cyber accents, severity color tokens
├── index.html                   # Title: "Sentry | SOC Dashboard", Google Fonts (Inter, JetBrains Mono)
├── AGENT.md                     # ⭐ This authoritative frontend guide
└── src/
    ├── index.css                # Glassmorphism, cyber glow filters, severity badges, custom scrollbars
    ├── main.jsx                 # React 18 StrictMode entry point
    ├── App.jsx                  # HashRouter: / (Overview) and /incident/:id (Incident Detail)
    ├── api/
    │   └── incidents.js         # REST client, dynamic host resolution, schema normalization & dossier export
    ├── ws/
    │   └── incidentSocket.js   # Native WebSocket client with dynamic IP resolution & backoff
    ├── mocks/
    │   └── incidents.mock.json  # Emergency offline mock data (fallback only)
    ├── components/
    │   ├── StatCard.jsx         # Executive KPI metric cards with dynamic colored accents
    │   ├── SeverityBadge.jsx    # Severity badge (critical/high/medium/low) with radar pulse
    │   ├── IncidentTable.jsx    # Sortable incident list with inline risk meter & new item flash
    │   ├── LiveFeedPanel.jsx    # Auto-scrolling real-time telemetry feed with MITRE & attack icons
    │   ├── SoarMetricsBar.jsx   # Real-time SOAR automation KPI bar (MTTD, MTTR, Fleet Assets)
    │   ├── AttackTrendChart.jsx # 24h threat velocity SVG area graph computed from live timestamps
    │   ├── SeverityDonutChart.jsx # Radial SVG donut chart with center threat count
    │   ├── RiskyUsersPanel.jsx  # Dynamic UEBA risky identity ranking with SVG sparklines & 1-click lock
    │   ├── ConnectedDevicesPanel.jsx # ⭐ Real-time connected laptops & endpoints on the network
    │   ├── EventInjectorModal.jsx    # ⭐ Freeform actual event & telemetry reporter with AI preview
    │   ├── RemediationConsole.jsx   # Multi-tab SOAR playbook engine & immediate action buttons
    │   ├── RiskScoreBreakdown.jsx   # 4-component risk breakdown (Anomaly, Rule, Severity, Correlation)
    │   └── EvidenceTimeline.jsx     # Chronological attack sequence with MITRE tags
    └── pages/
        ├── SOCOverview.jsx      # Main dashboard: metrics, charts, table, and 3-tab right panel
        └── IncidentDetail.jsx   # Deep-dive screen: header card, SOAR console, dossier & evidence
```

---

## 3. Critical Architectural Rules & Guidelines

### Rule 1: No Hardcoded Mock Data in Live Telemetry
- All visual components (**AttackTrendChart**, **SoarMetricsBar**, **RiskyUsersPanel**, **ConnectedDevicesPanel**) must compute their metrics dynamically from live telemetry (`incidents` and `streamedEvents`).
- **Do NOT** re-introduce fake names (e.g. `eve.patel`, `alice.chen`) or hardcoded device strings (e.g. `'4 hosts'`). If no events exist, show a clean, green baseline state.

### Rule 2: Non-Secure HTTP Context Compatibility
- In local networks (e.g. mobile hotspot or Wi-Fi IP `http://10.x.x.x:5173`), modern browsers treat the page as an **Insecure Context** (`window.isSecureContext === false`).
- **Never call `crypto.randomUUID()` directly!** It is undefined in insecure contexts and will crash.
- Always use the safe UUID generator helper:
  ```javascript
  function generateSafeUUID() {
    if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
      try { return crypto.randomUUID() } catch {}
    }
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
      const r = Math.random() * 16 | 0
      const v = c === 'x' ? r : (r & 0x3 | 0x8)
      return v.toString(16)
    })
  }
  ```

### Rule 3: Dynamic IP & Hostname Resolution
- Secondary laptops and mobile devices open the frontend via the host's IP address (e.g. `http://10.211.2.190:5173`).
- **Never hardcode `http://localhost:8000` or `ws://localhost:8000`!**
- Resolve the backend host dynamically using `window.location.hostname`:
  ```javascript
  // REST API
  const API_BASE = import.meta.env.VITE_API_URL || 
    (typeof window !== 'undefined' ? `${window.location.protocol}//${window.location.hostname}:8000` : 'http://localhost:8000')

  // WebSocket
  const defaultWsBase = typeof window !== 'undefined'
    ? `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.hostname}:8000`
    : 'ws://localhost:8000'
  const WS_BASE = import.meta.env.VITE_WS_URL || defaultWsBase
  ```

---

## 4. Key Components Deep Dive

### 4.1. `SOCOverview.jsx` (Main Dashboard)
- Coordinates top-level state: `incidents`, `streamedEvents`, `newIds`, `wsStatus`.
- Connects to native WebSocket on mount via `createIncidentSocket()`.
- Renders:
  - Top header with live WebSocket status pill (`Live` / `Offline`) and "+ Add Security Event & Analyze" trigger.
  - `SoarMetricsBar`: 5 real-time KPI metrics.
  - Left column: `StatCard` row, `AttackTrendChart`, `SeverityDonutChart`, `IncidentTable`.
  - Right column: 3 tabbed panels:
    1. **Live Event Feed** (`LiveFeedPanel.jsx`)
    2. **Risky Users** (`RiskyUsersPanel.jsx`)
    3. **Connected Devices** (`ConnectedDevicesPanel.jsx`)

### 4.2. `EventInjectorModal.jsx` (Actual Event & Threat Reporter)
- Allows users on primary or secondary laptops to report **actual events** in plain text or paste raw logs.
- Captures:
  - `host`: Target computer / machine name.
  - `user`: Account involved (e.g. `admin`, `root`, `developer`).
  - `sourceType`: Endpoint OS, Network Flow, Auth Server, Cloud.
  - `eventText`: Freeform description or log snippet.
- Client-side pre-classifier extracts features (`failed_login_count`, `bytes_sent`, `privilege_change`, `lsass_access`) and assigns correct `event_type` (`failed_login`, `privilege_escalation`, `data_exfiltration`, `credential_access`, `normal_login`).
- Communicates with `POST /events` on FastAPI backend.
- Displays live verdict: Rule breaches, ML Anomaly Score, MITRE ATT&CK techniques, and AI Threat Analyst executive assessment.

### 4.3. `ConnectedDevicesPanel.jsx` (Real-Time Fleet Discovery)
- Dynamically discovers all communicating hosts across the network.
- Fetches `/analytics/devices` from backend and merges with real-time hosts seen in `incidents` and `streamedEvents`.
- Displays:
  - Machine role (Primary Server Controller vs Connected Client Laptop).
  - Security status (`🟢 HEALTHY / NOMINAL`, `🚨 THREAT DETECTED`, `🟡 MONITORED`).
  - IP address, last seen timestamp, and telemetry event counters.

### 4.4. `RiskyUsersPanel.jsx` (Dynamic UEBA)
- Computes risky identities directly from live incident risk scores and event volume.
- Shows real account names (`admin`, `root`, `svc_backup`, etc.), associated hostnames, and threat level.
- Renders responsive pure SVG sparkline showing risk progression.
- Provides 1-click **"Lock"** action invoking `POST /actions/revoke-user`.
- Displays a clean baseline state (`✓ Zero Flagged Identities`) when no threats are detected.

### 4.5. `LiveFeedPanel.jsx` (Auto-Scrolling Real-Time Telemetry)
- Merges raw streamed WebSocket events with correlated incident events, deduplicated by `event_id`.
- Automatically scrolls to newest events at the top.
- Visual icon mapping:
  - `failed_login` / `auth_failure` &rarr; `🔑`
  - `privilege_escalation` &rarr; `👑`
  - `data_exfiltration` &rarr; `📤`
  - `credential_access` &rarr; `💾`
  - `normal_login` &rarr; `🟢` (Clean green baseline)
  - Generic anomaly &rarr; `⚠️`

### 4.6. `AttackTrendChart.jsx` (24h Velocity SVG Area Graph)
- Computes real 24-hour hourly buckets (`00:00` to `23:00`) from actual incident timestamps.
- Zero fake points: displays `0 / hr`, `0 Events`, and `🟢 Baseline Clean` when clean.
- Spikes dynamically as attacks are dispatched.

---

## 5. Normalization Layer (`src/api/incidents.js`)

The normalization layer isolates the frontend from schema differences between backend SQLite/PostgreSQL models and frontend components:

```javascript
export function normalizeIncident(inc) {
  // Handles:
  // 1. Integer severity (1-5) vs string severity ('critical', 'high', 'medium', 'low')
  // 2. Normalized risk scores (0.0 to 1.0) vs integer (0 to 100)
  // 3. MITRE techniques formatted as strings or objects ({ mitre_id, technique })
  // 4. Fallback hostname and username resolution
}
```

### Forensic Dossier Generator (`generateIncidentDossier`)
- Generates an enterprise-standard, SOC Tier-2 forensic audit dossier in JSON format.
- Downloadable directly by analysts via the UI for legal hold and regulatory chain of custody.

---

## 6. Build & Development Commands

From the `frontend/` directory:

```bash
# Install dependencies
npm install

# Run local development server (listening on 0.0.0.0:5173 for LAN/hotspot access)
npm run dev -- --host 0.0.0.0 --port 5173

# Production build verification (always run to check for JSX/syntax errors)
npm run build

# Preview production build
npm run preview
```
