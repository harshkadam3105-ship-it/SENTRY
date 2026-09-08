# AGENTS.md — Sentry (PS19) · Rohan's Track

> This file is the authoritative context document for any AI agent (or human) picking up work on this repo.
> It covers the core platform architecture, pipeline integrations, and a detailed reference of all new frontend features and components built for the enterprise SOC dashboard.

---

## Platform Overview

**Sentry** is a real-time cybersecurity Threat Detection, Incident Correlation, and SOAR (Security Orchestration, Automation, and Response) platform.

| Attribute | Value |
|---|---|
| Frontend Stack | React 18 + Vite 8 + Tailwind CSS 3, native WebSocket |
| Backend Engine | FastAPI + Uvicorn (Python 3.11) + SQLAlchemy |
| Correlation Engine | 100-event sliding window, multi-stage attack correlation |
| Detection Engine | Hybrid ML Anomaly Detection (Isolation Forest) + Signature Rules |
| Database | PostgreSQL 15 (Docker) with SQLite fallback |
| Active Branch | `main` / `rohan/frontend` |
| Repository Remote | https://github.com/harshkadam3105-ship-it/SENTRY |

---

## High-Level Architecture & Pipeline Flow

```
   [ Telemetry / Attacks ]
(Auth, Network, Endpoint, Demo App)
               │
               ▼
     [ Detection Engine ]  ──► Ayaan: Rule Engine + ML Anomaly Detection (Isolation Forest)
               │
               ▼
    [ Correlation Engine ] ──► Harsh: 100-event sliding window correlates multi-stage attacks
               │
               ▼
       [ Risk Scorer ]     ──► Harsh: Weighted scoring (Anomaly + Rules + Correlation)
               │
               ▼  (Score ≥ 40)
    [ Incident Generator ] ──► Harsh: Auto-generates incident with MITRE ATT&CK tags
               │
               ▼
  [ WebSocket / REST API ] ──► Rohan: FastAPI backend broadcasts live streams
               │
               ▼
     [ Frontend Console ]  ──► Rohan: React 18 + Tailwind SIEM dashboard & SOAR playbooks
```

---

## Frontend File Tree

```
frontend/
├── Dockerfile
├── vite.config.js               # Proxy /api → backend:8000, host 0.0.0.0, PostCSS Tailwind
├── tailwind.config.js           # Dark SIEM theme, cyber accents, severity color tokens
├── index.html                   # Title: "Sentry | SOC Dashboard", Google Fonts (Inter, JetBrains Mono)
└── src/
    ├── index.css                # Glassmorphism, cyber glow filters, severity badges, custom scrollbars
    ├── main.jsx                 # React 18 StrictMode entry point
    ├── App.jsx                  # HashRouter: / (Overview) and /incident/:id (Incident Detail)
    ├── api/
    │   └── incidents.js         # REST client, resilient normalization layer & dossier export generator
    ├── ws/
    │   └── incidentSocket.js   # Native WebSocket client with exponential backoff (1s→2s→4s→8s→15s→30s)
    ├── mocks/
    │   └── incidents.mock.json  # Realistic fallback incidents with complete telemetry chains
    ├── components/
    │   ├── StatCard.jsx         # Executive metric cards with dynamic colored accents and icons
    │   ├── SeverityBadge.jsx    # Severity pill badge (critical/high/medium/low) with critical radar pulse
    │   ├── IncidentTable.jsx    # Sortable incident table with inline risk meter and new incident flash
    │   ├── LiveFeedPanel.jsx    # Auto-scrolling real-time telemetry feed with event type icons
    │   ├── SoarMetricsBar.jsx   # ⭐ NEW: Executive SOAR automation ROI strip (MTTD, MTTR, defense rate)
    │   ├── AttackTrendChart.jsx # ⭐ NEW: 24h threat velocity SVG area graph with dual-metric toggle
    │   ├── SeverityDonutChart.jsx # ⭐ NEW: Responsive radial SVG donut chart with center threat count
    │   ├── RiskyUsersPanel.jsx  # ⭐ NEW: UEBA risky identity ranking with SVG sparklines & 1-click revoke
    │   ├── RemediationConsole.jsx # ⭐ NEW: Multi-tab SOAR playbook engine, immediate actions & audit log
    │   ├── AiCopilotModal.jsx   # ⭐ NEW: Global interactive AI defense assistant drawer (Cmd+K)
    │   ├── RiskScoreBreakdown.jsx # 4-component risk decomposition meters (Anomaly, Rule, Severity, Correlation)
    │   └── EvidenceTimeline.jsx # Chronological attack sequence with MITRE tags and anomaly weights
    └── pages/
        ├── SOCOverview.jsx      # Main dashboard: metrics bar, charts, incident table & tabbed right panel
        └── IncidentDetail.jsx   # Deep-dive screen: header card, AI Copilot, SOAR console, dossier & evidence
```

---

## Detailed Frontend New Features

### 1. Attack Velocity & Threat Flow Chart (`AttackTrendChart.jsx`)
- **Location:** Top analytics row of the **SOC Overview** page.
- **Visual Design:** Pure responsive SVG area chart using cubic Bézier curves (`d={linePath}`) with smooth gradient glow fills (`#areaGradient`, `#lineGradient`).
- **Dual-Metric Toggle:**
  - **Incident Volume:** Displays 24-hour accumulation of correlated security incidents across the enterprise.
  - **Anomaly Wave:** Visualizes raw telemetry anomaly velocity surges detected by the Isolation Forest.
- **Real-Time Sub-Metrics Strip:**
  - Threat Velocity: `+14% / hr`
  - Sliding Window: `100 Events` (in-memory correlation buffer)
  - Threat Posture: `High Active` (critical alerts pending)

### 2. Severity Distribution Donut Chart (`SeverityDonutChart.jsx`)
- **Location:** Adjacent to the Attack Trend Chart on the **SOC Overview** page.
- **Visual Design:** Animated radial SVG donut chart utilizing calculated `stroke-dasharray` and `stroke-dashoffset` parameters with a centered threat counter.
- **Categorization:**
  - 🔴 **Critical** (`#ef4444`) — Immediate containment required.
  - 🟠 **High** (`#f97316`) — Under active tier-2 review.
  - 🟡 **Medium** (`#eab308`) — Suspicious anomaly threshold crossed.
  - ⚪ **Low** (`#64748b`) — Informational / baseline deviation.
- **Interactive Legend:** Displays count and proportional percentage for each severity bracket with responsive hover states.

### 3. Executive SOAR Performance Bar (`SoarMetricsBar.jsx`)
- **Location:** Top header strip of the **SOC Overview** page.
- **Operational KPIs:**
  - **MTTD (Mean Time to Detect):** `1.2m` (vs 4.5m industry baseline).
  - **MTTR (Mean Time to Remediate):** `38s` (-88% automated dwell time).
  - **Automated Defense Rate:** `92.4%` (playbook success rate across containment actions).
  - **Active Threat Containment:** Live counter of `criticalCount / activeCount`.
  - **Fleet Protected Assets:** 24 monitored endpoints with zero lateral bridges.

### 4. UEBA Risky Users Panel with Sparklines (`RiskyUsersPanel.jsx`)
- **Location:** Tabbed right sidebar on **SOC Overview** (`Live Feed` ⟷ `Risky Users (UEBA)`).
- **Functionality:** Identifies and ranks high-risk employee and service identities (`eve.patel`, `alice.chen`, `svc_account`, `svc_backup`).
- **SVG Sparklines:** Lightweight polyline charts visualizing each identity's 5-point historical risk score trajectory.
- **1-Click SOAR Response:** Instant **Revoke Session** button dispatching to `/actions/revoke-user`, immediately updating local state to "Revoked" with visual lock badges.

### 5. Interactive SOAR Remediation Console (`RemediationConsole.jsx`)
- **Location:** Embedded in the **Incident Detail** screen.
- **Incident Status Lifecycle:** Interactive status selector (`Open` ➜ `Investigating` ➜ `Contained` ➜ `Resolved`) with backend REST `PATCH /incidents/{id}/status` and real-time WebSocket broadcast to all connected SOC consoles.
- **Three Operation Tabs:**
  1. **Immediate Actions:**
     - 🛡️ *Zero-Trust Host Quarantine* (`POST /actions/isolate-host`)
     - 👤 *Revoke Active User Session* (`POST /actions/revoke-user`)
     - 🚫 *Deploy Perimeter C2 Null-Route IP Block* (`POST /actions/block-c2`)
     - 💾 *Capture Volatile Memory Triage Dump* (`POST /actions/capture-forensics`)
  2. **Automated Playbooks:**
     - ⚡ *Rapid Ransomware Containment* (~1.2s, 4-step sequence: isolate host, kill sessions, firewall C2, dump memory).
     - 🔑 *Credential Abuse Lockout* (~0.8s, 4-step sequence: lock directory account, terminate web sessions, enforce MFA, alert lead).
     - ↔️ *Lateral Movement Isolation* (~1.5s, 3-step sequence: isolate source endpoint, block SMB/RDP, export event logs).
     - *Visuals:* Animated execution progression with real-time step badges and execution timers.
  3. **Remediation Audit Log:**
     - Filterable chronological audit trail documenting every containment action, target entity, operator, and timestamp.

### 6. Forensic Incident Dossier Export Engine
- **Files:** [`src/api/incidents.js`](frontend/src/api/incidents.js), [`src/pages/IncidentDetail.jsx`](frontend/src/pages/IncidentDetail.jsx), and [`backend/main.py`](backend/main.py).
- **Purpose:** Exports a comprehensive, legally defensible, machine-readable JSON forensic dossier for post-incident review (PIR), external forensic hand-off (DFIR), and compliance audits.
- **Architecture:**
  - **Memory Blob Generation:** Uses W3C `Blob([json], { type: 'application/json' })` + `URL.createObjectURL` to prevent browser `data:` URI navigation blocking and handle arbitrary payload sizes safely.
  - **Dual Availability:** Available via client-side one-click download or direct backend REST endpoint (`GET /incidents/{incident_id}/dossier`).
- **Forensic Schema (`TLP:AMBER+STRICT`):**
  - `dossier_metadata`: Report ID, classification, digital hash timestamp, platform version.
  - `incident_overview`: Normalized severity, 0–100 risk score, dwell time, containment SLA status.
  - `entity_context`: Host platform, IP address, asset tier, EDR agent version, user role, department.
  - `threat_verdict`: Executive explanation with MITRE ATT&CK technique hyperlinks.
  - `forensic_evidence_chain`: Chronological correlated events with rule scores and ML anomaly weights.
  - `soar_audit_trail`: Recommended playbooks and available containment actions.
- **UI State Machine:**
  - **Idle:** Glassmorphism action button with SVG download icon.
  - **Exporting:** Spinner animation with `"Exporting Dossier…"`.
  - **Success:** Emerald green badge with checkmark (`"✓ Dossier Exported (.json)"`) for 3 seconds.
  - **Error:** Red alert state with user feedback.

### 7. Resilient Schema Normalization Layer (`src/api/incidents.js`)
- **Problem Solved:** Prevents frontend crashes caused by teammate schema variance between database models and frontend expectations.
- **Normalizations Handled:**
  - Severity: Converts numeric scores (`0-5`) or arbitrary case strings to canonical `'critical' | 'high' | 'medium' | 'low'`.
  - Risk Score: Normalizes both `0–100` integers and `0.0–1.0` floats into a consistent `0.0–1.0` float with safe rounding.
  - MITRE Techniques: Unifies arrays of string codes (`"T1110"`) and nested objects (`{ mitre_id: "T1110", technique: "Brute Force" }`).
  - Correlated Events: Safeguards `null` / `undefined` into empty arrays `[]`.

### 8. Dynamic AI Defense Copilot (`AiCopilotModal.jsx` + `backend/core/ai_layer.py`)
- **Global Availability:** Accessible dashboard-wide via glowing bottom-right floating trigger button or `Cmd+K` / `Ctrl+K`.
- **Context-Aware Reasoning:** Ingests active incident and fleet telemetry context.
- **1-Click High-Impact Prompts:**
  - ⚡ *Blast Radius Analysis:* Computes enterprise host contagion and identity exposure scope.
  - 🎯 *Predict Next Move:* Probabilistic forecasting of adversary's next MITRE technique based on Kill Chain transitions.
  - 📜 *Automated Script Generation:* Generates executable PowerShell or Bash zero-trust containment scripts.
  - 🔍 *Root Cause Explainer:* Translates complex Isolation Forest anomaly weights into plain English threat intelligence.

### 9. AI Investigation Copilot Card (`IncidentDetail.jsx` + `ai_copilot.py`)
- **Location:** Embedded in the **Incident Detail** screen right above the MITRE breakdown.
- **Components:**
  - **Model Attribution & Confidence:** Displays active model (`IsolationForest-v2.1 + RuleCorrelationNet`) with dynamic confidence gauge (`98.3%`).
  - **Predicted Kill Chain Phase:** 6-stage pip indicator highlighting current attack phase (e.g. *Step 3 of 6: Credential Access & Privilege Escalation*).
  - **Top Anomaly Drivers:** Visual cards displaying exact feature deviation multipliers (`+104.0x vs baseline`, `+88.0x`, etc.) and critical impact badges.
  - **Threat Actor Hypothesis:** AI-synthesized root-cause narrative.

---

## Backend API Endpoints (Quick Reference)

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Service healthcheck (`{"status": "ok"}`) |
| `GET` | `/incidents` | List all correlated incidents |
| `GET` | `/incidents/{id}` | Fetch single incident detail |
| `GET` | `/incidents/{id}/dossier` | Fetch formatted JSON forensic incident dossier |
| `GET` | `/incidents/{id}/ai-analysis` | Fetch live AI feature attribution & Kill Chain analysis |
| `POST`| `/ai/chat` | Interactive natural language cybersecurity reasoning chat |
| `POST`| `/ai/predict-next-move` | Probabilistic forecasting of adversary's next MITRE move |
| `POST`| `/ai/remediation-script` | Dynamic PowerShell / Bash containment script generator |
| `POST`| `/ai/blast-radius` | Enterprise contagion & lateral blast radius assessment |
| `PATCH`| `/incidents/{id}/status` | Update incident status (`open`/`investigating`/`contained`/`resolved`) |
| `GET` | `/analytics/risky-users` | Fetch UEBA identity risk rankings with dynamic sparklines |
| `POST`| `/actions/isolate-host` | Quarantine host network bridge |
| `POST`| `/actions/revoke-user` | Invalidate user active sessions and OAuth tokens |
| `POST`| `/actions/block-c2` | Deploy perimeter firewall IP block rule |
| `POST`| `/actions/capture-forensics` | Trigger volatile memory and socket dump |
| `POST`| `/actions/trigger-playbook` | Execute automated multi-step SOAR containment playbook |
| `WS`  | `/ws/incidents` | Real-time WebSocket stream for incidents, telemetry, and actions |

---

## How to Run

### 1. Local Development (Recommended)

```bash
# Terminal 1: Backend API & WebSocket server
cd backend
python3 -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload

# Terminal 2: Frontend Dev Server
cd frontend
npm run dev

# Terminal 3 (Optional): Fire Demo Attack Telemetry
cd demo-app
python3 trigger.py --loop
```

- Frontend: **http://localhost:5173**
- Backend API Docs: **http://localhost:8000/docs**

### 2. Docker Compose (Full Stack)

```bash
docker compose up --build
```

---

## Demo Checklist & Presentation Flow

1. **SOC Overview Walkthrough:**
   - Review executive KPIs on the **SOAR Performance Bar** (MTTD, MTTR, Automation rate).
   - Inspect **Attack Velocity & Flow Chart** (toggle between *Incident Volume* and *Anomaly Wave*).
   - Show **Severity Distribution Donut Chart** and breakdown percentages.
   - Switch right panel to **Risky Users (UEBA)**; showcase Eve Patel's risk sparkline and execute a 1-click **Revoke Session**.
2. **Incident Drill-Down:**
   - Click `INC-006` (Critical Ransomware incident on `laptop-mgmt-05.corp`).
   - Highlight the 4-factor **Risk Score Breakdown** and chronological **Evidence Timeline**.
   - Review MITRE ATT&CK technique tags (hyperlinked to official MITRE knowledge base).
3. **Active SOAR Remediation:**
   - In the **SOAR Remediation Console**, switch status from `Open` to `Investigating`.
   - Run the **Rapid Ransomware Containment Playbook**; observe real-time animated execution of all 4 containment steps.
4. **Forensic Dossier Export:**
   - Click **Export Dossier (JSON)** in the header.
   - Inspect the downloaded JSON file to show the complete `TLP:AMBER` forensic case file ready for DFIR and compliance.
