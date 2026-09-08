# Sentry (PS19) — Rohan's Track: Frontend + Demo Environment

**Owner:** Rohan (solo track)
**Duration:** 12 hours
**Stack:** React + Vite + Tailwind CSS, Docker Compose, native WebSocket
**Branch:** work in your own feature branch, merge at checkpoints noted below

---

## 0. Assumptions & Contracts (fill in during 0:00–0:45 schema meeting)

> These are placeholders. Update this section the moment the team locks the schema — every later step depends on it being accurate.

- **REST base URL:** `http://localhost:8000` (FastAPI, owned by Tanmay)
- **Endpoints:** `GET /events`, `GET /incidents`, `GET /assets`, `POST /ingest`
- **WebSocket URL:** `ws://localhost:8000/ws/incidents`
- **Incident object shape (draft — confirm and replace):**
  ```json
  {
    "incident_id": "string",
    "created_at": "ISO8601",
    "host": "string",
    "user": "string",
    "severity": "low | medium | high | critical",
    "risk_score": 0.0,
    "mitre_techniques": ["T1110", "T1078"],
    "correlated_events": [
      {
        "event_id": "string",
        "type": "string",
        "timestamp": "ISO8601",
        "anomaly_score": 0.0,
        "rule_score": 0.0,
        "detail": "string"
      }
    ],
    "explanation": "string"
  }
  ```
- **Response action:** `POST /actions/isolate-host` `{ "host": "string" }` (Tanmay, 8:00–10:00)

---

## 1. Task Checklist (checkboxes for Antigravity agent to track progress)

### Phase 0 — 0:00–0:45 — Screens + Contract Lock-in
- [ ] Attend/co-run schema freeze meeting with full team
- [ ] Confirm exact `/incidents`, `/events` JSON shape — update Section 0 above
- [ ] Confirm WebSocket message envelope (single incident push vs. batch, event name if any)
- [ ] Sketch 2 screens only: **SOC Overview** and **Incident Detail** (skip attack-graph for now)
- [ ] Create wireframe notes (can be plain text/markdown, no need for Figma under time pressure)

### Phase 1 — 0:45–2:30 — Docker Compose Skeleton
- [ ] Create `docker-compose.yml` at repo root with services: `backend`, `db` (Postgres), `demo-app`, `frontend`
- [ ] `frontend` service: Node 20 image, mounts repo, runs `npm run dev -- --host`, exposes port `5173`
- [ ] Verify `docker compose up` boots all 4 containers without crash-looping
- [ ] Confirm frontend container can reach `backend` container by service name (not `localhost`) — use `VITE_API_URL` env var
- [ ] Push this early — this is a **team-wide blocker**, don't sit on it in your branch
- [ ] **Merge checkpoint:** open PR / merge to main once `docker compose up` works for a teammate on a clean clone

### Phase 2 — 2:30–5:00 — SOC Overview Dashboard Shell (static/mock data)
- [ ] Scaffold Vite React app: `npm create vite@latest frontend -- --template react`
- [ ] Install Tailwind CSS, set up base config
- [ ] Create `src/mocks/incidents.mock.json` — 5–8 fake incidents matching Section 0 schema exactly
- [ ] Build `<SOCOverview />` page:
  - [ ] Incident list/table: host, user, severity badge, risk score, timestamp
  - [ ] Severity color coding (critical=red, high=orange, medium=yellow, low=gray)
  - [ ] Summary stat cards at top (total incidents, critical count, avg risk score)
  - [ ] "Live feed" panel — auto-scrolling recent events list (mock data for now, feels alive)
  - [ ] Click a row → navigate to Incident Detail
- [ ] Add React Router (or simple state-based view switch) for two-screen navigation
- [ ] **Do not wire to real API yet** — everything reads from the mock JSON file

### Phase 3 — 5:00–7:30 — Incident Detail Screen (static/mock data)
- [ ] Build `<IncidentDetail />` page:
  - [ ] Header: host/user, severity badge, timestamp, risk score (large, prominent)
  - [ ] Risk score breakdown panel — show component scores (anomaly_score, rule_score, severity, correlation_score) as a simple bar/list, not a black box
  - [ ] Evidence list — render `correlated_events[]` as a timeline or table
  - [ ] "Why flagged" explanation panel — render `mitre_techniques[]` as tags + plain-language `explanation` field
  - [ ] Back button to SOC Overview
- [ ] Structure data-fetching so swapping mock → live is a one-line change:
  - [ ] Create `src/api/incidents.js` with a single `getIncidents()` / `getIncidentById()` function that currently returns mock data — this is the seam you'll cut over in Phase 4
- [ ] **Merge checkpoint:** merge your branch around the team's 6:00–6:15 "ugly end-to-end pipeline" checkpoint — even if your data is still mocked, get your UI code into main so integration testing at 8:30 has your screens available

### Phase 4 — 7:30–9:30 — Wire to Live WebSocket Data
- [ ] Replace mock calls in `src/api/incidents.js` with real `fetch()` to `GET /incidents`
- [ ] Add WebSocket client (`src/ws/incidentSocket.js`):
  - [ ] Connect to `ws://<backend-host>/ws/incidents`
  - [ ] On message: parse, prepend/update incident in state
  - [ ] Reconnect-on-drop logic (simple retry with backoff — demo reliability matters more than elegance)
- [ ] **Budget the first 30 minutes here for schema drift** — real payload will likely not match your mock exactly. Fix field-name/type mismatches, don't rebuild UI structure.
- [ ] Loop in the correlation-engine teammate directly during their 8:30–10:00 "integration lead" slot — they're explicitly tasked with fixing dashboard data mismatches from their end
- [ ] Verify: triggering a test event on the backend causes a new incident to appear in the UI within 1–2 seconds, no manual refresh

### Phase 5 — 9:30–11:00 — Stretch: Attack-Graph Visual (ONLY if ahead of schedule)
- [ ] Decision gate: are both prior screens fully working and demo-stable? If no → **skip this phase entirely**, move to Phase 6 early
- [ ] If yes: build a static styled sequence (CSS flexbox/grid timeline of attack stages), not an interactive graph library
- [ ] Do not use React Flow or any heavy graph lib under time pressure — visual polish over interactivity

### Phase 6 — 11:00–12:00 — Demo Reliability
- [ ] Move to the **actual demo machine** (not your dev laptop) — test everything fresh
- [ ] Run `docker compose up` from clean clone on demo machine, confirm boot time is acceptable
- [ ] Run the attack trigger script end-to-end **at least 5 times in a row**, confirm identical UI behavior each time
- [ ] Check browser zoom level / screen resolution matches what will be projected
- [ ] Check demo machine's network can actually reach backend (no localhost-vs-network-IP surprises)
- [ ] Pre-load a "known good" incident in state as a fallback if live pipeline hiccups mid-demo
- [ ] Have a screen-recorded backup video ready (team should have triggered this at the 6:00–6:15 checkpoint)

---

## 2. File Structure Target

```
frontend/
├── src/
│   ├── api/
│   │   └── incidents.js       # single seam: mock → live swap happens here
│   ├── ws/
│   │   └── incidentSocket.js
│   ├── mocks/
│   │   └── incidents.mock.json
│   ├── components/
│   │   ├── SeverityBadge.jsx
│   │   ├── IncidentTable.jsx
│   │   ├── RiskScoreBreakdown.jsx
│   │   ├── EvidenceTimeline.jsx
│   │   └── LiveFeedPanel.jsx
│   ├── pages/
│   │   ├── SOCOverview.jsx
│   │   └── IncidentDetail.jsx
│   ├── App.jsx
│   └── main.jsx
├── Dockerfile
├── tailwind.config.js
└── vite.config.js
```

## 3. Merge Checkpoints Summary

| Time | Checkpoint | What to merge |
|---|---|---|
| ~2:30 | Docker Compose working | `docker-compose.yml`, frontend/backend Dockerfiles |
| ~6:00–6:15 | Team full-pipeline checkpoint | Your two screens (mock data OK) |
| ~9:30 | Post live-data wiring | Working WebSocket integration |
| ~11:00 | Pre-demo freeze | No more feature changes — bug fixes only |

## 4. Key Risks (own these proactively)

- **Schema drift** between your mock and the real payload — mitigated by locking Section 0 early and using a single data-access seam (`src/api/incidents.js`)
- **Docker networking** — container-to-container uses service names, not `localhost`; easy to lose 20 minutes here if unprepared
- **Demo machine ≠ dev machine** — always leave real buffer time in Phase 6 for this
- **Over-scoping the attack-graph** — it's explicitly optional; two solid screens beat three broken ones
