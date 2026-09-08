# AGENTS.md — Sentry (PS19) · Rohan's Track

> This file is the authoritative context document for any AI agent (or human) picking up work on this repo.
> It covers everything built in Session 1 (2026-09-08), current state, known issues, and next steps.

---

## Project Overview

**Sentry** is a real-time cybersecurity threat detection and SOC (Security Operations Center) dashboard.

| Attribute | Value |
|---|---|
| Stack | React 18 + Vite 8 + Tailwind CSS 3, native WebSocket |
| Backend (stub) | FastAPI + Uvicorn (Python 3.11) |
| Database | PostgreSQL 15 (via Docker) |
| Orchestration | Docker Compose (4 services) |
| Active branch | `rohan/frontend` |
| Remote | https://github.com/harshkadam3105-ship-it/SENTRY |

---

## Branch Rules

| Branch | Purpose | State |
|---|---|---|
| `main` | Team integration — clean base only | `Initial commit` only (LICENSE + README) |
| `rohan/frontend` | Rohan's working branch | All frontend + backend stub work lives here |

> **IMPORTANT:** `main` was force-reset to strip an accidental merge. Any teammate who pulled that merge must run:
> ```bash
> git fetch && git reset --hard origin/main
> ```

---

## What Was Built (Session 1)

### 1. Docker Compose — `docker-compose.yml`

4-service stack on a shared `sentry-net` bridge:

| Service | Image | Port | Notes |
|---|---|---|---|
| `frontend` | Node 20 slim | `5173` | Vite dev server, bind `0.0.0.0` |
| `backend` | Python 3.11 slim | `8000` | FastAPI stub |
| `db` | Postgres 15 alpine | `5432` | Healthcheck gated |
| `demo-app` | Python 3.11 slim | — | Attack trigger script |

**Container networking:** all inter-service calls use **service names**, not `localhost`.
- Frontend reads `VITE_API_URL` (→ `http://backend:8000` in Docker, `http://localhost:8000` local)
- Frontend reads `VITE_WS_URL` (→ `ws://backend:8000` in Docker)

---

### 2. Backend Stub — `backend/main.py`

Fully working FastAPI stub. Tanmay's team replaces this wholesale — it is **not a placeholder**, it's a working integration target.

**Endpoints:**

| Method | Path | Returns |
|---|---|---|
| `GET` | `/health` | `{"status": "ok"}` |
| `GET` | `/incidents` | Array of 3 seed incidents |
| `GET` | `/incidents/{id}` | Single incident or `404` |
| `GET` | `/events` | All correlated events flattened |
| `GET` | `/assets` | Host list |
| `POST` | `/ingest` | Accepts attack trigger payload |
| `POST` | `/actions/isolate-host` | Returns isolation confirmation |
| `WS` | `/ws/incidents` | Streams incidents; pushes synthetic every 15s |

**Fixed bugs this session:**
- `return {"error": "not found"}, 404` → `raise HTTPException(status_code=404, ...)` (tuple returns silently 200 in FastAPI)
- `events.extend(inc["correlated_events"])` → `events.extend(inc.get("correlated_events") or [])` (Pyrefly type error on untyped dict)

---

### 3. Frontend App — `frontend/`

**Full file tree:**
```
frontend/
├── Dockerfile
├── vite.config.js          # proxy /api → backend, host 0.0.0.0
├── tailwind.config.js      # dark SIEM theme, severity colors, animations
├── index.html              # title: "Sentry | SOC Dashboard"
└── src/
    ├── index.css           # glassmorphism, severity badges, MITRE tags, animations
    ├── main.jsx            # React 18 StrictMode entry
    ├── App.jsx             # HashRouter — / and /incident/:id
    ├── api/
    │   └── incidents.js   ← ⭐ ONE-LINE SWAP (USE_LIVE_API flag)
    ├── ws/
    │   └── incidentSocket.js  # exponential backoff: 1s→2s→4s→8s→15s→30s
    ├── mocks/
    │   └── incidents.mock.json  # 7 realistic incidents, spec-exact schema
    ├── components/
    │   ├── SeverityBadge.jsx     # critical/high/medium/low with pulse on critical
    │   ├── StatCard.jsx          # glassmorphism stat cards with accent colors
    │   ├── IncidentTable.jsx     # sorted by severity+risk_score, inline risk bar
    │   ├── LiveFeedPanel.jsx     # auto-scroll, WS status indicator, event icons
    │   ├── RiskScoreBreakdown.jsx # 4-component bars: anomaly, rule, severity, correlation
    │   └── EvidenceTimeline.jsx  # chronological events with icons, anomaly/rule scores
    └── pages/
        ├── SOCOverview.jsx       # stat cards + table + live feed, WS connected
        └── IncidentDetail.jsx    # risk score, MITRE tags, timeline, Isolate Host button
```

**Design system:**
- Background: `#070b14` / `#0d1117` / `#111827`
- Accent: cyan-400 (`#22d3ee`) with glow shadow
- Severity: critical=red-400, high=orange-400, medium=yellow-400, low=slate-400
- MITRE tags: indigo bg, linked to `attack.mitre.org`
- Font: Inter (body) + JetBrains Mono (code/IDs/scores)

---

### 4. Demo App — `demo-app/trigger.py`

```bash
python trigger.py          # fires 3 attack events once
python trigger.py --loop   # fires every 20s (continuous demo mode)
```

---

### 5. Integration Contract — `INTEGRATION_DEPS.md`

Full field-by-field contract for Tanmay + correlation-engine teammate. Key points:
- WS must send **one JSON object per `send()`**, not a batch array
- `severity` must be **lowercase** (`"critical"` not `"Critical"`)
- `risk_score` must be **float 0.0–1.0** (not int 94)
- `correlated_events` must be **array**, send `[]` not `null`
- Backend must set **CORS headers** or all `fetch()` calls silently fail

---

## How to Run Locally (Right Now)

```bash
# Frontend dev server (currently running on port 5173)
cd frontend && npm run dev

# Backend stub (Python 3.11 + fastapi + uvicorn installed system-wide)
cd backend && python3 -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

Open: **http://localhost:5173**

---

## How to Run via Docker (Team)

```bash
# From repo root — requires Docker Desktop
docker compose up --build

# Frontend → http://localhost:5173
# Backend  → http://localhost:8000
# API docs → http://localhost:8000/docs  (FastAPI auto-docs)
```

---

## Phase 4 Cutover — Switching Mock → Live API

In [`src/api/incidents.js`](frontend/src/api/incidents.js), change **line 13**:

```js
// Before (mock mode):
const USE_LIVE_API = false

// After (live mode):
const USE_LIVE_API = true
```

That is the **only** change needed. The WebSocket client is already live — it connects automatically on page load and reconnects on drop.

---

## Merge Checkpoints (from spec)

| Time | Checkpoint | Status |
|---|---|---|
| ~2:30 | Docker Compose working | ✅ Done — `docker-compose.yml` ready |
| ~6:00–6:15 | Team full-pipeline checkpoint | ✅ Both screens done with mock data |
| ~9:30 | Post live-data wiring | ⬜ Flip `USE_LIVE_API = true` |
| ~11:00 | Pre-demo freeze | ⬜ Bug fixes only after this |

---

## Known Issues / Watchouts

| Issue | Severity | Notes |
|---|---|---|
| `uv python install` process hangs indefinitely | Low | Kill with `pkill -f "uv python install"` — not needed for this project |
| Backend stub pushed to `rohan/frontend`, not Tanmay's backend service | Info | Stub is a drop-in target; Tanmay replaces `backend/` directory |
| HashRouter used (not BrowserRouter) | Info | Intentional — works in Docker without server rewrite rules. URLs look like `/#/incident/INC-001` |
| `COMPONENTS` const in RiskScoreBreakdown.jsx is declared but unused | Low | Defined for future extension; Pyrefly may flag it |
| WebSocket will fail in mock mode (no backend running) | Expected | Frontend shows "Offline" status gracefully — incidents still load from mock REST |

---

## Spec Phases Remaining

- **Phase 4 (7:30–9:30):** Flip `USE_LIVE_API = true`, verify WS live stream, fix schema drift with correlation-engine teammate
- **Phase 5 (9:30–11:00, STRETCH):** Attack-graph visual — only if both screens are demo-stable. CSS timeline only, no React Flow
- **Phase 6 (11:00–12:00):** Demo machine setup, 5× end-to-end trigger runs, screen resolution check, backup video

---

## Git History (rohan/frontend)

```
dfa4b1d  fix: HTTPException 404 + extend type error + pyrefly config
646c4f8  feat: initialize project dependencies and add incident mock data file 2 page interface
cd2aafb  Initial commit
```
