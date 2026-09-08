# SentinelX — Integration Dependencies

> **Who this is for:** Tanmay (backend/FastAPI), Correlation-Engine teammate, anyone touching the data pipeline.
> **What it covers:** Every field the frontend reads, every endpoint it calls, and what breaks vs. silently degrades on schema drift.

---

## 1. REST Endpoints the Frontend Calls

| Method | Path | Called by | When |
|---|---|---|---|
| `GET` | `/incidents` | `getIncidents()` | SOC Overview page load + Phase 4 live mode |
| `GET` | `/incidents/:incident_id` | `getIncidentById(id)` | Incident Detail page load |
| `POST` | `/actions/isolate-host` | `isolateHost(host)` | "Isolate Host" button on Incident Detail |

> [!IMPORTANT]
> **`/events` and `/assets` are NOT called by the frontend yet.** They exist in the backend stub but the UI doesn't read them. Don't let their shape block frontend integration.

### CORS requirement
The backend **must** return CORS headers allowing `http://localhost:5173` (dev) and `*` (Docker):
```python
# FastAPI example — already in the stub
app.add_middleware(CORSMiddleware, allow_origins=["*"], ...)
```
Without this, every `fetch()` call from the browser will fail silently with a network error.

### Base URL resolution
The frontend reads `VITE_API_URL` from env. In Docker it's set to `http://backend:8000` (service name). In local dev it falls back to `http://localhost:8000`. **No hardcoded IPs anywhere.**

---

## 2. WebSocket Contract

**URL:** `ws://<backend-host>/ws/incidents`

### What the frontend expects on connect
Each message must be a **single JSON object** — one incident per `send()`. **Not a batch array.** The client does:
```js
const incident = JSON.parse(event.data)  // expects one object, not []
onIncident(incident)
```

> [!CAUTION]
> If the backend sends `[{...}, {...}]` (array), `JSON.parse` will succeed but the frontend will treat the whole array as a single incident object and all field reads (`incident.incident_id`, `incident.severity`, etc.) will return `undefined`. **The UI will render blank rows — no error thrown.** This is a silent failure.

### Reconnect handled by frontend
The frontend auto-reconnects with exponential backoff (1s → 2s → 4s → 8s → 15s → 30s). The backend **does not need to implement reconnect logic** — just accept new WebSocket connections normally.

---

## 3. Incident Object — Field-by-Field Contract

This is the exact shape the frontend reads. Every field listed is accessed in at least one component.

```jsonc
{
  // ── Top-level fields ──────────────────────────────────────────────────────

  "incident_id": "INC-001",       // string  — REQUIRED. Used as React key + URL param (/incident/:id)
  "created_at":  "2026-09-08T06:12:34Z",  // ISO 8601 string — REQUIRED. Parsed by new Date()
  "host":        "workstation-14.corp",   // string — REQUIRED. Displayed in table + detail header
  "user":        "alice.chen",            // string — REQUIRED. Displayed in table + detail header
  "severity":    "critical",              // REQUIRED. MUST be one of: "low" | "medium" | "high" | "critical"
                                          // lowercase — severity badge renders "" for anything else
  "risk_score":  0.94,                    // float 0.0–1.0 — REQUIRED. Multiplied by 100 for display
  "mitre_techniques": ["T1110", "T1078"], // string[] — optional (renders empty if missing)
  "explanation": "...",                   // string — optional (hides panel if missing/empty)

  // ── correlated_events[] ───────────────────────────────────────────────────
  // Each element is one row in the Evidence Timeline.

  "correlated_events": [
    {
      "event_id":      "EVT-001a",              // string — REQUIRED. Used as React key
      "type":          "auth_failure",           // string — see event type table below
      "timestamp":     "2026-09-08T06:10:11Z",  // ISO 8601 — REQUIRED. Sorted chronologically
      "anomaly_score": 0.87,                     // float 0.0–1.0 — optional (defaults to 0)
      "rule_score":    0.95,                     // float 0.0–1.0 — optional (defaults to 0)
      "detail":        "52 failed SSH..."        // string — REQUIRED. Main text in timeline card
    }
  ]
}
```

### Severity values — exact strings required

| Value | Badge rendered | What happens if wrong |
|---|---|---|
| `"critical"` | 🔴 CRITICAL (pulsing) | — |
| `"high"` | 🟠 HIGH | — |
| `"medium"` | 🟡 MEDIUM | — |
| `"low"` | ⚫ LOW | — |
| anything else | ⚫ LOW (fallback) | Sorted last, no color highlight |

> [!WARNING]
> **Case matters.** `"Critical"` or `"CRITICAL"` will fall through to the `low` style. All severity strings must be **lowercase**.

### risk_score — float not int

The UI does `Math.round(risk_score * 100)` to get a 0–100 display value. If the backend sends an integer (e.g. `94` instead of `0.94`) the bar will render at 9400% width and break the layout. **Must be a float between 0.0 and 1.0.**

### event.type — known values and unknown fallback

The `EvidenceTimeline` component has styled entries for these `type` strings:

| type string | Icon | Color |
|---|---|---|
| `auth_failure` | 🔑 | red |
| `lateral_movement` | ↔️ | orange |
| `privilege_escalation` | ⬆️ | red |
| `data_exfiltration` | 📤 | red |
| `command_and_control` | 📡 | orange |
| `suspicious_process` | ⚙️ | yellow |
| `account_creation` | 👤 | orange |
| `persistence` | 🔒 | orange |
| `network_anomaly` | 🌐 | cyan |
| `credential_dump` | 💾 | red |
| `ransomware_indicator` | 🚨 | red |
| `file_discovery` | 📂 | yellow |
| `data_collection` | 📦 | yellow |
| `anomaly_detected` | ⚠️ | cyan |

> [!NOTE]
> **Unknown types are safe.** Any `type` value not in the table above falls back to `⚠️` grey styling. You won't break anything by adding new event types — they just won't have a custom icon/color until you tell Rohan to add them.

---

## 4. POST /actions/isolate-host

**Request:**
```json
{ "host": "workstation-14.corp" }
```

**Expected response (any 2xx):**
```json
{ "status": "isolated", "host": "...", "timestamp": "ISO8601" }
```

The frontend only checks `response.ok`. If you return `{ "status": "queued" }` that's fine — it just shows "✓ Host Isolated". If you return a non-2xx, the button shows "✗ Isolate Failed".

---

## 5. Docker Networking

| Service | Hostname inside Docker network | Port |
|---|---|---|
| `frontend` | `frontend` | `5173` |
| `backend` | `backend` | `8000` |
| `db` | `db` | `5432` |
| `demo-app` | `demo-app` | — |

> [!IMPORTANT]
> **Never use `localhost` in container code.** Use service names.
> - Frontend → Backend: `http://backend:8000` (via `VITE_API_URL` env var)
> - Backend → DB: `postgresql://sentry:sentry_pass@db:5432/sentry_db` (via `DATABASE_URL` env var)
> - demo-app → Backend: `http://backend:8000` (via `BACKEND_URL` env var)

**Postgres credentials (set in docker-compose.yml):**
```
POSTGRES_USER:     sentry
POSTGRES_PASSWORD: sentry_pass
POSTGRES_DB:       sentry_db
```

---

## 6. What Breaks vs. Degrades Gracefully

| Issue | Impact | Visible in UI? |
|---|---|---|
| Missing `incident_id` | React key warning; clicking row goes to `/incident/undefined` | Partial — broken link |
| Missing `severity` | Renders LOW badge (fallback), sorted last | Silent |
| `severity` not lowercase | Same as missing — renders LOW | Silent |
| `risk_score` > 1.0 (e.g. sent as int `94`) | Risk bar overflows container, layout breaks | **Visible — breaks bar** |
| `correlated_events` missing/null | Evidence timeline empty, risk breakdown shows 0/100 | Graceful |
| WS sends array instead of object | All incident fields read as `undefined`, blank table rows | **Silent failure** |
| `created_at` not ISO 8601 | Time shows "Invalid Date" | Visible |
| CORS not set on backend | All `fetch()` calls fail, incidents never load | **Page stays blank** |
| `event.type` unknown string | Grey ⚠️ fallback, no crash | Graceful |
| `anomaly_score` / `rule_score` missing | Renders as 0%, no crash | Graceful |

---

## 7. Correlation-Engine Teammate — Specific Notes

The plan mentions you have an **"integration lead" slot at 8:30–10:00** — this is the window to fix payload mismatches. Prioritise:

1. **Snake_case field names** — `risk_score` not `riskScore`, `incident_id` not `incidentId`, `created_at` not `createdAt`
2. **`correlated_events` must be an array** even if empty — send `[]` not `null`
3. **`mitre_techniques` must be `string[]`** — not objects, not a comma-separated string
4. **`severity` must be lowercase** — most common drift risk
5. `anomaly_score` and `rule_score` per event are already wired to display in the Evidence Timeline — no code change needed on Rohan's side if you include them

---

## 8. How to Test Your Payload Against the UI

**Option A — Paste into mock file:**
```bash
# Replace the contents of this file with your actual /incidents response:
frontend/src/mocks/incidents.mock.json
# Then refresh http://localhost:5173
```

**Option B — Hit the backend stub directly:**
```bash
# The stub's output is the exact schema the frontend expects:
curl http://localhost:8000/incidents | python3 -m json.tool
```

**Option C — Use the browser DevTools:**
Once `USE_LIVE_API = true`, open DevTools → Network tab → filter by `/incidents`. Check the response shape against the contract above.
