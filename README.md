# privesc-detector

A Python-based privilege escalation and lateral movement detection system. Ingests authentication events from CrowdStrike Falcon and Unix auth logs, models them as a directed graph stored in MongoDB, and runs four independent detections in real time as new events arrive. Reference enrichment data (vault keytab inventory, critical account catalogue) is loaded at startup and refreshed on a configurable background interval.

---

## What it does

When an auth event is ingested via the API, the system:
1. Persists the event as a directed graph edge in MongoDB
2. Rebuilds the in-memory auth graph from all edges
3. Runs all four detections against the new event
4. Writes any fired alerts back to MongoDB
5. Returns the results immediately in the API response

### Detections

| Detection | Trigger | Severity |
| --- | --- | --- |
| **A — Privilege Escalation** | Any auth edge where `dst_privilege > src_privilege` | Scaled by delta (low → critical) |
| **B — Auth Burst** | Distinct account switches on a single host exceed a threshold within a sliding time window | High |
| **C — Excessive Auth Chain** | A lateral movement path (SSH→auth→SSH→...) across machines exceeds a configured hop count | High |
| **D — Keytab Smuggling** | A confirmed `kinit` success (`auth_success=True`) references a keytab not registered in the vault, or not expected on that host | High / Critical if account is flagged |

Detection D uses the enrichment layer: a vault keytab inventory (host → expected keytab paths) and a critical accounts catalogue. Severity escalates to `critical` when the initiating account is marked critical in the catalogue.

---

## Architecture

```
POST /ingest/event
       │
       ▼
  EdgeStore (Motor/MongoDB)
       │
       ▼
  Graph Builder (NetworkX DiGraph)
       │
       ▼
  EventDispatcher ◄──── EnrichmentCacheManager
  ├── Detection A: Privilege Escalation  (per-edge, sync)          │
  ├── Detection B: Auth Burst            (in-memory sliding window, sync)
  ├── Detection C: Auth Chain            (iterative DFS, sync)     │
  └── Detection D: Keytab Smuggling      (per-edge, enrichment lookup, sync)
       │                                         ▲
       ▼                                         │ background refresh
  AlertStore (Motor/MongoDB)           ┌─────────┴─────────┐
       │                               │  VaultEnrichment  │
       ▼                               │  CriticalAccounts │
  GET /alerts                          └───────────────────┘
```

**Hybrid async/sync design:** The store layer uses Motor (async) for non-blocking MongoDB I/O. All detection logic is pure synchronous Python — no async required — making it easy to unit test independently. The `EnrichmentCacheManager` loads reference data synchronously at startup and refreshes it in a background `asyncio.Task` on a configurable interval; detections receive a plain `AllEnrichments` snapshot with no async involvement.

---

## Tech stack

- **Python 3.11+**
- **FastAPI** — REST API with async routes
- **Motor** — async MongoDB driver (store layer)
- **NetworkX** — directed graph construction and DFS traversal (detection C)
- **Pydantic v2** — data models and API request/response validation
- **PyYAML** — threshold and configuration management

---

## Project structure

```
privesc-detector/
├── pyproject.toml
├── config/
│   └── thresholds.yaml          # Tunable detection thresholds + enrichment refresh interval
└── src/
    └── privesc_detector/
        ├── main.py              # FastAPI app + lifespan startup/shutdown
        ├── config.py            # PyYAML → typed AppConfig dataclasses
        ├── dispatcher.py        # Routes new edges to all detections
        ├── ingest/
        │   ├── crowdstrike.py   # CrowdStrike Falcon stub (replace with real client)
        │   └── unix_auth.py     # Unix auth log stub (replace with real parser)
        ├── models/
        │   ├── node.py          # AccountNode, HostNode
        │   ├── edge.py          # AuthEdge (includes auth_success flag)
        │   └── alert.py         # Alert
        ├── store/
        │   ├── client.py        # Motor client setup
        │   ├── edges.py         # EdgeStore
        │   ├── nodes.py         # NodeStore
        │   ├── sessions.py      # SessionStore
        │   └── alerts.py        # AlertStore
        ├── graph/
        │   └── builder.py       # load_graph(edges) → nx.DiGraph
        ├── enrichment/
        │   ├── base.py          # EnrichmentStore ABC
        │   ├── vault.py         # VaultEnrichment + VaultCache (host → keytab paths)
        │   ├── critical_accounts.py  # CriticalAccountsEnrichment + CriticalAccountsCache
        │   └── cache.py         # EnrichmentCacheManager + AllEnrichments snapshot
        ├── detections/
        │   ├── base.py          # DetectionResult dataclass
        │   ├── privilege_escalation.py
        │   ├── auth_burst.py    # + BurstWindowState
        │   ├── auth_chain.py    # + _all_simple_paths_from DFS
        │   └── keytab_smuggling.py  # Detection D
        └── api/
            ├── dependencies.py
            └── routes/
                ├── health.py
                ├── ingest.py
                └── alerts.py
```

---

## Getting started

**Requirements:** Python 3.11, MongoDB running locally on port 27017.

```bash
# Create and activate a virtual environment
python3.11 -m venv .venv
source .venv/bin/activate

# Install the package and dev dependencies
pip install -e ".[dev]"

# Run the API server
uvicorn privesc_detector.main:app --reload
```

### Configuration

Edit `config/thresholds.yaml` to tune detection sensitivity:

```yaml
auth_burst:
  window_seconds: 60
  distinct_account_threshold: 5

auth_chain:
  max_chain_length: 4

privilege_escalation:
  enabled: true

keytab_smuggling:
  enabled: true

enrichment:
  refresh_interval_seconds: 300  # how often vault + account data is reloaded
```

Override the MongoDB connection via environment variables:

```bash
export MONGO_URI=mongodb://localhost:27017
export MONGO_DB=privesc_detector
```

---

## API

| Method | Endpoint | Description |
| --- | --- | --- |
| `POST` | `/ingest/event` | Ingest a normalized auth edge, run all detections |
| `GET` | `/alerts` | List alerts (`skip`, `limit`, `detection_type`, `since`) |
| `GET` | `/alerts/{id}` | Fetch a single alert |
| `PATCH` | `/alerts/{id}/acknowledge` | Mark an alert as acknowledged |
| `GET` | `/health` | Liveness check including MongoDB connectivity |

Interactive docs available at `http://localhost:8000/docs` when the server is running.

---

## Running tests

Tests are pure unit tests — no running MongoDB required.

```bash
pytest tests/ -v
```

63 tests covering all four detections, the enrichment layer, both ingest stubs, and the alert API routes.

---

## Next steps

### Ingest layer
- [ ] Implement the real CrowdStrike Falcon API client in `ingest/crowdstrike.py` (Event Streams or Detections API)
- [ ] Implement real Unix auth log parsing in `ingest/unix_auth.py` (tail `auth.log`, parse PAM/sshd/kinit lines)
- [ ] Add a background polling loop or webhook endpoint to drive continuous ingestion
- [ ] Build the privilege tier score calculator — combine environment, linked resource sensitivity, account type, and other signals into the `privilege_tier` float

### Graph
- [ ] Persist the graph as edges only and rebuild on demand vs. maintain an incremental in-memory graph — evaluate trade-offs at scale
- [ ] Add time-windowed graph queries so old edges age out and the chain detection focuses on recent activity
- [ ] Add `NodeStore` population — currently edges reference node IDs that may not exist as node documents yet

### Detections
- [ ] Tune default thresholds against real data once ingestion is live
- [ ] Add deduplication logic to the dispatcher so the same alert is not re-fired on every subsequent edge in an ongoing burst
- [ ] Extend Detection C to track which account changed at each hop, not just the node sequence, for richer alert context
- [ ] Connect the enrichment stubs to real data sources — replace `VaultEnrichment.load()` with a real vault API/DB call and `CriticalAccountsEnrichment.load()` with a real directory query
- [ ] Extend Detection D to cross-reference `allowed_hosts` in the critical accounts cache — flag when a critical service account authenticates from an unexpected host

### API & operations
- [ ] Add authentication to the API (API key or OAuth2)
- [ ] Add a `POST /ingest/batch` endpoint for bulk event ingestion
- [ ] Add pagination cursors to `GET /alerts` for large result sets
- [ ] Expose Prometheus metrics (events ingested, alerts fired per detection type, graph node/edge count)
- [ ] Add structured logging (structlog or python-json-logger) throughout

### Infrastructure
- [ ] Containerize with Docker (`Dockerfile` + `docker-compose.yml` with MongoDB)
- [ ] Add MongoDB index TTL on old edges to bound collection growth
- [ ] Write integration tests against a real MongoDB instance (e.g., via `testcontainers-python`)
- [ ] Set up CI (GitHub Actions) to run `pytest` and `ruff` on every push
