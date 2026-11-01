# Architecture

```
                 operators (browser, CLI)                         GitHub Actions
                        │ HTTPS :443, X-API-Key                    │ detection-regression.yml
                        ▼                                          ▼
 ┌───────────── nginx ──────────────┐                    offline Sigma engine over
 │ :443  operator API + UI          │                    telemetry/*.ndjson (no lab needed)
 │ :8443 agents, mTLS required      │
 └──────────────┬───────────────────┘
                │ X-Driftwatch-Proxy, X-Client-Verify, X-Client-Cert
                ▼
 ┌──────────── driftwatch server (FastAPI) ─────────────┐      ┌──────────── Elasticsearch ───────────┐
 │ enrollment + CA      library + review gate           │◀────▶│ Windows/Linux telemetry (Beats/Agent) │
 │ task signer (Ed25519) scheduler                      │      │ Kibana detection alerts               │
 │ results engine        drift detection                │      │ Defender config change events         │
 │ evidence bundles      EDR correlation (read-only)    │      └───────────────────────────────────────┘
 │ SQLite store + audit log                             │
 └──────────────┬───────────────────────────────────────┘
                │ signed task bundles (pull, every heartbeat)
     ┌──────────┴──────────┐
     ▼                     ▼
 lab-win01 agent       lab-lin01 agent      (Go, compiled-in Safe Action Catalog,
                                             go:embed read-only hygiene scripts)
```

## Components

### Control server (`src/driftwatch/server`)

- **`app.py`**: the HTTP surface. Agent routes (`/api/v1/enroll`, `/agent/heartbeat`, `/agent/tasks`,
  `/agent/results`) only accept requests that came through the mTLS proxy: the proxy adds a shared
  `X-Driftwatch-Proxy` secret and the client certificate, and the server fingerprints that certificate itself
  and matches it to the enrolled agent. Operator routes need `X-API-Key`.
- **`service.py`**: the `Platform` holds the business rules: lab scope, dispatch (drafts refused with 409),
  evaluation, automatic `approved → verified` on the first clean run, and the hygiene schedule. Hygiene
  collection is due when the last hygiene run is older than the interval, measured on the server clock.
- **`store.py`**: SQLite with WAL. Agents, tokens, runs, heartbeats, hygiene snapshots, drift events,
  schedules and an append-only audit log. Each audit row stores `prev_hash` and
  `hash = sha256(canonical_json([prev_hash, ts, actor, action, details]))`, starting from 64 zeros;
  `verify_audit_chain()` (and `GET /api/v1/audit/verify`) reports the first broken entry. This is a hash chain,
  not a signature: it shows tampering by anyone who cannot rewrite every later row.
- **`bundles.py`**: builds and signs task bundles (canonical JSON, Ed25519, base64 of the exact signed bytes).
- **`scheduler.py`**: plans each schedule's day once, inside its window, verified tests only, at least five
  minutes apart per agent. Times are random by default so the blue team cannot learn the pattern.
  Schedules are created with `POST` and edited with `PUT /api/v1/schedules/{id}`; an edit applies from the
  next plan and is audited as `schedule.updated`.

### Agent (`agent/`)

A single static Go binary per platform. Every cycle it heartbeats (gopsutil metrics, kernel version and
non-loopback IP addresses, validated server-side), pulls due tasks and
verifies each bundle before touching anything:

1. The Ed25519 signature checks out against the key pinned at enrollment.
2. The bundle is version 1 and has a well-formed run id and `DW-<runid>` marker.
3. It names this agent, this platform and this agent's lab scope.
4. It was issued in the past and has not expired.
5. It has 1–20 steps in order, each action is allowed for the bundle kind, and each step's params validate
   against the compiled-in catalog.
6. The run id is not already in `seen.json` (replay protection).

Only then does the `Runner` execute the steps, clean up, and post results. The catalog has no generic
"execute" action. Hygiene collection runs embedded, read-only PowerShell or Bash scripts and returns JSON.

### Results engine (`src/driftwatch/results`)

After `evaluation_delay` seconds the server queries Elastic for telemetry and detection alerts that carry
the run's marker (or the run's observables), from just before the run until `window_seconds` after it:

| Observation | Outcome |
| --- | --- |
| Any step was blocked (quarantine, access denied, ASR) | `prevented` |
| A step errored or was skipped, no step results came back, or Elastic was unreachable | `error` |
| Every step executed and at least one alert matched the run | `detected` |
| Every step executed and no alert matched | `missed` |

`passed` compares the outcome with `expected.outcome` (prevention also satisfies an expected detection),
and a detection only passes when every rule id in `expected.detections` fired.
Every evaluated run produces an evidence bundle: the run, the test as dispatched, the agent, the latest
hygiene snapshot and Elastic hits, plus `manifest.json` with SHA-256 per file, `manifest.sig` and
`public_key.txt`. The UI verifies bundles in the browser with WebCrypto.

### Drift detection (`src/driftwatch/results/drift.py`)

- **Control drift**: comparing consecutive hygiene snapshots. When a check flips, Driftwatch searches
  Elastic between the last good and first bad snapshot for a matching configuration-change event (for
  example Defender event 5007) to record the exact time and user.
- **Test drift**: comparing a run with the previous evaluated run of the same test on the same agent. A
  pass → fail flip is linked to failing hygiene controls that the test lists in `hygiene_controls`.

### Detection regression (`src/driftwatch/regression.py`, `src/driftwatch/sigma`)

A small Sigma engine (field modifiers, `1 of`, `all of`, boolean conditions with parentheses) evaluates
rules against `telemetry/<test>.ndjson` and `telemetry/benign.ndjson`. In a PR only the rules and tests the
diff touched are evaluated. The gate fails when a paired rule stops matching its test's telemetry or starts
matching the benign baseline. Results are written as JUnit XML and a Markdown PR comment. The same rules are
translated to KQL and can be deployed to the Kibana detection engine (`driftwatch rules deploy`).

### Intel drafter (`src/driftwatch/intel`)

Reads the CISA advisories feed and drafts tests from an advisory, either with Claude (`claude-opus-5-5`,
structured output constrained to catalog actions) or with an offline keyword mapper. Every drafted step is
re-validated against the catalog, and drafts are written with `status: draft` to `library/drafts/`.
Nothing drafted can run until a named human approves it.

### EDR correlation (`src/driftwatch/connectors`)

Read-only clients for Microsoft Defender Secure Score and CrowdStrike Falcon Zero Trust Assessment.
Correlation lists where vendor posture and lab results disagree. It never changes an outcome. A mock EDR
service (`driftwatch mock-edr`) stands in for both APIs in the lab and in tests.

### UI (`web/`)

React 19 with HashRouter, Tailwind 4, motion and React Flow on top of the shared `@portfolio/aegis-ui`
package. Two data modes:

- **live** uses the operator API with a key kept only in `sessionStorage`;
- **replay** reads `web/public/demo/*.json` exported by `scripts/export_demo.py`. Writes are simulated.

## Data flow of one run

1. An operator (or a schedule) asks for test *T* on agent *A*. The server checks that *T* is approved or
   verified and that *A* is in lab scope, then stores a queued run.
2. On *A*'s next heartbeat, `/agent/tasks` returns the run as a signed bundle.
3. The agent verifies, executes and cleans up, then posts step results.
4. After the evaluation delay, the results engine scores the run, records drift, writes the signed
   evidence bundle and, for an approved test with a clean run, marks the test verified.
