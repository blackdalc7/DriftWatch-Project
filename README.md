# Driftwatch

[![ci](https://github.com/blackdalc7/DriftWatch-Project/actions/workflows/ci.yml/badge.svg)](https://github.com/blackdalc7/DriftWatch-Project/actions/workflows/ci.yml)

Continuous security validation for a small lab: one Windows VM, one Linux VM and an Elastic backend.

Driftwatch answers two questions, every day, with evidence:

1. **Has the lab's configuration drifted?** Each agent collects a read-only hygiene baseline (Defender, ASR,
   PowerShell logging, auditd, SSH, firewall and so on). When a control changes state, Driftwatch records the
   drift event and pinpoints the exact moment and actor from Elastic change events.
2. **Do our detections still work?** Tests emulate one ATT&CK technique each with benign, typed actions.
   The results engine searches Elastic for the run's `DW-<runid>` marker and scores the run as
   `prevented`, `detected`, `missed` or `error`. In CI, a pull request fails when a modified Sigma rule
   stops detecting the recorded telemetry of its paired test.

> **Safety statement.** All AI-generated tests must be gated by a human review and a successful lab run
> before being marked "verified". All agent actions must be benign, typed and signed. There is no
> arbitrary remote shell execution: the agent can only run actions from a Safe Action Catalog compiled
> into its binary, and only from task bundles signed by the server's Ed25519 key.

## What is validated, and how

Coverage shows the code runs; it does not prove a test catches anything on a real network. Each capability is labelled by the strongest evidence behind it.

| Capability | Validation evidence | Level |
|---|---|---|
| Server: enrollment, scoring, drift, bundles, API | pytest suite, run on every push in [CI](https://github.com/blackdalc7/DriftWatch-Project/actions/workflows/ci.yml) | Unit tested |
| Go agent | `go test ./...` on Linux and Windows runners | Unit tested |
| Agent ↔ server over mTLS | `scripts/e2e_local.sh` runs a real server, mTLS proxy and Go agent on one host: enroll, heartbeat, signed bundles, results posted, run scored. A CI job | Integration tested (one host, no Elasticsearch) |
| Linux hygiene checks | `check-baseline.sh` shellchecked and run on the CI runner | Runs on CI host |
| Detection rules (Sigma → KQL) | `detection-regression.yml` lints every rule on each PR; running affected tests on lab agents needs a self-hosted runner | Lint tested, lab run optional |
| Scoring against Elastic | Results engine tested with fixtures; the e2e run checks the no-Elasticsearch path | Fixture tested, live Elastic not yet shown |
| Two-VM Windows lab | `make up` stack and agent install steps documented; no committed lab capture yet | Not yet verified live |
| Web console and demo | Vitest unit tests; the demo replays a seeded week and labels simulated writes | Unit tested, demo simulated |
| Claude drafting (`intel draft`) | Mocked client in `tests/test_intel.py`; offline mapper is the default | Mocked |

## Repository layout

| Path | What lives there |
| --- | --- |
| `src/driftwatch/` | Control server (FastAPI + SQLite), Sigma engine, results engine, drift detection, scheduler, EDR connectors, CISA intel drafter, CLI |
| `agent/` | Go agent: enrollment, heartbeat, signed-bundle verification, catalog executors, hygiene collector |
| `web/` | Operator UI ("Midnight Lab"): React 19, Vite, Tailwind, React Flow |
| `packages/aegis-ui/` | Vendored copy of the shared design system the UI is built on |
| `library/tests/` | Reviewed tests (YAML). `library/drafts/` holds unreviewed drafts |
| `rules/` | Sigma rules paired with tests |
| `telemetry/` | Recorded telemetry per test plus a benign baseline, used by the offline regression gate |
| `schema/` | JSON Schema generated from the test models |
| `tests/` | Python test suite (85% coverage gate) |
| `deploy/` | Dockerfiles, docker compose, nginx mTLS proxy, Elastic templates |
| `scripts/` | Local mTLS dev proxy, end-to-end script, demo snapshot exporter |
| `docs/` | [Architecture](docs/ARCHITECTURE.md), [threat model](docs/THREAT_MODEL.md), [test schema](docs/TEST_SCHEMA.md) |

## Quick start

### Look at it without any VMs

```bash
cd web && npm ci && npm run build:demo && npx vite preview --outDir dist-demo
```

The demo build replays a seeded week from `web/public/demo/` and runs entirely in your browser. Writes are
simulated and say so. Regenerate the snapshot with `PYTHONPATH=src python scripts/export_demo.py`.

### Run the lab

Requirements: Docker with compose, Go 1.24, Python 3.13, Node 22.

```bash
cp .env.example .env && make secrets      # paste the printed values into .env
make pki                                  # CA, server certificate, bundle signing key in deploy/pki
make web agent                            # UI into web/dist, agent binaries + SHA256SUMS into agent/bin/
make up                                   # elasticsearch, server, mock EDR, nginx (443 operators, 8443 agents)
```

Create an enrollment token in the UI (Fleet → New enrollment token) or with the API, then on each VM:

```powershell
driftwatch-agent.exe enroll --server https://driftwatch.lab:8443 --token dwt_... --ca ca.pem
driftwatch-agent.exe run
```

The agent generates its own key, sends a CSR and receives a client certificate with `CN=<agent id>`. Only
agents carrying a tag listed in `DRIFTWATCH_LAB_TAGS` are ever sent work.

### Develop

```bash
make install test regress     # Python: deps, tests with coverage gate, offline regression gate
make agent-test               # Go unit tests (includes Python <-> Go signature fixtures)
make web-test                 # UI type-check and vitest
make e2e                      # server + mTLS proxy + real agent binary, one full loop, no Elastic needed
```

## The story the demo tells

On day two of the seeded week someone switches off the ASR rule *Block execution of potentially obfuscated
scripts* on `lab-win01` at 11:42:07. Nothing alerts.

- The next hygiene snapshot flips `win.asr.block_obfuscated_scripts` from pass to fail. The drift timeline
  turns amber at that moment, and the Elastic change event names the exact time and user.
- The next run of `dw-win-encoded-powershell` changes from `detected` to `missed`. Driftwatch records a test
  drift event and lists the ASR control as the likely cause, because the test declares it in
  `hygiene_controls`.
- The EDR posture page shows CrowdStrike's Zero Trust Assessment still reporting ASR as meeting criteria.
  This is a false negative in the vendor score, and only the lab run exposes it. Driftwatch lists it as a
  disagreement instead of trusting either side blindly.

Scrub the drift timeline to 11:42 and the whole UI shifts from green to amber.

## How a test becomes "verified"

```
draft ──(named human approves: CLI `library approve` or the UI)──▶ approved
approved ──(a lab run executes every step and cleans up)──▶ verified
```

- AI-drafted tests (`driftwatch intel draft`, using Claude or an offline mapper) are always written as
  `draft` into `library/drafts/`. Drafts cannot be dispatched.
- Approved tests can be run on demand, and their first clean run verifies them automatically.
- Schedules only plan verified tests. The Schedules page lists anything it skipped.
- Every transition is written to the audit log. Each entry is SHA-256 chained to the one before it, so an
  edited, removed or inserted row breaks the chain. `GET /api/v1/audit/verify` checks it on the server and the
  Audit page recomputes it in your browser.

## Where the Claude API is used

`driftwatch intel draft` can call Anthropic's Claude API (through the `anthropic` Python SDK) to turn a threat-intel note into a draft validation test. It is optional: without `ANTHROPIC_API_KEY` in `.env`, an offline ATT&CK mapper writes the draft instead. Either way the result is only a `draft` and needs a named human to approve it before it can run. Nothing else in Driftwatch talks to an LLM.

## Hidden features

The UI has a few things that are not in the menus:

| Trigger | What happens |
| --- | --- |
| ↑ ↑ ↓ ↓ ← → ← → B A | Green-phosphor 1990s terminal mode for ten seconds |
| Settings → *deface* | Shows what the console would look like if the SOC itself were owned |
| Click the logo 7 times within 3 s, or type `quack` in the terminal | Rubber-duck adversary mode; the tagline changes to "duck-driven validation" |
| `Ctrl+K` | zsh-style terminal: `run`, `drift <host>`, `ls`, `cd`, `blast`, `status`, `fortune` |
| `shell` in the terminal | It refuses. There is no remote shell. That is the whole point |
| Drift timeline, `[` and `]` | Jump between drift events; the scrubber also snaps to events magnetically |
| Scrub the timeline before the first snapshot | "Before Driftwatch existed, everything was compliant. Allegedly." |
| Open an evidence bundle | The bundle decrypts in a hex scramble while its Ed25519 signature and file hashes are verified in your browser |
| Campaign replay | Drag a threat actor onto a server to replay its attack chain against that host's latest results. Techniques that do not apply to the host's OS are marked n/a |
| Empty states | "All tests passed. Either you're a genius, or the agent is dead." and friends |

## Prior art and credit

Driftwatch stands on the shoulders of
[Sigma](https://github.com/SigmaHQ/sigma) (rule format),
[MITRE ATT&CK](https://attack.mitre.org/) and the
[ATT&CK Navigator](https://github.com/mitre-attack/attack-navigator) (layer export),
[Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) (the idea of small, single-technique tests),
and the CISA advisories feed. Broader breach-and-attack-simulation platforms such as MITRE Caldera and
Project Achilles inspired the problem space. Driftwatch deliberately takes a narrower path: no
operator-chosen commands, no C2 model, and drift measurement as a first-class result next to detection.

## License

See [LICENSE](LICENSE).
