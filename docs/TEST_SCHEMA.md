# Test schema

Driftwatch tests are YAML files in `library/tests/` (reviewed) and `library/drafts/` (unreviewed). The
canonical definition is the Pydantic model in `src/driftwatch/schema.py`. A JSON Schema generated from it
lives in `schema/driftwatch-test.schema.json` (`make schema`) for editor validation.

## Example

```yaml
id: dw-win-encoded-powershell
name: Encoded PowerShell command
description: Starts PowerShell with -EncodedCommand. The payload only prints a marker, but the launch pattern is a staple of loaders.
version: 1
status: approved
platforms: [windows]
severity: high
attack:
  tactic: execution
  techniques: [T1059.001, T1027]
steps:
  - action: powershell.encoded_marker
expected:
  outcome: detected
  detections: [5f2b1c0e-6a41-4c7e-9b8a-1d2e3f4a5b05]
hygiene_controls: [win.powershell.scriptblock_logging, win.asr.block_obfuscated_scripts]
provenance: {source: manual}
review:
  approved_by: driftwatch-maintainers
  approved_at: "2026-10-30T12:00:00Z"
  notes: Hand-written seed test, reviewed with its Sigma rule.
```

## Fields

Unknown fields are rejected everywhere.

| Field | Type | Rules |
| --- | --- | --- |
| `id` | string | `dw-` followed by 3–63 lowercase letters, digits or hyphens; matches the file name |
| `name` | string | 3–120 characters |
| `description` | string | at least 10 characters; say what it does and why it is safe |
| `version` | int | ≥ 1; bump it when the steps or expectation change |
| `status` | `draft` \| `approved` \| `verified` | see lifecycle below |
| `platforms` | list | `windows` and/or `linux`; every step must be valid on every listed platform |
| `severity` | `low` \| `medium` \| `high` \| `critical` | default `medium` |
| `attack.tactic` | string | an ATT&CK enterprise tactic slug, for example `credential-access` |
| `attack.techniques` | list | ATT&CK ids like `T1059` or `T1059.001`, at least one |
| `steps` | list | 1–10 catalog actions, each `{action, params}` |
| `expected.outcome` | `detected` \| `prevented` | what a working defense looks like |
| `expected.detections` | list | Sigma rule ids that must fire for `detected` |
| `expected.window_seconds` | int | 30–3600, default 300; how long after the run to look for telemetry |
| `hygiene_controls` | list | baseline check ids that should stop or reveal this test; used to explain test drift |
| `provenance.source` | `manual` \| `cisa` \| `atomic-red-team` | where the idea came from |
| `provenance.reference` | string | advisory id or URL |
| `provenance.generated_by` / `generated_at` | string / time | set by the AI drafter |
| `review.approved_by` / `approved_at` / `notes` | | written by the approve command or the UI |
| `verification.run_id` / `agent_id` / `verified_at` | | written by the server after the first clean run |

## Lifecycle

| Status | How a test gets there | Can be dispatched | Can be scheduled |
| --- | --- | --- | --- |
| `draft` | written by a person or by `driftwatch intel draft` | no | no |
| `approved` | `driftwatch library approve <id> --reviewer <name>` or *Hold to approve* in the UI. Requires `review.approved_by` | yes, on demand | no |
| `verified` | the server, after a run of the approved test executed every step and cleaned up. Requires `review.approved_by` and `verification.run_id` | yes | yes |

The model validator enforces these invariants, so a hand-edited file that claims `verified` without a
reviewer and a run id fails to load.

## Safe Action Catalog

Steps can only use these actions. Their parameters are validated on the server and again on the agent.

| Action | Platforms | Techniques | Params |
| --- | --- | --- | --- |
| `file.eicar_drop` | windows, linux | T1105 | `wait_seconds` 1–60 |
| `process.discovery` | windows, linux | T1016, T1033, T1057, T1069.001, T1082 | `command` from a fixed list per platform |
| `registry.run_key_canary` | windows | T1547.001 | `hold_seconds` |
| `scheduled_task.canary` | windows | T1053.005 | `hold_seconds` |
| `persistence.autostart_canary` | linux | T1547.013 | `hold_seconds` |
| `dns.sinkhole_query` | windows, linux | T1071.004 | `count` |
| `file.credential_canary_read` | windows, linux | T1552.001 | none |
| `powershell.encoded_marker` | windows | T1059.001, T1027 | none |

`hygiene.collect` also exists, but only the server's own hygiene bundles may use it. Run
`driftwatch catalog` for descriptions, parameter ranges and cleanup behaviour.

## Pairing a test with a rule

1. Write the Sigma rule in `rules/<platform>/` with a stable UUID `id`.
2. Put that id in the test's `expected.detections`.
3. Record telemetry from a lab run into `telemetry/<test id>.ndjson`.
4. `make regress` must pass: the rule matches the test's telemetry and does not match
   `telemetry/benign.ndjson`.
