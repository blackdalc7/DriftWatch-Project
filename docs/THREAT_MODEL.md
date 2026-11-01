# Threat model

Driftwatch puts software that emulates attacker behaviour on lab machines. The main risk is that
Driftwatch itself becomes the attacker's tool. The design goal is that **a fully compromised Driftwatch
server still cannot make an agent do anything outside the Safe Action Catalog**.

## Assets

| Asset | Why it matters |
| --- | --- |
| Bundle signing key (`bundle-signing.key`) | Whoever holds it can queue catalog actions on agents |
| Lab CA key | Whoever holds it can impersonate agents to the server |
| Operator API key | Approve tests, dispatch runs, revoke agents |
| Lab VMs | Must not be turned into a beachhead |
| Evidence bundles | Must be trustworthy proof of what ran and what was seen |
| Elastic credentials | Read access to all lab telemetry |

## Trust boundaries

1. Operator browser ↔ nginx :443 (TLS, API key)
2. Agent ↔ nginx :8443 (mutual TLS, client cert issued by the lab CA)
3. nginx ↔ server (shared proxy secret on an internal network)
4. Server ↔ Elasticsearch / Kibana / EDR APIs (credentials from `.env`)
5. CI ↔ repository (pull requests from contributors)
6. Intel drafter ↔ CISA feed and the Claude API (untrusted text in, untrusted drafts out)

## Threats and mitigations

| # | Threat (STRIDE) | Mitigation |
| --- | --- | --- |
| T1 | **Elevation**: a server compromise is used to run arbitrary commands on agents | No shell or "execute" action exists in the agent. The catalog is compiled in; every step's params are validated against fixed choices and ranges on the agent itself. `process.discovery` takes one of a fixed set of commands, never free text. |
| T2 | **Tampering**: a task bundle is forged or modified in transit | Ed25519 signature over canonical JSON, verified against the key pinned at enrollment, before parsing steps. |
| T3 | **Replay**: a captured bundle is re-sent | Run ids are recorded in `seen.json`; bundles carry `issued_at`/`expires_at`; future-dated bundles are refused. |
| T4 | **Spoofing**: a rogue host enrols as an agent | Enrollment tokens are single-use by default and expire (TTL). The agent's private key never leaves it; it sends a CSR and receives `CN=<agent id>`. |
| T5 | **Spoofing**: a client bypasses nginx and calls agent routes directly | Agent routes require the proxy secret header. The server recomputes the certificate fingerprint and matches the enrolled agent, ignoring any identity the client claims. |
| T6 | **Elevation**: tests reach production machines | Work is dispatched only to agents carrying a tag in `DRIFTWATCH_LAB_TAGS`. Bundles name the scope and agents refuse a mismatch. |
| T7 | **Elevation**: an AI-drafted test does something unsafe | Drafts can only reference catalog actions and are re-validated. A draft cannot be dispatched; a named human must approve it, and only a clean lab run verifies it. Schedules use verified tests only. |
| T8 | **Tampering**: prompt injection through a CISA advisory | Model output is structured, constrained to catalog action ids, and validated like any other input. The worst case is a bad draft that a reviewer rejects. |
| T9 | **Tampering**: a PR weakens a rule silently | The detection-regression workflow fails the PR when a paired rule stops matching its recorded telemetry, or starts matching benign telemetry. |
| T10 | **Repudiation**: who approved or dispatched what | Append-only audit log for approvals, verifications, dispatches, revocations, token and schedule changes. Reviewer names are written into the test file. |
| T11 | **Tampering**: evidence is edited after the fact | Bundles have per-file SHA-256 in a signed manifest. Anyone can verify with `driftwatch evidence verify` or in the UI. |
| T12 | **Information disclosure**: operator key leaks from the browser | The key lives in `sessionStorage` only and is never written to disk. The UI is same-origin with the API. |
| T13 | **Denial of service**: a revoked or stolen agent keeps calling in | Revocation is checked on every agent request. Certificates are short-lived (default 30 days). |
| T14 | **Side effects**: an action leaves the VM changed | Every catalog action has a cleanup step that the agent reports on. Canary artefacts are named with the run marker so they are easy to find. |

## What is out of scope

- Compromise of the lab hypervisor or the Elastic cluster itself.
- An attacker who already has administrator rights on a lab VM. They can stop the agent, but they cannot
  use it to reach the other VM.
- Real malware. EICAR and marker strings are inert by design.

## Operational guidance

- Keep `deploy/pki/` off the server image; mount it read-only. Back up the CA key offline.
- Rotate the signing key by running `make pki` again and re-enrolling agents. Agents pin the key they
  enrolled with.
- Keep the lab VMs on an isolated network segment. The agent only needs outbound :8443 to the server.
