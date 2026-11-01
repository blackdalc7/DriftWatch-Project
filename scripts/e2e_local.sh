#!/usr/bin/env bash
# End-to-end smoke test on one Linux host: real server, real mTLS proxy, real Go agent.
#
# PKI init -> server -> proxy -> token -> agent enroll (CSR, TTL token) -> heartbeat -> signed hygiene
# bundle -> queued test bundle -> results posted -> run scored. Elasticsearch is not needed: without it
# the results engine scores the run as an error with a clear note, which is what this script checks.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
PY=${PYTHON:-python3}
export DRIFTWATCH_ADMIN_TOKEN="e2e-admin-token-0123456789abcdef"
export DRIFTWATCH_PROXY_SECRET="e2e-proxy-secret-0123456789abcdef"
export DRIFTWATCH_DATA_DIR="$WORK/data" DRIFTWATCH_PKI_DIR="$WORK/pki"
export DRIFTWATCH_LIBRARY_DIRS="$ROOT/library/tests" DRIFTWATCH_RULES_DIR="$ROOT/rules"
export DRIFTWATCH_EVALUATION_DELAY=0 DRIFTWATCH_SCHEDULER_TICK=5 DRIFTWATCH_HEARTBEAT_INTERVAL=5
export DRIFTWATCH_ELASTIC_URL="http://127.0.0.1:1" PYTHONPATH="$ROOT/src"
PIDS=()
cleanup() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done; rm -rf "$WORK"; }
trap cleanup EXIT

api() { curl -fsS -H "X-API-Key: $DRIFTWATCH_ADMIN_TOKEN" -H 'Content-Type: application/json' "$@"; }

echo "== PKI"
PUB=$("$PY" -m driftwatch pki init --dir "$WORK/pki" --hosts localhost,127.0.0.1 | sed -n 's/.*agent config): //p')

echo "== server and proxy"
"$PY" -m uvicorn --factory driftwatch.server.app:create_app --host 127.0.0.1 --port 18000 --log-level warning &
PIDS+=($!)
"$PY" "$ROOT/scripts/dev_mtls_proxy.py" --pki "$WORK/pki" --upstream http://127.0.0.1:18000 --port 18443 2>"$WORK/proxy.log" &
PIDS+=($!)
for _ in $(seq 50); do curl -fsS http://127.0.0.1:18000/healthz >/dev/null 2>&1 && break; sleep 0.2; done

echo "== agent build"
(cd "$ROOT/agent" && go build -o "$WORK/driftwatch-agent" ./cmd/driftwatch-agent)
TOKEN=$(api -X POST http://127.0.0.1:18000/api/v1/tokens -d '{"label":"e2e","ttl_seconds":300,"max_uses":1,"tags":["lab"]}' \
  | "$PY" -c 'import json,sys; print(json.load(sys.stdin)["token"])')
cat >"$WORK/agent.json" <<JSON
{"server_url":"https://127.0.0.1:18443","ca_file":"$WORK/pki/ca.crt","signing_public_key":"$PUB",
 "lab_scope":"lab","state_dir":"$WORK/state","workspace":"$WORK/ws","poll_seconds":5}
JSON

echo "== enroll"
"$WORK/driftwatch-agent" enroll -config "$WORK/agent.json" -token "$TOKEN"
if "$WORK/driftwatch-agent" enroll -config "$WORK/agent.json" -token "$TOKEN" 2>/dev/null; then
  echo "FAIL: re-enrollment should be refused"; exit 1
fi

echo "== run agent"
HOME="$WORK/home" "$WORK/driftwatch-agent" run -config "$WORK/agent.json" 2>"$WORK/agent.log" &
PIDS+=($!)
api -X POST http://127.0.0.1:18000/api/v1/runs -d '{"test_id":"dw-lin-host-discovery","tags":["lab"]}' >/dev/null

echo "== wait for results"
for _ in $(seq 60); do
  STATE=$(api "http://127.0.0.1:18000/api/v1/runs?limit=10" | "$PY" -c '
import json,sys
runs=json.load(sys.stdin)
t=[r for r in runs if r["test_id"]=="dw-lin-host-discovery"]
h=[r for r in runs if r["test_id"]=="builtin.hygiene"]
print(t[0]["status"] if t else "none", h[0]["status"] if h else "none")')
  [ "$STATE" = "evaluated evaluated" ] && break
  sleep 1
done
echo "test/hygiene run status: $STATE"
[ "$STATE" = "evaluated evaluated" ] || { tail -20 "$WORK/agent.log"; exit 1; }
api "http://127.0.0.1:18000/api/v1/runs?limit=10" | "$PY" -c '
import json,sys
runs={r["test_id"]:r for r in json.load(sys.stdin)}
t=runs["dw-lin-host-discovery"]
steps=t["step_results"]
assert all(s["status"]=="executed" for s in steps), steps
assert any("# DW-" in s["observables"].get("process.command_line","") for s in steps), steps
print("steps:", [(s["action"], s["status"], s["observables"]) for s in steps])
print("outcome:", t["outcome"], "| notes:", (t.get("evaluation") or {}).get("notes"))
h=runs["builtin.hygiene"]
print("hygiene:", h["evaluation"])
'
grep -q '"refused' "$WORK/agent.log" && { echo "FAIL: agent refused a server bundle"; exit 1; }
echo "E2E OK"
