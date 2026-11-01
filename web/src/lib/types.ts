// Shapes returned by the Driftwatch operator API (src/driftwatch/server/app.py).

export type Outcome = "prevented" | "detected" | "missed" | "error" | "collected";
export type ReviewStatus = "draft" | "approved" | "verified";
export type Platform = "windows" | "linux";

export interface Metrics {
  cpu_percent?: number; memory_percent?: number; disk_percent?: number; uptime_seconds?: number;
  memory_total_bytes?: number; disk_total_bytes?: number; load_average?: number[];
  ip_addresses?: string[]; kernel_version?: string;
}

export interface Agent {
  id: string; hostname: string; platform: Platform; os_version: string; agent_version: string; tags: string[];
  cert_expires_at: string; enrolled_at: string; last_seen: string | null; metrics: Metrics;
  status: "active" | "revoked"; connection: "online" | "offline" | "never"; lab_scope: string | null; cert_sha256?: string | null;
}

export interface Heartbeat { ts: string; cpu_percent: number | null; memory_percent: number | null; disk_percent: number | null }

export interface AgentDetail extends Agent {
  heartbeats: Heartbeat[];
  hygiene: HygieneReport | null;
  recent_runs: Run[];
}

export interface Check {
  id: string; title: string; severity?: "low" | "medium" | "high"; status: "pass" | "fail" | "unknown";
  expected?: string; actual?: string | null; detail?: string;
}

export interface HygieneReport { schema: string; platform: Platform; collected_at: string; checks: Check[] }
export interface HygieneSnapshot { id?: number; agent_id: string; collected_at: string; report: HygieneReport }

export interface StepResult {
  index: number; action: string; status: "executed" | "blocked" | "error" | "skipped"; cleanup?: string;
  detail?: string; exit_code?: number | null; observables?: Record<string, unknown>; started_at?: string; finished_at?: string;
}

export interface Alert { rule_id: string; rule_name: string; timestamp: string; severity?: string }

export interface Evaluation {
  outcome: Outcome; passed: boolean; telemetry_seen?: boolean; telemetry_hits?: number;
  detection_quality?: "technique" | "tactic" | "general" | "none"; alerts?: Alert[];
  expected_detections?: string[]; missing_detections?: string[]; notes?: string[];
  checks?: number; failing?: number; drift_events?: number[];
}

export interface Run {
  id: string; test_id: string; test_version: number; agent_id: string; source: string; schedule_id: string | null;
  status: "queued" | "dispatched" | "completed" | "evaluated" | "expired" | "cancelled";
  created_at: string; not_before: string | null; dispatched_at: string | null; expires_at: string | null;
  started_at: string | null; finished_at: string | null; step_results: StepResult[] | null;
  outcome: Outcome | null; passed: boolean | null; evaluation: Evaluation | null; evaluated_at?: string | null;
  agent_log?: string;
}

export interface FlowStep {
  index: number; action: string; title: string; params: Record<string, unknown>; techniques: string[];
  observables: string[]; cleanup: string;
}

export interface Rule {
  id: string; title: string; level: string; techniques: string[]; logsource: Record<string, string>; kql: string;
  path: string | null;
}

export interface TestView {
  id: string; name: string; description: string; version: number; status: ReviewStatus; platforms: Platform[];
  severity: "low" | "medium" | "high" | "critical"; attack: { tactic: string; techniques: string[] };
  steps: { action: string; params: Record<string, unknown> }[];
  expected: { outcome: "prevented" | "detected"; detections: string[]; window_seconds: number };
  hygiene_controls: string[];
  provenance: { source: string; reference: string | null; generated_by: string | null; generated_at: string | null };
  review: { approved_by: string | null; approved_at: string | null; notes: string | null } | null;
  verification: { run_id: string | null; agent_id: string | null; verified_at: string | null } | null;
  emulated_techniques: string[]; dispatchable: boolean; results: { runs: number; passed: number };
}

export interface TestDetail extends TestView { yaml: string; flow: FlowStep[]; rules: Rule[]; hardening: string[] }

export interface DriftEvent {
  id: number; agent_id: string; hostname?: string; kind: "control" | "test"; subject: string;
  from_state: string; to_state: string; last_good_at: string | null; first_bad_at: string;
  exact_change_at: string | null; detected_at: string;
  details: {
    title?: string; severity?: string; direction?: "regressed" | "recovered"; before?: string; after?: string;
    change_event?: { code?: string; user?: string; message?: string; timestamp?: string };
    previous_outcome?: string; outcome?: string; likely_causes?: string[];
  };
}

export interface Schedule {
  id: string; name: string; test_ids: string[]; target_tags: string[]; days: number[]; window_start: string;
  window_end: string; timezone: string; randomize: boolean; enabled: boolean; created_at: string;
  last_planned_date: string | null;
}

export interface PlannedRun { schedule_id?: string; test_id: string; agent_id: string; at: string }

export interface Summary {
  agents: { total: number; online: number }; tests: Record<ReviewStatus, number>; outcomes: Record<string, number>;
  pass_rate: number | null; passed?: number; scored?: number; drift_open: number; signing_key_id: string;
}

export interface CatalogAction {
  id: string; title: string; description: string; platforms: Platform[]; techniques: string[]; observables: string[];
  cleanup: string; schedulable_as_test: boolean;
}

export interface NavigatorLayer {
  name: string; techniques: { techniqueID: string; score: number; color: string; comment: string; metadata?: { name: string; value: string }[] }[];
}

export interface Finding {
  type: "posture_disagreement" | "test_failure_context"; vendor?: string; host: string; control?: string; test?: string; driftwatch?: string;
  outcome?: string; summary: string; edr?: Record<string, unknown>; edr_context?: string[];
}

export interface DefenderControl { name: string; category: string; percent: number; status: string; description: string }

export interface Correlation {
  defender: { current_score: number; max_score: number; percent: number; created: string; controls?: DefenderControl[] } | null;
  crowdstrike: Record<string, { overall: number; sensor_config: number; os: number }>;
  findings: Finding[]; configured?: boolean; errors?: string[];
}

export interface AuditEntry {
  id: number; ts: string; actor: string; action: string; details: Record<string, unknown>; prev_hash?: string; hash?: string;
}
