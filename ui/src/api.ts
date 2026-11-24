// Typed client for the Guardian API (src/guardian/api/app.py). Same-origin only.

export type RiskLevel = "Critical" | "High" | "Medium" | "Low" | "Unknown";

export interface RunInfo {
  run_id: string;
  target: string;
  commit: string;
  generated_at: string;
  synthetic: boolean;
  findings: number;
  by_risk_level: Record<string, number> | null;
  by_type: Record<string, number> | null;
}

export interface FindingRow {
  id: string;
  type: string;
  title: string;
  component: string;
  version: string | null;
  severity: string;
  risk_score: number | null;
  risk_level: RiskLevel | null;
  coverage: number | null;
  override: string | null;
  explained: boolean;
}

export interface FactorContribution {
  factor: string;
  weight: number;
  value: number | null;
  effective_weight: number;
  contribution: number | null;
}

export interface Finding {
  id: string;
  type: string;
  title: string;
  component: { name: string; version: string | null; purl: string | null; ecosystem: string | null };
  dependency_path: string[];
  introduced_by: string[];
  advisory_ids: string[];
  severity: string;
  fixed_in: { tool: string; versions: string[] }[];
  evidence: { evidence_id: string; tool: string; ref: string | null; file: string | null; line: number | null }[];
  factors: {
    cvss: number | null;
    epss: number | null;
    kev: boolean | null;
    reachability: string;
    exposure: string;
    provenance: number | null;
    confirmed_malicious: boolean;
  };
  risk: {
    score: number | null;
    level: RiskLevel;
    contributions: FactorContribution[];
    unknown_factors: string[];
    weight_coverage: number;
    override: string | null;
  } | null;
}

export interface EvidenceRecord {
  id: string;
  kind: string;
  tool: string;
  tool_version: string | null;
  ref: string | null;
  file: string | null;
  line: number | null;
  graph_node: string | null;
  excerpt: string | null;
}

export interface Explanation {
  finding_id: string;
  why_it_matters: string;
  reachability: string;
  confidence: "high" | "medium" | "low";
  confidence_reason: string;
  cited_evidence: string[];
  provider: string;
  model: string;
  generator: string;
}

export interface FindingDetail {
  finding: Finding;
  evidence: EvidenceRecord[];
  explanation: Explanation | null;
  rejected_explanations: number;
  confidence?: { level: "high" | "medium" | "low"; reasons: string[] };
}

export interface GraphElements {
  nodes: { data: { id: string; label: string; role: string; scope?: string; on_path: boolean } }[];
  edges: { data: { id: string; source: string; target: string; on_path: boolean } }[];
  source: string;
  other_parents?: number;
}

export interface AgentStep {
  n: number;
  agent: string;
  subagent: string | null;
  tool: string;
  args: Record<string, unknown>;
  result_chars: number;
  error?: boolean;
}

export type JobStatus = "queued" | "cloning" | "scanning" | "analyzing" | "done" | "error";

export interface Job {
  id: string;
  repo: string;
  status: JobStatus;
  step: string;
  run_id: string | null;
  error: string | null;
  steps: AgentStep[];
  accepted: number;
  rejected: number;
  blocked: number;
  findings: number | null;
  lockfile_origin?: "repository" | "generated" | "upgraded" | null;
  created: string;
  finished: string | null;
}

// ---- agent run (plan, hypotheses, budget, timeline) -----------------------------------------

export interface AgentEvent {
  seq: number;
  ts: string;
  agent: string;
  kind: string;
  name: string | null;
  payload: Record<string, unknown>;
}

export interface PlanItem {
  id: string;
  goal: string;
  status: "pending" | "in_progress" | "done" | "blocked" | "dropped";
  assigned_agent: string;
  rationale: string;
}

export interface Hypothesis {
  id: string;
  author: string;
  claim: string;
  kind: string;
  confidence: string;
  status: "proposed" | "verified" | "rejected" | "needs_more_evidence";
  reasons: string[];
  finding_ids: string[];
}

export interface AgentRunInfo {
  id: string;
  goal: string;
  target: string;
  provider: string;
  model: string;
  status: "running" | "completed" | "incomplete" | "budget_exhausted" | "error" | "interrupted";
  stop_reason: string | null;
  budget: { max_steps?: number; max_tool_calls?: number; max_seconds?: number; max_tokens?: number };
  usage: Record<string, unknown> | null;
  live_usage: { steps: number; tool_calls: number; tokens: number };
  started_at: string;
  finished_at: string | null;
  has_report: boolean;
}

export interface AgentTimeline {
  agent_run: AgentRunInfo | null;
  events: AgentEvent[];
  plan: PlanItem[];
  hypotheses: Hypothesis[];
  last_seq: number;
  live?: boolean;
}

// ---- dependency graph overview ---------------------------------------------------------------

export interface GraphNodeData {
  id: string;
  label: string;
  name: string;
  version: string | null;
  scope: string;
  role: "root" | "direct" | "transitive";
  depth: number;
  risk: "Critical" | "High" | "Medium" | "Low" | "None";
  findings: number;
  focus: boolean;
}

export interface GraphOverview {
  nodes: { data: GraphNodeData }[];
  edges: { data: { id: string; source: string; target: string } }[];
  stats: {
    scope: string;
    shown_nodes: number;
    total_nodes: number;
    focus_candidates: number;
    focus_skipped: number;
    truncated: boolean;
  };
}

// ---- SBOM ------------------------------------------------------------------------------------

export interface SbomItem {
  bom_ref: string | null;
  type: string;
  name: string;
  version: string | null;
  label: string;
  purl: string | null;
  ecosystem: string | null;
  licenses: string[];
  found_by: string | null;
  location: string | null;
  risk: "Critical" | "High" | "Medium" | "Low" | "None";
  findings: number;
}

export interface SbomView {
  document: {
    format: string | null;
    spec_version: string | null;
    serial_number: string | null;
    version: number | null;
    timestamp: string | null;
    tools: string[];
    subject: string | null;
    components: number;
    dependency_records: number;
  };
  summary: {
    by_type: Record<string, number>;
    by_ecosystem: Record<string, number>;
    top_licenses: Record<string, number>;
    with_findings: number;
  };
  total: number;
  items: SbomItem[];
}

// ---- remediation (Day 2) ---------------------------------------------------------------------

export interface ProposalEdit { file: string; op: string; section: string; package: string; from_spec: string | null; to_spec: string }
export interface Approval { decision: "approved" | "rejected"; approver: string; at: string; note: string | null; proposal_sha: string }
export interface ValidationBrief { verdict: string; at: string; reasons: string[] }
// A fix proposal as the server stores it.
export interface Proposal {
  id: string;
  run_id: string;
  finding_id: string;
  package: string | null;
  current_version: string | null;
  action: string;
  target: string | null;
  summary: string;
  justification: string | null;
  expected_risk_reduction: { findings_resolved: string[]; highest_score_resolved: number | null; highest_level_resolved: string | null; note: string };
  compatibility: { level: string; reasons: string[] };
  rollback: string[];
  alternatives_considered: { action: string; why_not_chosen: string }[];
  evidence_refs: string[];
  edits: ProposalEdit[];
  applicable: boolean;
  needs: string[];
  confidence: string;
  status: "proposed" | "approved" | "rejected" | "applied" | "validated" | "failed";
  approvals: Approval[];
  validations: (ValidationBrief & Partial<ValidationReport>)[];
  validating?: { state: "running" | "done" | "error"; step: string; error: string | null; log?: { at: string; msg: string }[] } | null;
}
export interface FindingRef { id: string; type: string; component: string; version: string | null; advisories: string[]; level: string; score: number | null }
export interface ValidationReport {
  verdict: "verified" | "partially_verified" | "failed" | "blocked";
  reasons: string[];
  final_confidence: string;
  branch?: { branch: string; commit: string; path: string };
  diff?: string;
  steps: Record<string, { status: string; detail?: string }>;
  progress?: { at: string; msg: string }[];
  sbom_diff?: { components_before: number; components_after: number; added: string[]; removed: string[]; version_changed: string[] };
  findings_diff?: { targeted_resolved: string[]; targeted_remaining: string[]; resolved: FindingRef[]; remaining: FindingRef[]; new: FindingRef[] };
  risk?: { before: { levels: Record<string, number>; top_score: number | null; findings: number }; after: { levels: Record<string, number>; top_score: number | null; findings: number } };
  approval?: Approval;
  at: string;
}

// What the server can do right now; used to explain disabled buttons.
export interface Capabilities {
  agents: { ready: boolean; detail: string };
  validation: { ready: boolean; detail: string };
  sandbox: { ready: boolean; detail: string };
  push: { ready: boolean; detail: string };
}

export interface Checklist {
  counts: Record<string, number>;
  items: { n: number; text: string; status: "pass" | "fail" | "n/a"; evidence: string }[];
}

export interface RunSummary {
  findings: number;
  by_risk_level: Record<string, number>;
  by_type: Record<string, number>;
  by_severity: Record<string, number>;
  by_reachability: Record<string, number>;
  by_exposure: Record<string, number>;
  dependency_findings: number;
  runtime_findings: number;
  dev_only_findings: number;
  kev_findings: number;
  with_fix: number;
  vulnerable_packages: number;
  raw_matches: Record<string, number>;
  coverage?: {
    scanners_run: string[];
    scanners_not_run: string[];
    dockerfile_scanned: boolean;
    workflows_scanned: boolean;
    image_scanned: boolean;
    anomaly_rules_run: boolean;
  };
  tools: Record<string, string>;
  target: { name: string; commit: string; repo?: string; license?: string };
  generated_at: string;
}

// GET JSON; throws with the server's error text on failure.
async function get<T>(path: string, params: Record<string, string | number | undefined>): Promise<T> {
  const query = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== "") query.set(k, String(v));
  const response = await fetch(`${path}?${query.toString()}`, { headers: { Accept: "application/json" } });
  if (!response.ok) throw new Error(`${path}: HTTP ${response.status}`);
  return (await response.json()) as T;
}

// POST JSON with optional headers (e.g. the approval token).
async function post<T>(path: string, body: unknown, extra: Record<string, string> = {}): Promise<T> {
  const response = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json", ...extra },
    body: JSON.stringify(body),
  });
  if (!response.ok) {
    let detail = `HTTP ${response.status}`;
    try {
      const parsed = (await response.json()) as { detail?: unknown };
      if (typeof parsed.detail === "string") detail = parsed.detail;
    } catch {
      /* keep the status text */
    }
    throw new Error(`${path}: ${detail}`);
  }
  return (await response.json()) as T;
}

// Every server call the UI makes, in one place.
export const api = {
  runs: () => get<RunInfo[]>("/api/runs", {}),
  summary: (run: string) => get<RunSummary>("/api/summary", { run }),
  findings: (run: string, filters: { type?: string; level?: string; q?: string; limit?: number }) =>
    get<{ total: number; items: FindingRow[] }>("/api/findings", { run, ...filters }),
  finding: (run: string, id: string) => get<FindingDetail>(`/api/findings/${encodeURIComponent(id)}`, { run }),
  graph: (run: string, id: string) => get<GraphElements>(`/api/graph/${encodeURIComponent(id)}`, { run }),
  graphOverview: (run: string, p: { scope: string; risk?: string; q?: string; limit: number }) =>
    get<GraphOverview>("/api/graph-overview", { run, ...p }),
  sbom: (run: string, p: { q?: string; type?: string; ecosystem?: string; vulnerable?: boolean; limit: number; offset: number }) =>
    get<SbomView>("/api/sbom", { run, ...p, vulnerable: p.vulnerable ? "true" : undefined }),
  sbomDownloadUrl: (run: string) => `/api/sbom/download?run=${encodeURIComponent(run)}`,
  agentEvents: (run: string, after: number, limit = 400) => get<AgentTimeline>("/api/agent-events", { run, after, limit }),
  agentReport: (run: string) => get<{ run_id: string; markdown: string }>("/api/agent-report", { run }),
  checklist: (run: string) => get<Checklist>("/api/checklist", { run }),
  proposals: (run: string) => get<{ run_id: string; proposals: Proposal[] }>("/api/proposals", { run }),
  proposal: (run: string, id: string) => get<Proposal>(`/api/proposals/${encodeURIComponent(id)}`, { run }),
  approvalToken: () => get<{ token: string }>("/api/approval-token", {}),
  decide: (run: string, id: string, decision: "approve" | "reject", approver: string, note: string, token: string) =>
    post<Approval>(`/api/proposals/${encodeURIComponent(id)}/${decision}`, { run, approver, note }, { "X-Guardian-Approval": token }),
  validate: (run: string, id: string, token: string) =>
    post<{ state: string }>(`/api/proposals/${encodeURIComponent(id)}/validate`, { run }, { "X-Guardian-Approval": token }),
  exportFix: (run: string, id: string, token: string) =>
    post<ExportResult>(`/api/proposals/${encodeURIComponent(id)}/export`, { run }, { "X-Guardian-Approval": token }),
  pushFix: (run: string, id: string, confirm_repo: string, token: string) =>
    post<{ branch: string; compare_url: string; default_branch_moved: boolean }>(`/api/proposals/${encodeURIComponent(id)}/push`, { run, confirm_repo }, { "X-Guardian-Approval": token }),
  startRun: (opts: { repo?: string; demo?: boolean; goal: "assess" | "remediate"; custom_goal?: string; branch?: string }) =>
    post<Job>("/api/runs", opts),
  capabilities: () => get<Capabilities>("/api/capabilities", {}),
  job: (id: string) => get<Job>(`/api/jobs/${encodeURIComponent(id)}`, {}),
};

// Links are built only from recognised advisory ID shapes, never from repository text.
export function advisoryUrl(id: string): string | null {
  if (/^CVE-\d{4}-\d{4,}$/.test(id)) return `https://nvd.nist.gov/vuln/detail/${id}`;
  if (/^GHSA(-[0-9a-z]{4}){3}$/.test(id)) return `https://github.com/advisories/${id}`;
  if (/^MAL-\d{4}-\d+$/.test(id)) return `https://osv.dev/vulnerability/${id}`;
  return null;
}

export interface ExportResult {
  repo: string; branch: string; title: string; verdict: string; approved_by: string;
  lockfile_origin: string; metadata_file: string; command: string;
}
