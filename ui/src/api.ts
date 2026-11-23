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
}

export interface AgentSteps {
  run_id: string;
  provider: string | null;
  model: string | null;
  generator: string | null;
  steps: AgentStep[];
  counts: { tool_calls: number; accepted: number; rejected: number; blocked: number };
  final_message: string | null;
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
  created: string;
  finished: string | null;
}

async function get<T>(path: string, params: Record<string, string | number | undefined>): Promise<T> {
  const query = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== "") query.set(k, String(v));
  const response = await fetch(`${path}?${query.toString()}`, { headers: { Accept: "application/json" } });
  if (!response.ok) throw new Error(`${path}: HTTP ${response.status}`);
  return (await response.json()) as T;
}

async function post<T>(path: string, body: unknown): Promise<T> {
  const response = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
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

export const api = {
  runs: () => get<RunInfo[]>("/api/runs", {}),
  findings: (run: string, filters: { type?: string; level?: string; q?: string; limit?: number }) =>
    get<{ total: number; items: FindingRow[] }>("/api/findings", { run, ...filters }),
  finding: (run: string, id: string) => get<FindingDetail>(`/api/findings/${encodeURIComponent(id)}`, { run }),
  graph: (run: string, id: string) => get<GraphElements>(`/api/graph/${encodeURIComponent(id)}`, { run }),
  agentSteps: (run: string) => get<AgentSteps>("/api/agent-steps", { run }),
  startRun: (repo: string) => post<Job>("/api/runs", { repo }),
  job: (id: string) => get<Job>(`/api/jobs/${encodeURIComponent(id)}`, {}),
};

// Links are built only from recognised advisory ID shapes, never from repository text.
export function advisoryUrl(id: string): string | null {
  if (/^CVE-\d{4}-\d{4,}$/.test(id)) return `https://nvd.nist.gov/vuln/detail/${id}`;
  if (/^GHSA(-[0-9a-z]{4}){3}$/.test(id)) return `https://github.com/advisories/${id}`;
  if (/^MAL-\d{4}-\d+$/.test(id)) return `https://osv.dev/vulnerability/${id}`;
  return null;
}
