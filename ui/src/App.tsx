import { useEffect, useState, type FormEvent } from "react";
import {
  api,
  type AgentSteps,
  type FindingDetail,
  type FindingRow,
  type GraphElements,
  type Job,
  type RunInfo,
} from "./api";
import { EvidenceCard, LevelBadge } from "./EvidenceCard";

const TYPES = [
  "", "malicious_package", "vulnerable_direct", "vulnerable_transitive", "vulnerable_image_package",
  "typosquat", "install_script", "lockfile_change", "unexpected_dependency", "untrusted_image",
  "unpinned_ci", "misconfiguration",
];
const LEVELS = ["", "Critical", "High", "Medium", "Low"];
const AGENT_STYLE: Record<string, string> = {
  orchestrator: "bg-slate-800 text-white",
  discovery: "bg-sky-100 text-sky-900",
  detection: "bg-violet-100 text-violet-900",
  analysis: "bg-emerald-100 text-emerald-900",
};
const STATUS_STYLE: Record<string, string> = {
  queued: "bg-slate-100 text-slate-700",
  cloning: "bg-sky-100 text-sky-800",
  scanning: "bg-violet-100 text-violet-800",
  analyzing: "bg-amber-100 text-amber-900",
  done: "bg-emerald-100 text-emerald-800",
  error: "bg-red-100 text-red-800",
};

function describe(step: { tool: string; args: Record<string, unknown>; subagent: string | null }): string {
  if (step.tool === "task") return `delegate → ${String(step.subagent ?? step.args.subagent_type ?? "subagent")}`;
  if (step.tool === "list_findings") return `limit ${String(step.args.limit ?? "")}`;
  if (step.tool === "get_finding") return String(step.args.finding_id ?? "");
  if (step.tool === "submit_explanations") return `${String(step.args.count ?? 0)} explanation(s)`;
  return Object.keys(step.args).length ? JSON.stringify(step.args).slice(0, 120) : "";
}

export default function App() {
  const [runs, setRuns] = useState<RunInfo[]>([]);
  const [run, setRun] = useState("");
  const [filters, setFilters] = useState({ type: "", level: "", q: "" });
  const [rows, setRows] = useState<{ total: number; items: FindingRow[] }>({ total: 0, items: [] });
  const [selected, setSelected] = useState("");
  const [detail, setDetail] = useState<FindingDetail | null>(null);
  const [graph, setGraph] = useState<GraphElements | null>(null);
  const [steps, setSteps] = useState<AgentSteps | null>(null);
  const [tab, setTab] = useState<"findings" | "steps">("findings");
  const [repo, setRepo] = useState("");
  const [job, setJob] = useState<Job | null>(null);
  const [starting, setStarting] = useState(false);
  const [error, setError] = useState("");

  async function refreshRuns() {
    const r = await api.runs();
    setRuns(r);
    return r;
  }

  useEffect(() => {
    refreshRuns()
      .then((r) => {
        const first = r[0];
        if (first) setRun((current) => current || first.run_id);
      })
      .catch((e: Error) => setError(e.message));
  }, []);

  useEffect(() => {
    if (!run) return;
    api.findings(run, { ...filters, limit: 200 }).then((r) => {
      setRows(r);
      setSelected((current) => (r.items.some((i) => i.id === current) ? current : (r.items[0]?.id ?? "")));
    }).catch((e: Error) => setError(e.message));
  }, [run, filters]);

  useEffect(() => {
    if (!run) {
      setSteps(null);
      return;
    }
    setSteps(null);
    api.agentSteps(run).then(setSteps).catch((e: Error) => setError(e.message));
  }, [run]);

  useEffect(() => {
    if (!run || !selected) {
      setDetail(null);
      return;
    }
    setGraph(null);
    api.finding(run, selected).then(setDetail).catch((e: Error) => setError(e.message));
    api.graph(run, selected).then(setGraph).catch((e: Error) => setError(e.message));
  }, [run, selected]);

  useEffect(() => {
    if (!job || job.status === "done" || job.status === "error") return;
    const timer = setInterval(() => {
      api.job(job.id)
        .then(async (next) => {
          setJob(next);
          if (next.status === "done" || next.status === "error") {
            const r = await refreshRuns();
            if (next.run_id && r.some((x) => x.run_id === next.run_id)) setRun(next.run_id);
            if (next.steps.length > 0) setTab("steps");
          }
        })
        .catch((e: Error) => setError(e.message));
    }, 2000);
    return () => clearInterval(timer);
  }, [job?.id, job?.status]);

  async function startScan(event: FormEvent) {
    event.preventDefault();
    const url = repo.trim();
    if (!url) return;
    setError("");
    setStarting(true);
    try {
      const started = await api.startRun(url);
      setJob(started);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setStarting(false);
    }
  }

  const current = runs.find((r) => r.run_id === run);
  return (
    <div className="mx-auto max-w-7xl p-4">
      <header className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold">Software Supply Chain Guardian</h1>
          <p className="text-xs text-slate-500">
            Scanner facts, gated DeepInfra explanations and the agent steps behind them.
          </p>
        </div>
        <div className="flex items-center gap-2 text-sm">
          <label htmlFor="run">Run</label>
          <select id="run" className="rounded border border-slate-300 bg-white px-2 py-1" value={run}
                  onChange={(e) => setRun(e.target.value)}>
            {runs.map((r) => (
              <option key={r.run_id} value={r.run_id}>
                {r.run_id} · {r.target}{r.synthetic ? " (SYNTHETIC)" : ""}
              </option>
            ))}
          </select>
        </div>
      </header>

      <form onSubmit={startScan} className="mb-4 rounded-lg border border-slate-200 bg-white p-3">
        <div className="mb-1 text-sm font-medium">Scan a GitHub repository</div>
        <div className="flex flex-wrap gap-2">
          <input
            aria-label="GitHub repository URL"
            className="min-w-[22rem] flex-1 rounded border border-slate-300 px-2 py-1 text-sm"
            placeholder="https://github.com/owner/repository"
            value={repo}
            onChange={(e) => setRepo(e.target.value)}
            maxLength={200}
          />
          <button type="submit" disabled={starting || !repo.trim()}
                  className="rounded bg-slate-800 px-3 py-1 text-sm text-white disabled:opacity-50">
            {starting ? "Starting…" : "Scan repository"}
          </button>
        </div>
        <p className="mt-1 text-xs text-slate-500">
          Public npm repositories with package.json and package-lock.json (v2/v3). The clone is
          depth-1 and read-only; nothing from it is executed.
        </p>
      </form>

      {job && <JobBanner job={job} onShowSteps={() => setTab("steps")} />}
      {error && <div className="mb-3 rounded bg-red-50 p-2 text-sm text-red-800">{error}</div>}

      {current && (
        <section className="mb-4 flex flex-wrap gap-4 text-sm">
          <div className="rounded border border-slate-200 bg-white px-3 py-2">
            <div className="text-xs text-slate-500">Commit</div>
            <code>{current.commit.slice(0, 12)}</code>
          </div>
          <div className="rounded border border-slate-200 bg-white px-3 py-2">
            <div className="text-xs text-slate-500">Findings</div>
            {current.findings}
          </div>
          <div className="rounded border border-slate-200 bg-white px-3 py-2">
            <div className="text-xs text-slate-500">By risk level</div>
            <div className="flex gap-1">
              {Object.entries(current.by_risk_level ?? {}).map(([level, n]) => (
                <span key={level}><LevelBadge level={level} /> {n}</span>
              ))}
            </div>
          </div>
          <div className="rounded border border-slate-200 bg-white px-3 py-2">
            <div className="text-xs text-slate-500">Agent steps</div>
            {steps ? `${steps.counts.tool_calls} tool calls · ${steps.counts.accepted} accepted` : "—"}
          </div>
        </section>
      )}

      <nav className="mb-3 flex gap-2 text-sm">
        {(["findings", "steps"] as const).map((t) => (
          <button key={t} type="button" onClick={() => setTab(t)}
                  className={`rounded px-3 py-1 ${tab === t ? "bg-slate-800 text-white" : "bg-white border border-slate-300"}`}>
            {t === "findings" ? "Findings" : "Agent steps"}
          </button>
        ))}
      </nav>

      {tab === "steps" ? (
        <AgentStepsView data={steps} run={run} />
      ) : (
        <div className="grid gap-4 lg:grid-cols-[22rem_1fr]">
          <aside>
            <div className="mb-2 grid grid-cols-2 gap-2 text-sm">
              <select aria-label="Type" className="rounded border border-slate-300 bg-white px-1 py-1"
                      value={filters.type} onChange={(e) => setFilters({ ...filters, type: e.target.value })}>
                {TYPES.map((t) => <option key={t} value={t}>{t ? t.replaceAll("_", " ") : "All types"}</option>)}
              </select>
              <select aria-label="Risk level" className="rounded border border-slate-300 bg-white px-1 py-1"
                      value={filters.level} onChange={(e) => setFilters({ ...filters, level: e.target.value })}>
                {LEVELS.map((l) => <option key={l} value={l}>{l || "All levels"}</option>)}
              </select>
              <input aria-label="Search" placeholder="Search package or title" maxLength={100}
                     className="col-span-2 rounded border border-slate-300 px-2 py-1" value={filters.q}
                     onChange={(e) => setFilters({ ...filters, q: e.target.value })} />
            </div>
            <p className="mb-1 text-xs text-slate-500">
              {rows.total} findings, ranked by risk{rows.total > rows.items.length ? ` (first ${rows.items.length})` : ""}
            </p>
            <ol className="max-h-[70vh] overflow-y-auto rounded border border-slate-200 bg-white text-sm">
              {rows.items.map((r) => (
                <li key={r.id}>
                  <button type="button" onClick={() => setSelected(r.id)}
                          className={`w-full border-b border-slate-100 px-2 py-1.5 text-left ${selected === r.id ? "bg-blue-50" : "hover:bg-slate-50"}`}>
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-mono text-xs text-slate-500">{r.id}</span>
                      <LevelBadge level={r.risk_level} score={r.risk_score} />
                    </div>
                    <div className="truncate">{r.component}{r.version ? `@${r.version}` : ""}</div>
                    <div className="truncate text-xs text-slate-500">
                      {r.type.replaceAll("_", " ")}{r.explained ? " · explained" : ""}
                    </div>
                  </button>
                </li>
              ))}
            </ol>
          </aside>
          <main>{detail ? <EvidenceCard detail={detail} graph={graph} /> : <p className="text-sm text-slate-500">Select a finding.</p>}</main>
        </div>
      )}
    </div>
  );
}

function JobBanner({ job, onShowSteps }: { job: Job; onShowSteps: () => void }) {
  const active = !["done", "error"].includes(job.status);
  return (
    <section className="mb-4 rounded-lg border border-slate-200 bg-white p-3 text-sm">
      <div className="flex flex-wrap items-center gap-2">
        <span className={`rounded px-2 py-0.5 text-xs font-semibold ${STATUS_STYLE[job.status] ?? ""}`}>
          {job.status}
        </span>
        <span className="font-mono text-xs text-slate-500">{job.repo}</span>
        {active && <span className="animate-pulse text-xs text-slate-500">working…</span>}
      </div>
      <div className="mt-1 text-slate-700">{job.step}</div>
      {job.error && <div className="mt-1 rounded bg-amber-50 p-2 text-xs text-amber-900">{job.error}</div>}
      <div className="mt-1 flex flex-wrap gap-3 text-xs text-slate-600">
        {job.findings !== null && <span>findings {job.findings}</span>}
        <span>tool calls {job.steps.length}</span>
        <span>accepted {job.accepted}</span>
        <span>rejected {job.rejected}</span>
        <span>blocked {job.blocked}</span>
        {job.run_id && (
          <button type="button" onClick={onShowSteps} className="underline">
            view agent steps for {job.run_id}
          </button>
        )}
      </div>
      {job.steps.length > 0 && (
        <ol className="mt-2 max-h-32 overflow-y-auto border-t border-slate-100 pt-1 font-mono text-xs">
          {job.steps.slice(-8).map((s) => (
            <li key={`${job.id}-${s.n}`} className="flex gap-2">
              <span className="w-6 text-slate-400">{s.n}</span>
              <span className="w-20 truncate text-slate-500">{s.agent}</span>
              <span className="w-40 truncate">{s.tool}</span>
              <span className="truncate text-slate-500">{describe(s)}</span>
            </li>
          ))}
        </ol>
      )}
    </section>
  );
}

function AgentStepsView({ data, run }: { data: AgentSteps | null; run: string }) {
  if (!run) return <p className="text-sm text-slate-500">Select a run.</p>;
  if (!data) return <p className="text-sm text-slate-500">Loading agent steps…</p>;
  if (data.steps.length === 0) {
    return (
      <div className="rounded border border-slate-200 bg-white p-4 text-sm text-slate-600">
        No agent steps recorded for {run}. Run the DeepInfra analysis for this run.
      </div>
    );
  }
  const phases = [...new Set(data.steps.filter((s) => s.agent !== "orchestrator").map((s) => s.agent))];
  return (
    <section className="rounded-lg border border-slate-200 bg-white p-4">
      <header className="mb-3 flex flex-wrap items-center gap-4 text-sm">
        <div>
          <div className="text-xs text-slate-500">Model</div>
          <code>{data.provider}:{data.model}</code>
        </div>
        <div>
          <div className="text-xs text-slate-500">Tool calls</div>
          {data.counts.tool_calls}
        </div>
        <div>
          <div className="text-xs text-slate-500">Accepted / rejected</div>
          {data.counts.accepted} / {data.counts.rejected}
        </div>
        <div>
          <div className="text-xs text-slate-500">Blocked</div>
          {data.counts.blocked}
        </div>
        {phases.length > 0 && (
          <div>
            <div className="text-xs text-slate-500">Phases</div>
            <div className="flex flex-wrap items-center gap-1">
              {phases.map((p, i) => (
                <span key={p}>
                  <span className={`rounded px-1.5 py-0.5 text-xs ${AGENT_STYLE[p] ?? "bg-slate-100"}`}>{p}</span>
                  {i < phases.length - 1 ? <span className="px-1 text-slate-400">→</span> : null}
                </span>
              ))}
            </div>
          </div>
        )}
      </header>
      <ol className="border-l border-slate-200">
        {data.steps.map((s) => (
          <li key={s.n} className="relative mb-2 ml-3 pl-4">
            <span className="absolute -left-[7px] top-1.5 h-3 w-3 rounded-full border-2 border-white bg-slate-400" />
            <div className="flex flex-wrap items-center gap-2 text-sm">
              <span className="w-7 font-mono text-xs text-slate-400">{s.n}</span>
              <span className={`rounded px-1.5 py-0.5 text-xs font-semibold ${AGENT_STYLE[s.agent] ?? "bg-slate-100"}`}>
                {s.agent}
              </span>
              <code className="text-xs">{s.tool}</code>
              <span className="text-xs text-slate-500">{describe(s)}</span>
              <span className="text-xs text-slate-400">{s.result_chars} chars</span>
            </div>
          </li>
        ))}
      </ol>
      {data.final_message && (
        <p className="mt-3 border-t border-slate-100 pt-2 text-xs text-slate-600">
          Final: {data.final_message}
        </p>
      )}
    </section>
  );
}
