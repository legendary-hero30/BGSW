import { useEffect, useState, type FormEvent } from "react";
import { api, type Job, type RunInfo } from "./api";
import { AgentView } from "./views/AgentView";
import { ChecklistView } from "./views/ChecklistView";
import { FindingsView } from "./views/FindingsView";
import { GraphView } from "./views/GraphView";
import { RemediationView } from "./views/RemediationView";
import { OverviewView } from "./views/OverviewView";
import { ReportView } from "./views/ReportView";
import { SbomView } from "./views/SbomView";
import { Chip, Empty } from "./ui";

type Tab = "overview" | "agent" | "findings" | "graph" | "sbom" | "remediation" | "report" | "checklist";
const TABS: { id: Tab; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "agent", label: "Agent run" },
  { id: "findings", label: "Findings" },
  { id: "graph", label: "Dependency graph" },
  { id: "sbom", label: "SBOM" },
  { id: "remediation", label: "Remediation" },
  { id: "report", label: "Report" },
  { id: "checklist", label: "Checklist" },
];
const EXAMPLES = ["https://github.com/OWASP/NodeGoat", "https://github.com/cr0hn/vulnerable-node"];
const ACTIVE = new Set(["queued", "cloning", "scanning", "analyzing"]);
const STAGES: { id: string; label: string }[] = [
  { id: "cloning", label: "Clone" },
  { id: "analyzing", label: "Agents at work" },
  { id: "done", label: "Done" },
];

function JobBanner({ job, onWatch }: { job: Job; onWatch: () => void }) {
  const active = ACTIVE.has(job.status);
  const index = job.status === "queued" ? -1 : STAGES.findIndex((s) => s.id === (job.status === "scanning" ? "analyzing" : job.status));
  return (
    <div className={`mb-4 rounded-lg border p-3 text-sm ${job.status === "error" ? "border-red-200 bg-red-50" : "border-slate-200 bg-white"}`}>
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex items-center gap-1.5">
          {STAGES.map((s, i) => (
            <span key={s.id} className="flex items-center gap-1.5">
              <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${job.status === "error" && i === Math.max(index, 0) ? "bg-red-100 text-red-800" : i < index || (job.status === "done" && i <= index) ? "bg-emerald-100 text-emerald-800" : i === index ? "bg-sky-100 text-sky-800" : "bg-slate-100 text-slate-500"}`}>
                {active && i === index && <span className="mr-1 inline-block h-1.5 w-1.5 animate-pulse rounded-full bg-sky-500" />}
                {s.label}
              </span>
              {i < STAGES.length - 1 && <span className="text-slate-300">→</span>}
            </span>
          ))}
        </div>
        <span className="font-mono text-xs text-slate-500">{job.repo}</span>
        {job.findings !== null && <Chip>{job.findings} findings</Chip>}
        {job.steps.length > 0 && <Chip tone="info">{job.steps.length} agent steps</Chip>}
        {job.run_id && <button type="button" onClick={onWatch} className="ml-auto rounded bg-slate-900 px-3 py-1 text-xs text-white">Watch the agents</button>}
      </div>
      <div className="mt-1 text-slate-700">{job.step}</div>
      {job.error && <div className="mt-1 rounded bg-amber-50 p-2 text-xs text-amber-900">{job.error}</div>}
    </div>
  );
}

export default function App() {
  const [runs, setRuns] = useState<RunInfo[]>([]);
  const [run, setRun] = useState("");
  const [tab, setTab] = useState<Tab>("overview");
  const [finding, setFinding] = useState("");
  const [repo, setRepo] = useState("");
  const [job, setJob] = useState<Job | null>(null);
  const [starting, setStarting] = useState(false);
  const [error, setError] = useState("");

  async function refreshRuns(): Promise<RunInfo[]> {
    const r = await api.runs();
    setRuns(r);
    return r;
  }

  useEffect(() => {
    refreshRuns()
      .then((r) => {
        const first = r[0];
        if (first) setRun((cur) => cur || first.run_id);
      })
      .catch((e: Error) => setError(e.message));
  }, []);

  const active = job !== null && ACTIVE.has(job.status);
  useEffect(() => {
    if (!job || !ACTIVE.has(job.status)) return;
    let stop = false;
    const timer = setInterval(() => {
      api.job(job.id)
        .then(async (next) => {
          if (stop) return;
          setJob(next);
          const r = await refreshRuns();
          if (next.run_id) setRun(next.run_id);
          if (!ACTIVE.has(next.status) && next.run_id && r.some((x) => x.run_id === next.run_id)) setRun(next.run_id);
        })
        .catch((e: Error) => setError(e.message));
    }, 1500);
    return () => {
      stop = true;
      clearInterval(timer);
    };
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
      setTab("agent");
      if (started.run_id) setRun(started.run_id);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setStarting(false);
    }
  }

  const stored = runs.some((r) => r.run_id === run);
  const options = run && !stored ? [{ run_id: run, target: "in progress" }, ...runs] : runs;
  function openFinding(id: string) {
    setFinding(id);
    setTab("findings");
  }
  const needsStored = tab !== "agent";

  return (
    <div className="min-h-screen">
      <header className="bg-slate-900 text-white">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-3 px-4 py-3">
          <div>
            <h1 className="text-lg font-bold tracking-tight">Software Supply Chain Guardian</h1>
            <p className="text-xs text-slate-300">Know what you build. Trust what you ship.</p>
          </div>
          <div className="flex items-center gap-2 text-sm">
            <label htmlFor="run" className="text-slate-300">Run</label>
            <select id="run" className="max-w-[22rem] rounded border border-slate-600 bg-slate-800 px-2 py-1 text-white" value={run}
                    onChange={(e) => { setRun(e.target.value); setFinding(""); }}>
              {options.map((r) => (
                <option key={r.run_id} value={r.run_id}>
                  {r.run_id} · {r.target}{"synthetic" in r && r.synthetic ? " (SYNTHETIC)" : ""}
                </option>
              ))}
            </select>
          </div>
        </div>
      </header>

      <div className="mx-auto max-w-7xl p-4">
        <form onSubmit={startScan} className="mb-4 rounded-lg border border-slate-200 bg-white p-3 shadow-sm">
          <label htmlFor="repo" className="mb-1 block text-sm font-semibold text-slate-800">Analyze a GitHub repository</label>
          <div className="flex flex-wrap gap-2">
            <input id="repo" className="min-w-[22rem] flex-1 rounded border border-slate-300 px-3 py-2 text-sm" placeholder="https://github.com/owner/repository"
                   value={repo} onChange={(e) => setRepo(e.target.value)} maxLength={200} autoComplete="off" spellCheck={false} />
            <button type="submit" disabled={starting || active || !repo.trim()} className="rounded bg-slate-900 px-4 py-2 text-sm font-medium text-white disabled:opacity-50">
              {starting ? "Starting…" : active ? "Analysis running…" : "Analyze"}
            </button>
          </div>
          <div className="mt-1.5 flex flex-wrap items-center gap-2 text-xs text-slate-500">
            <span>Try:</span>
            {EXAMPLES.map((u) => <button key={u} type="button" onClick={() => setRepo(u)} className="rounded bg-slate-100 px-1.5 py-0.5 font-mono hover:bg-slate-200">{u.replace("https://github.com/", "")}</button>)}
            <span className="ml-auto">Public npm repositories with a package-lock.json. The clone is read-only and nothing from it is executed. The agents plan and choose their own steps.</span>
          </div>
        </form>

        {job && <JobBanner job={job} onWatch={() => { if (job.run_id) setRun(job.run_id); setTab("agent"); }} />}
        {error && <div className="mb-3 rounded bg-red-50 p-2 text-sm text-red-800">{error}</div>}

        <nav className="mb-4 flex flex-wrap gap-1 border-b border-slate-200">
          {TABS.map((t) => (
            <button key={t.id} type="button" onClick={() => setTab(t.id)}
                    className={`-mb-px border-b-2 px-3 py-2 text-sm ${tab === t.id ? "border-slate-900 font-semibold text-slate-900" : "border-transparent text-slate-500 hover:text-slate-800"}`}>
              {t.label}
            </button>
          ))}
        </nav>

        {!run ? (
          <Empty title="No runs yet" hint="Paste a GitHub repository above and press Analyze." />
        ) : needsStored && !stored ? (
          <Empty title="Findings are not stored yet" hint="The agents are still working. Open the Agent run tab to follow them; this view unlocks when they build findings." />
        ) : (
          <>
            {tab === "overview" && <OverviewView key={run} run={run} onOpenFinding={openFinding} go={(t) => setTab(t)} />}
            {tab === "agent" && <AgentView key={run} run={run} following={active && job?.run_id === run} onOpenReport={() => setTab("report")} />}
            {tab === "findings" && <FindingsView key={run} run={run} selected={finding} onSelect={setFinding} />}
            {tab === "graph" && <GraphView key={run} run={run} onOpenFinding={openFinding} />}
            {tab === "sbom" && <SbomView key={run} run={run} />}
            {tab === "remediation" && <RemediationView key={run} run={run} onOpenFinding={openFinding} />}
            {tab === "report" && <ReportView key={run} run={run} />}
            {tab === "checklist" && <ChecklistView key={run} run={run} />}
          </>
        )}
      </div>
    </div>
  );
}
