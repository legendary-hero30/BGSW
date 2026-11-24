// Top-level page: start a scan (public or own repo), flow bar, and the tab views for the selected run.
import { useEffect, useState, type FormEvent } from "react";
import { api, type Capabilities, type Job, type Proposal, type RunInfo } from "./api";
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
// Public repos with an npm lockfile, offered as one-click examples.
const EXAMPLES = ["https://github.com/OWASP/NodeGoat", "https://github.com/cr0hn/vulnerable-node"];
// Job states that mean work is still going on.
const ACTIVE = new Set(["queued", "cloning", "scanning", "analyzing"]);
const STAGES: { id: string; label: string }[] = [
  { id: "cloning", label: "Clone" },
  { id: "analyzing", label: "Agents at work" },
  { id: "done", label: "Done" },
];

// Progress line for the running scan: clone, agents at work, done.
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

// Five-step bar from risk to verified fix; a rejection counts as a decision.
function FlowStepper({ proposals, onGo }: { proposals: Proposal[]; onGo: () => void }) {
  const fixable = proposals.filter((p) => p.applicable);
  const approved = fixable.filter((p) => p.approvals.at(-1)?.decision === "approved");
  const rejected = fixable.filter((p) => p.approvals.at(-1)?.decision === "rejected");
  const decided = approved.length + rejected.length === fixable.length && fixable.length > 0;
  const allRejected = decided && approved.length === 0;
  const validated = fixable.filter((p) => p.validations.length > 0);
  const reports = validated.map((p) => p.validations.at(-1)?.verdict);
  const verified = reports.filter((v) => v === "verified").length;
  const steps: { label: string; done: boolean; detail: string }[] = [
    { label: "Prioritized risk", done: true, detail: "scored findings" },
    { label: "Recommended fix", done: proposals.length > 0, detail: proposals.length ? `${fixable.length} applicable of ${proposals.length}` : "none yet" },
    { label: "Human approval", done: decided, detail: `${approved.length} approved, ${rejected.length} rejected of ${fixable.length}` },
    { label: "Build, test, rescan", done: allRejected || validated.length > 0 && validated.length >= approved.length && approved.length > 0, detail: allRejected ? "skipped: all rejected" : `${validated.length} validated` },
    { label: "Verified remediation", done: allRejected || verified > 0, detail: allRejected ? "nothing applied" : validated.length ? `${verified} verified, ${reports.length - verified} not` : "pending" },
  ];
  const current = steps.findIndex((s) => !s.done);
  return (
    <div className="mb-4 flex flex-wrap items-center gap-1 rounded-lg border border-slate-200 bg-white p-2 text-xs" aria-label="Remediation flow">
      {steps.map((s, i) => (
        <span key={s.label} className="flex items-center gap-1">
          <span className={`rounded-full px-2.5 py-1 font-medium ${s.done ? "bg-emerald-100 text-emerald-800" : i === current ? "bg-sky-100 text-sky-900 ring-1 ring-sky-400" : "bg-slate-100 text-slate-500"}`}>
            {s.done ? "✓ " : `${i + 1}. `}{s.label} <span className="font-normal opacity-75">({s.detail})</span>
          </span>
          {i < steps.length - 1 && <span className="text-slate-300">→</span>}
        </span>
      ))}
      <button type="button" onClick={onGo} className="ml-auto rounded bg-slate-900 px-3 py-1 text-white">Open remediation</button>
    </div>
  );
}

// Page state: runs, the selected run and tab, scan form, capabilities and proposals.
export default function App() {
  const [runs, setRuns] = useState<RunInfo[]>([]);
  const [run, setRun] = useState("");
  const [tab, setTab] = useState<Tab>("overview");
  const [finding, setFinding] = useState("");
  const [repo, setRepo] = useState("");
  const [mode, setMode] = useState<"public" | "own">("public");
  const [job, setJob] = useState<Job | null>(null);
  const [starting, setStarting] = useState(false);
  const [error, setError] = useState("");
  const [goal, setGoal] = useState<"assess" | "remediate">("remediate");
  const [custom, setCustom] = useState("");
  const [caps, setCaps] = useState<Capabilities | null>(null);
  const [proposals, setProposals] = useState<Proposal[]>([]);

  // Reload the run list; used after a job finishes.
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

  useEffect(() => {
    api.capabilities().then(setCaps).catch(() => setCaps(null));
  }, []);

  // Proposals of the selected run drive the flow stepper; refreshed while anything is in motion.
  const active = job !== null && ACTIVE.has(job.status);
  useEffect(() => {
    if (!run) { setProposals([]); return; }
    let stop = false;
    const load = () => api.proposals(run).then((r) => { if (!stop) setProposals(r.proposals); }).catch(() => { if (!stop) setProposals([]); });
    void load();
    const t = setInterval(() => { void load(); }, 3000);
    return () => { stop = true; clearInterval(t); };
  }, [run, tab]);

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
          if (!ACTIVE.has(next.status) && next.run_id && r.some((x) => x.run_id === next.run_id)) {
            setRun(next.run_id);
            const p = await api.proposals(next.run_id).catch(() => ({ proposals: [] as Proposal[] }));
            if (p.proposals.some((x) => x.applicable)) setTab("remediation");
          }
        })
        .catch((e: Error) => setError(e.message));
    }, 1500);
    return () => {
      stop = true;
      clearInterval(timer);
    };
  }, [job?.id, job?.status]);

  // Start a scan (repo, demo, or a rescan of a pushed branch) and jump to the agent view.
  async function startScan(event: FormEvent | null, demo = false, again?: { repo: string; branch: string }) {
    event?.preventDefault();
    const url = again ? again.repo : repo.trim();
    if (!demo && !url) return;
    setError("");
    setStarting(true);
    try {
      const started = await api.startRun({ repo: demo ? undefined : url, demo, goal: again ? "assess" : goal, custom_goal: again ? undefined : custom.trim() || undefined, branch: again?.branch });
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
  const  needsStored = tab !== "agent";

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
        <form onSubmit={(e) => void startScan(e)} className="mb-4 rounded-lg border border-slate-200 bg-white p-3 shadow-sm">
          <div role="radiogroup" aria-label="Mode" className="mb-2 flex flex-wrap gap-4 text-sm">
            <label className="flex items-center gap-1"><input type="radio" name="mode" checked={mode === "public"} onChange={() => setMode("public")} /> <b>Public repo</b>: analyse and recommend, no push</label>
            <label className="flex items-center gap-1"><input type="radio" name="mode" checked={mode === "own"} onChange={() => setMode("own")} /> <b>My repo</b>: analyse, fix, then prepare a push you run yourself</label>
          </div>
          <label htmlFor="repo" className="mb-1 block text-sm font-semibold text-slate-800">{mode === "own" ? "Your GitHub repository (must be cloneable without a login)" : "Analyze a public GitHub repository"}</label>
          <div className="flex flex-wrap gap-2">
            <input id="repo" className="min-w-[22rem] flex-1 rounded border border-slate-300 px-3 py-2 text-sm" placeholder="https://github.com/owner/repository"
                   value={repo} onChange={(e) => setRepo(e.target.value)} maxLength={200} autoComplete="off" spellCheck={false} />
            <button type="submit" disabled={starting || active || !repo.trim()} className="rounded bg-slate-900 px-4 py-2 text-sm font-medium text-white disabled:opacity-50">
              {starting ? "Starting…" : active ? "Analysis running…" : "Analyze"}
            </button>
            <button type="button" disabled={starting || active} onClick={() => void startScan(null, true)}
                    className="rounded border border-slate-900 px-4 py-2 text-sm font-medium text-slate-900 disabled:opacity-50"
                    title="Two outdated dependencies, a real build and tests">
              Run the demo app
            </button>
          </div>
          <div className="mt-2 flex flex-wrap items-center gap-3 text-xs text-slate-600">
            <label className="flex items-center gap-1">Goal
              <select value={goal} onChange={(e) => setGoal(e.target.value as "assess" | "remediate")} className="rounded border border-slate-300 px-1 py-1">
                <option value="remediate">Assess and propose fixes (stops at human approval)</option>
                <option value="assess">Assess only</option>
              </select>
            </label>
            <input aria-label="Custom goal" placeholder="…or write your own goal (optional)" value={custom} onChange={(e) => setCustom(e.target.value)}
                   maxLength={800} className="min-w-[16rem] flex-1 rounded border border-slate-300 px-2 py-1" />
          </div>
          {caps && (
            <div className="mt-2 flex flex-wrap gap-2 text-xs">
              {([["Agents (DeepInfra)", caps.agents], ["Validation (npm registry)", caps.validation], ["Build/test sandbox", caps.sandbox]] as const).map(([label, c]) => (
                <span key={label} title={c.detail} className={`rounded px-2 py-0.5 ${c.ready ? "bg-emerald-100 text-emerald-800" : "bg-amber-100 text-amber-900"}`}>
                  {c.ready ? "✓" : "!"} {label}{c.ready ? "" : `: ${c.detail}`}
                </span>
              ))}
            </div>
          )}
          <div className="mt-1.5 flex flex-wrap items-center gap-2 text-xs text-slate-500">
            <span>Try:</span>
            {EXAMPLES.map((u) => <button key={u} type="button" onClick={() => setRepo(u)} className="rounded bg-slate-100 px-1.5 py-0.5 font-mono hover:bg-slate-200">{u.replace("https://github.com/", "")}</button>)}
            <span className="ml-auto">Public npm repositories with a package-lock.json. The clone is read-only and nothing from it is executed. The agents plan and choose their own steps.</span>
          </div>
        </form>

        {job && <JobBanner job={job} onWatch={() => { if (job.run_id) setRun(job.run_id); setTab("agent"); }} />}
        {error && <div className="mb-3 rounded bg-red-50 p-2 text-sm text-red-800">{error}</div>}

        {run && stored && <FlowStepper proposals={proposals} onGo={() => setTab("remediation")} />}

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
            {tab === "findings" && <FindingsView key={run} run={run} selected={finding} onSelect={setFinding} onOpenRemediation={() => setTab("remediation")} />}
            {tab === "graph" && <GraphView key={run} run={run} onOpenFinding={openFinding} />}
            {tab === "sbom" && <SbomView key={run} run={run} />}
            {tab === "remediation" && <RemediationView key={run} run={run} mode={mode} onOpenFinding={openFinding} onRescan={(r, b) => void startScan(null, false, { repo: r, branch: b })} />}
            {tab === "report" && <ReportView key={run} run={run} />}
            {tab === "checklist" && <ChecklistView key={run} run={run} />}
          </>
        )}
      </div>
    </div>
  );
}
