// Run summary: counts by risk level and type, and shortcuts to the other tabs.
import { useEffect, useState } from "react";
import { api, type AgentTimeline, type FindingRow, type RunSummary } from "../api";
import { AgentBadge, Card, Chip, Empty, RISK_BAR, RISK_ORDER, RiskBadge, Stat } from "../ui";

export function OverviewView({
  run,
  onOpenFinding,
  go,
}: {
  run: string;
  onOpenFinding: (id: string) => void;
  go: (tab: "agent" | "findings" | "graph" | "sbom" | "report") => void;
}) {
  const [s, setS] = useState<RunSummary | null>(null);
  const [top, setTop] = useState<FindingRow[]>([]);
  const [agent, setAgent] = useState<AgentTimeline | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    setS(null);
    setError("");
    api.summary(run).then(setS).catch((e: Error) => setError(e.message));
    api.findings(run, { limit: 8 }).then((r) => setTop(r.items)).catch(() => setTop([]));
    api.agentEvents(run, 0, 1).then(setAgent).catch(() => setAgent(null));
  }, [run]);

  if (error) return <Empty title="Could not load the summary" hint={error} />;
  if (!s) return <Empty title="Loading…" />;
  const levels = RISK_ORDER.map((l) => [l, s.by_risk_level[l] ?? 0] as const);
  const max = Math.max(1, ...levels.map(([, n]) => n));
  const cov = s.coverage;
  const run_ = agent?.agent_run;
  return (
    <div className="space-y-4">
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
        <Stat label="Findings" value={s.findings} sub={`${s.dependency_findings} in dependencies`} />
        <Stat label="Vulnerable packages" value={s.vulnerable_packages} sub={`${s.runtime_findings} runtime · ${s.dev_only_findings} dev-only`} />
        <Stat label="Known exploited (KEV)" value={s.kev_findings} sub="CISA catalog" />
        <Stat label="With a fix available" value={s.with_fix} sub="reported by a scanner" />
        <Stat label="Commit" value={<span className="font-mono text-base">{s.target.commit.slice(0, 10)}</span>} sub={s.target.name} />
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="Risk distribution">
          <ul className="space-y-1.5">
            {levels.map(([level, n]) => (
              <li key={level} className="flex items-center gap-2 text-sm">
                <span className="w-16"><RiskBadge level={level} /></span>
                <div className="h-3 flex-1 rounded bg-slate-100"><div className={`h-3 rounded ${RISK_BAR[level]}`} style={{ width: `${(n / max) * 100}%` }} /></div>
                <span className="w-10 text-right tabular-nums">{n}</span>
              </li>
            ))}
          </ul>
          <div className="mt-2 flex flex-wrap gap-1">
            {Object.entries(s.by_type).sort((a, b) => b[1] - a[1]).map(([t, n]) => <Chip key={t}>{t.replaceAll("_", " ")} {n}</Chip>)}
          </div>
        </Card>

        <Card title="What was checked">
          {cov ? (
            <div className="space-y-1.5 text-sm">
              <div>Dependency scanners run: {cov.scanners_run.map((x) => <Chip key={x} tone="good">{x}</Chip>)} {cov.scanners_not_run.map((x) => <Chip key={x} tone="warn">{x}: not run</Chip>)}</div>
              <div className="flex flex-wrap gap-1">
                <Chip tone={cov.dockerfile_scanned ? "good" : "warn"}>Dockerfile {cov.dockerfile_scanned ? "scanned" : "not scanned"}</Chip>
                <Chip tone={cov.workflows_scanned ? "good" : "warn"}>CI workflows {cov.workflows_scanned ? "scanned" : "not scanned"}</Chip>
                <Chip tone={cov.image_scanned ? "good" : "warn"}>Base image {cov.image_scanned ? "scanned" : "not scanned"}</Chip>
                <Chip tone={cov.anomaly_rules_run ? "good" : "warn"}>Anomaly rules {cov.anomaly_rules_run ? "run" : "not run"}</Chip>
              </div>
              <div className="text-xs text-slate-500">Tools: {Object.entries(s.tools).map(([k, v]) => `${k} ${v.replace(/^\S+\s/, "")}`).join(" · ")}</div>
            </div>
          ) : (
            <div className="text-sm text-slate-600">Scanner-only baseline: every scanner and inspection was run in a fixed order.</div>
          )}
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-[1fr_22rem]">
        <Card title="Highest-risk findings" right={<button type="button" onClick={() => go("findings")} className="text-xs text-blue-700 underline">All findings</button>}>
          <ul className="divide-y divide-slate-100">
            {top.map((f) => (
              <li key={f.id}>
                <button type="button" onClick={() => onOpenFinding(f.id)} className="flex w-full items-center gap-2 py-1.5 text-left text-sm hover:bg-slate-50">
                  <RiskBadge level={f.risk_level} score={f.risk_score} />
                  <span className="font-mono text-xs text-slate-500">{f.id}</span>
                  <span className="truncate font-medium">{f.component}{f.version ? `@${f.version}` : ""}</span>
                  <span className="ml-auto truncate text-xs text-slate-500">{f.type.replaceAll("_", " ")}</span>
                </button>
              </li>
            ))}
          </ul>
        </Card>

        <Card title="Agents" right={<button type="button" onClick={() => go("agent")} className="text-xs text-blue-700 underline">Watch the run</button>}>
          {!run_ ? (
            <div className="text-sm text-slate-600">No agent run for this scan (scanner-only baseline).</div>
          ) : (
            <div className="space-y-1.5 text-sm">
              <div><Chip tone={run_.status === "completed" ? "good" : run_.status === "running" ? "info" : "warn"}>{run_.status.replaceAll("_", " ")}</Chip> <span className="font-mono text-xs">{run_.model}</span></div>
              <div className="text-xs text-slate-600">{run_.live_usage.steps} model calls · {run_.live_usage.tool_calls} tool calls · {run_.live_usage.tokens.toLocaleString()} tokens</div>
              <div className="text-xs text-slate-600">plan items {agent?.plan.filter((p) => p.status === "done").length}/{agent?.plan.length} done · hypotheses {agent?.hypotheses.filter((h) => h.status === "verified").length}/{agent?.hypotheses.length} verified</div>
              <div className="flex flex-wrap gap-1">{[...new Set(agent?.plan.map((p) => p.assigned_agent))].map((a) => <AgentBadge key={a} agent={a} />)}</div>
              {run_.has_report && <button type="button" onClick={() => go("report")} className="mt-1 w-full rounded bg-slate-900 px-3 py-1.5 text-sm text-white">Read the report</button>}
            </div>
          )}
        </Card>
      </div>

      <div className="grid gap-3 sm:grid-cols-3">
        <button type="button" onClick={() => go("graph")} className="rounded-lg border border-slate-200 bg-white p-3 text-left text-sm shadow-sm hover:bg-slate-50"><b>Dependency graph</b><div className="text-xs text-slate-500">Trace any package to the app.</div></button>
        <button type="button" onClick={() => go("sbom")} className="rounded-lg border border-slate-200 bg-white p-3 text-left text-sm shadow-sm hover:bg-slate-50"><b>SBOM</b><div className="text-xs text-slate-500">CycloneDX components and download.</div></button>
        <button type="button" onClick={() => go("agent")} className="rounded-lg border border-slate-200 bg-white p-3 text-left text-sm shadow-sm hover:bg-slate-50"><b>Agent steps</b><div className="text-xs text-slate-500">Every decision and tool call.</div></button>
      </div>
    </div>
  );
}
