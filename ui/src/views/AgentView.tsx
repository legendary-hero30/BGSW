import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { api, type AgentEvent, type AgentTimeline, type Hypothesis, type PlanItem } from "../api";
import { Markdown } from "../markdown";
import { AgentBadge, Card, Chip, Empty, Meter, agentStyle, fmtDuration, fmtTime } from "../ui";

const ISSUE_KINDS = new Set([
  "gate_rejection", "gate_attempt_limit", "tool_error", "blocked", "step_limit", "budget_notice",
  "budget_exhausted", "injection_suspected", "run_error", "findings_rebuilt",
]);

const PLAN_TONE: Record<PlanItem["status"], "neutral" | "info" | "good" | "bad" | "warn"> = {
  pending: "neutral", in_progress: "info", done: "good", blocked: "bad", dropped: "warn",
};
const HYP_TONE: Record<Hypothesis["status"], "neutral" | "good" | "bad" | "warn"> = {
  proposed: "neutral", verified: "good", rejected: "bad", needs_more_evidence: "warn",
};
const STATUS_TONE: Record<string, "info" | "good" | "bad" | "warn" | "neutral"> = {
  running: "info", completed: "good", incomplete: "warn", budget_exhausted: "warn", error: "bad", interrupted: "bad",
};

const str = (v: unknown): string => (typeof v === "string" ? v : v === undefined || v === null ? "" : JSON.stringify(v));
const rec = (v: unknown): Record<string, unknown> => (v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : {});
const list = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);

function argsLine(args: unknown, max = 110): string {
  const parts = Object.entries(rec(args)).map(([k, v]) => `${k}=${typeof v === "string" ? v : JSON.stringify(v)}`);
  const text = parts.join(", ");
  return text.length > max ? `${text.slice(0, max)}…` : text;
}

function Collapsible({ summary, children, open = false }: { summary: ReactNode; children: ReactNode; open?: boolean }) {
  return (
    <details open={open} className="mt-1 rounded border border-slate-200 bg-slate-50">
      <summary className="cursor-pointer select-none px-2 py-1 text-xs text-slate-600">{summary}</summary>
      <div className="border-t border-slate-200 p-2">{children}</div>
    </details>
  );
}

function Pre({ children, max = "max-h-64" }: { children: ReactNode; max?: string }) {
  return <pre className={`${max} overflow-auto whitespace-pre-wrap break-words font-mono text-xs text-slate-700`}>{children}</pre>;
}

function EventBody({ e }: { e: AgentEvent }) {
  const p = e.payload;
  switch (e.kind) {
    case "model_call":
      return <div className="text-xs text-slate-400">model call #{str(p.step)} · {str(p.messages)} messages in context</div>;
    case "model_response": {
      const calls = list(p.tool_calls).map(rec);
      const text = str(p.text).trim();
      return (
        <div>
          {text && <div className="whitespace-pre-wrap rounded-lg bg-slate-100 px-3 py-2 text-sm text-slate-800">{text}</div>}
          {str(p.thinking) && (
            <Collapsible summary="Reasoning exposed by the provider">
              <Pre>{str(p.thinking)}</Pre>
            </Collapsible>
          )}
          {calls.length > 0 && (
            <div className="mt-1 flex flex-wrap items-center gap-1 text-xs text-slate-500">
              <span>decides to call</span>
              {calls.map((c, i) => (
                <code key={i} className="rounded bg-indigo-50 px-1.5 py-0.5 text-indigo-800" title={argsLine(c.args, 400)}>
                  {str(c.name)}
                </code>
              ))}
            </div>
          )}
          {(p.tokens_in != null || p.tokens_out != null) && (
            <div className="mt-0.5 text-[11px] text-slate-400">tokens in {str(p.tokens_in)} · out {str(p.tokens_out)}</div>
          )}
        </div>
      );
    }
    case "tool_call":
    case "tool_error": {
      const failed = e.kind === "tool_error" || p.error === true;
      return (
        <div>
          <div className="flex flex-wrap items-baseline gap-2 text-sm">
            <code className={`rounded px-1.5 py-0.5 font-semibold ${failed ? "bg-red-100 text-red-800" : "bg-indigo-100 text-indigo-900"}`}>{e.name}</code>
            <span className="break-all font-mono text-xs text-slate-600">{argsLine(p.args)}</span>
            {p.ms != null && <span className="text-[11px] text-slate-400">{str(p.ms)} ms · {str(p.result_chars)} chars</span>}
            {failed && <Chip tone="bad">error</Chip>}
          </div>
          {(str(p.preview) || str(p.message)) && (
            <Collapsible summary={failed ? "Error" : "Result (preview)"} open={failed}>
              <Pre max="max-h-40">{str(p.message) || str(p.preview)}</Pre>
            </Collapsible>
          )}
        </div>
      );
    }
    case "delegate_start": {
      const args = rec(p.args);
      return (
        <div>
          <div className="text-sm">
            Delegates to <AgentBadge agent={e.name ?? "specialist"} />
          </div>
          <Collapsible summary="Instructions given" open>
            <Pre max="max-h-40">{str(args.description)}</Pre>
          </Collapsible>
        </div>
      );
    }
    case "delegate":
      return (
        <div>
          <div className="text-sm font-medium text-slate-700">Specialist reported back</div>
          {str(p.result_text) ? (
            <Collapsible summary="Answer" open>
              <div className="max-h-80 overflow-auto"><Markdown source={str(p.result_text)} /></div>
            </Collapsible>
          ) : null}
        </div>
      );
    case "plan":
      return (
        <div className="text-sm">
          <span className="font-medium">Plan {e.name === "add" ? "adds" : "revises"} {str(p.id)}</span>{" "}
          <Chip tone={PLAN_TONE[(str(p.status) as PlanItem["status"]) || "pending"] ?? "neutral"}>{str(p.status)}</Chip>{" "}
          <AgentBadge agent={str(p.assigned_agent) || "supervisor"} />
          <div className="mt-0.5 text-slate-800">{str(p.goal)}</div>
          {str(p.rationale) && <div className="mt-0.5 text-xs italic text-slate-500">why: {str(p.rationale)}</div>}
        </div>
      );
    case "hypothesis":
      return e.name === "verdict" ? (
        <div className="text-sm">
          Verifier rules on <b>{str(p.id)}</b>: <Chip tone={HYP_TONE[(str(p.status) as Hypothesis["status"])] ?? "neutral"}>{str(p.status)}</Chip>
          <ul className="mt-0.5 list-disc pl-5 text-xs text-slate-600">{list(p.reasons).map((r, i) => <li key={i}>{str(r)}</li>)}</ul>
        </div>
      ) : (
        <div className="text-sm">
          Hypothesis <b>{str(p.id)}</b> recorded <Chip>{str(p.kind)}</Chip> <Chip tone="neutral">confidence {str(p.confidence)}</Chip>
          <div className="mt-0.5 text-slate-800">{str(p.claim)}</div>
          <div className="mt-0.5 text-xs text-slate-500">cites findings {list(p.finding_ids).map(str).join(", ")} · evidence {list(p.evidence_refs).map(str).join(", ")}</div>
        </div>
      );
    case "gate_rejection": {
      const reasons = list(p.reasons).length ? list(p.reasons) : list(p.problems);
      return (
        <div className="text-sm">
          <Chip tone="warn">gate rejected</Chip> <b>{e.name}</b>
          {str(p.claim) && <div className="mt-0.5 text-xs text-slate-600">“{str(p.claim)}”</div>}
          <ul className="mt-0.5 list-disc pl-5 text-xs text-amber-900">{reasons.map((r, i) => <li key={i}>{str(r)}</li>)}</ul>
        </div>
      );
    }
    case "gate_attempt_limit":
      return <div className="text-sm"><Chip tone="warn">attempt limit</Chip> no more explanation attempts accepted for {e.name}</div>;
    case "blocked":
      return <div className="text-sm"><Chip tone="bad">blocked</Chip> tool <code>{e.name}</code> is not on {e.agent}'s roster</div>;
    case "step_limit":
      return <div className="text-sm"><Chip tone="warn">step limit</Chip> {e.agent} reached its limit of {str(p.limit)} model calls for this task and was stopped</div>;
    case "budget_notice":
      return <div className="rounded bg-amber-50 px-2 py-1 text-sm text-amber-900">{str(p.text)}</div>;
    case "budget_exhausted":
      return <div className="text-sm"><Chip tone="bad">budget exhausted</Chip> during <code>{e.name}</code>; the run stops here</div>;
    case "injection_suspected":
      return (
        <div className="text-sm">
          <Chip tone="bad">prompt-injection-like text</Chip> {str(p.file)}:{str(p.line)} <span className="text-xs text-slate-500">({str(p.pattern)}) — treated as data, not followed</span>
        </div>
      );
    case "findings_rebuilt":
      return <div className="text-sm"><Chip tone="warn">findings rebuilt</Chip> ids unchanged: {str(p.unchanged)}; explanations were discarded</div>;
    case "sandbox":
      return <div className="text-sm text-slate-600">Sandbox: <b>{e.name}</b> — <span className="text-xs">{str(p.reason)}</span></div>;
    case "run_error":
      return <div className="text-sm"><Chip tone="bad">run error</Chip> {str(p.message)}</div>;
    default:
      return <Pre max="max-h-24">{JSON.stringify(p)}</Pre>;
  }
}

function EventRow({ e }: { e: AgentEvent }) {
  const nested = e.agent !== "supervisor" && e.agent !== "runner" && e.agent !== "security";
  return (
    <li className={`border-l-4 ${agentStyle(e.agent).bar} bg-white py-1.5 pl-3 pr-2 ${nested ? "ml-5" : ""}`}>
      <div className="mb-0.5 flex items-center gap-2 text-[11px] text-slate-400">
        <AgentBadge agent={e.agent} />
        <span>#{e.seq}</span>
        <span>{fmtTime(e.ts)}</span>
        <span className="uppercase tracking-wide">{e.kind.replaceAll("_", " ")}</span>
      </div>
      <EventBody e={e} />
    </li>
  );
}

export function AgentView({
  run,
  following,
  onOpenReport,
}: {
  run: string;
  following: boolean; // a scan job for this run is active: keep polling even before the run row exists
  onOpenReport: () => void;
}) {
  const [data, setData] = useState<AgentTimeline | null>(null);
  const [error, setError] = useState("");
  const [hidden, setHidden] = useState<Set<string>>(new Set());
  const [showCalls, setShowCalls] = useState(false);
  const [onlyIssues, setOnlyIssues] = useState(false);
  const [q, setQ] = useState("");
  const [follow, setFollow] = useState(true);
  const [now, setNow] = useState(() => Date.now());
  const endRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let cancelled = false;
    let seq = 0;
    let timer: ReturnType<typeof setTimeout> | undefined;
    setData(null);
    setError("");
    async function tick() {
      try {
        const t = await api.agentEvents(run, seq);
        if (cancelled) return;
        const last = t.events[t.events.length - 1];
        if (last) seq = last.seq;
        setData((prev) => {
          if (!prev) return t;
          const have = new Set(prev.events.map((x) => x.seq));
          return { ...t, agent_run: t.agent_run ?? prev.agent_run, events: [...prev.events, ...t.events.filter((x) => !have.has(x.seq))] };
        });
        const more = t.events.length >= 400;
        if (more) timer = setTimeout(tick, 0);
        else if (t.live || (following && !t.agent_run)) timer = setTimeout(tick, 1500);
      } catch (e) {
        if (!cancelled) setError((e as Error).message);
      }
    }
    void tick();
    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
    };
  }, [run, following]);

  const live = data?.live === true || (following && !data?.agent_run);
  useEffect(() => {
    if (!live) return;
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, [live]);

  const events = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return (data?.events ?? []).filter((e) => {
      if (hidden.has(e.agent)) return false;
      if (e.kind === "model_call" && !showCalls) return false;
      if (onlyIssues && !(ISSUE_KINDS.has(e.kind) || e.payload.error === true)) return false;
      return !needle || JSON.stringify(e).toLowerCase().includes(needle);
    });
  }, [data, hidden, showCalls, onlyIssues, q]);

  useEffect(() => {
    if (follow && live) endRef.current?.scrollIntoView({ block: "end" });
  }, [events.length, follow, live]);

  if (error && !data) return <Empty title="Could not load the agent run" hint={error} />;
  if (!data) return <Empty title="Loading the agent run…" />;
  const info = data.agent_run;
  if (!info)
    return following ? (
      <Empty title="The agents are starting…" hint="Waiting for the first event." />
    ) : (
      <Empty title="No agent run recorded for this scan" hint="This run was produced by the scanner-only baseline, without agents." />
    );

  const agents = [...new Set(data.events.map((e) => e.agent))];
  const started = new Date(info.started_at).getTime();
  const ended = info.finished_at ? new Date(info.finished_at).getTime() : now;
  const elapsed = (ended - started) / 1000;
  const sawThinking = data.events.some((e) => e.kind === "model_response" && str(e.payload.thinking));
  const u = info.live_usage;

  return (
    <div className="grid gap-4 lg:grid-cols-[21rem_1fr]">
      <aside className="space-y-3">
        <Card
          title="Agent run"
          right={
            <span className="flex items-center gap-1.5">
              {info.status === "running" && <span className="h-2 w-2 animate-pulse rounded-full bg-sky-500" />}
              <Chip tone={STATUS_TONE[info.status] ?? "neutral"}>{info.status.replaceAll("_", " ")}</Chip>
            </span>
          }
        >
          <div className="text-sm text-slate-800">{info.goal}</div>
          <div className="mt-2 text-xs text-slate-500">
            {info.provider} · <span className="font-mono">{info.model}</span>
          </div>
          {info.stop_reason && <div className="mt-1 rounded bg-amber-50 p-1.5 text-xs text-amber-900">{info.stop_reason}</div>}
          {info.has_report && (
            <button type="button" onClick={onOpenReport} className="mt-2 w-full rounded bg-slate-900 px-3 py-1.5 text-sm text-white">
              Read the agent's report
            </button>
          )}
        </Card>

        <Card title="Budget">
          <div className="space-y-2">
            <Meter label="Model calls" used={u.steps} max={info.budget.max_steps} />
            <Meter label="Tool calls" used={u.tool_calls} max={info.budget.max_tool_calls} />
            <Meter label="Tokens" used={u.tokens} max={info.budget.max_tokens} />
            <Meter label="Time" used={Math.round(elapsed)} max={info.budget.max_seconds} unit="s" />
          </div>
          <div className="mt-1 text-[11px] text-slate-400">elapsed {fmtDuration(elapsed)}</div>
        </Card>

        <Card title={`Plan (${data.plan.length})`}>
          {data.plan.length === 0 ? (
            <div className="text-xs text-slate-500">The supervisor has not written a plan yet.</div>
          ) : (
            <ul className="space-y-1.5">
              {data.plan.map((p) => (
                <li key={p.id} className="text-sm">
                  <div className="flex items-center gap-1.5">
                    <span className="font-mono text-xs text-slate-500">{p.id}</span>
                    <Chip tone={PLAN_TONE[p.status]}>{p.status.replaceAll("_", " ")}</Chip>
                    <AgentBadge agent={p.assigned_agent} />
                  </div>
                  <div className="text-slate-800">{p.goal}</div>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card title={`Hypotheses (${data.hypotheses.length})`}>
          {data.hypotheses.length === 0 ? (
            <div className="text-xs text-slate-500">None recorded. Inference is kept separate from tool facts.</div>
          ) : (
            <ul className="space-y-2">
              {data.hypotheses.map((h) => (
                <li key={h.id} className="text-sm">
                  <div className="flex items-center gap-1.5">
                    <span className="font-mono text-xs text-slate-500">{h.id}</span>
                    <Chip tone={HYP_TONE[h.status]}>{h.status.replaceAll("_", " ")}</Chip>
                    <span className="text-xs text-slate-500">{h.confidence}</span>
                  </div>
                  <div className="text-slate-800">{h.claim}</div>
                  {h.reasons.length > 0 && <div className="mt-0.5 text-xs text-slate-500">{h.reasons.join(" · ")}</div>}
                </li>
              ))}
            </ul>
          )}
        </Card>
      </aside>

      <main>
        <div className="mb-2 rounded-lg border border-slate-200 bg-white p-2 text-xs text-slate-600">
          {sawThinking
            ? "Reasoning is shown where the provider exposes it."
            : "This model does not expose hidden reasoning (its reasoning_tokens are 0). Each step shows what the agent wrote before acting, the rationale it records, and the tools it chose."}
        </div>
        <div className="mb-2 flex flex-wrap items-center gap-2 text-xs">
          {agents.map((a) => (
            <button
              key={a}
              type="button"
              onClick={() => setHidden((h) => { const n = new Set(h); if (n.has(a)) n.delete(a); else n.add(a); return n; })}
              className={`rounded-full border px-2 py-0.5 ${hidden.has(a) ? "border-slate-200 text-slate-400 line-through" : "border-slate-300 bg-white"}`}
            >
              {a.replaceAll("_", " ")}
            </button>
          ))}
          <label className="flex items-center gap-1"><input type="checkbox" checked={showCalls} onChange={(e) => setShowCalls(e.target.checked)} /> model calls</label>
          <label className="flex items-center gap-1"><input type="checkbox" checked={onlyIssues} onChange={(e) => setOnlyIssues(e.target.checked)} /> only problems</label>
          <label className="flex items-center gap-1"><input type="checkbox" checked={follow} onChange={(e) => setFollow(e.target.checked)} /> follow live</label>
          <input aria-label="Filter events" placeholder="Filter events" value={q} onChange={(e) => setQ(e.target.value)}
                 className="ml-auto w-44 rounded border border-slate-300 px-2 py-0.5" />
          <span className="text-slate-400">{events.length} of {data.events.length} events</span>
        </div>
        {events.length === 0 ? (
          <Empty title="No events match" />
        ) : (
          <ol className="divide-y divide-slate-100 overflow-hidden rounded-lg border border-slate-200">
            {events.map((e) => <EventRow key={e.seq} e={e} />)}
          </ol>
        )}
        {live && <div className="mt-2 flex items-center gap-2 text-xs text-slate-500"><span className="h-2 w-2 animate-pulse rounded-full bg-sky-500" /> working…</div>}
        <div ref={endRef} />
      </main>
    </div>
  );
}
