// Fix proposals, human approval, validation report, and the push-and-rescan step.
import { useCallback, useEffect, useState } from "react";
import { api, type Capabilities, type ExportResult, type Proposal, type ValidationReport } from "../api";
import { Card, Chip, Empty, RiskBadge } from "../ui";

const STATUS_TONE: Record<string, "neutral" | "good" | "warn" | "bad" | "info"> = {
  proposed: "info", approved: "warn", rejected: "bad", validated: "good", failed: "bad", applied: "warn",
};
const VERDICT: Record<string, { tone: "good" | "warn" | "bad"; text: string }> = {
  verified: { tone: "good", text: "Verified" },
  partially_verified: { tone: "warn", text: "Partially verified" },
  failed: { tone: "bad", text: "Failed" },
  blocked: { tone: "bad", text: "Blocked" },
};

// Small row of counts per risk level (used for before/after).
function Levels({ levels }: { levels: Record<string, number> }) {
  const entries = Object.entries(levels);
  if (!entries.length) return <span className="text-slate-500">none</span>;
  return <span className="flex flex-wrap gap-1">{entries.map(([k, v]) => <span key={k} className="flex items-center gap-1"><RiskBadge level={k} /> {v}</span>)}</span>;
}

// The validation report: verdict, step results, risk before/after, diffs.
function Report({ r }: { r: ValidationReport }) {
  const v = VERDICT[r.verdict] ?? { tone: "warn" as const, text: r.verdict };
  const fd = r.findings_diff;
  return (
    <Card title="Validation report" right={<Chip tone={v.tone}>{v.text}</Chip>}>
      <ul className="mb-2 list-disc pl-5 text-sm">{r.reasons.map((x) => <li key={x}>{x}</li>)}</ul>
      <div className="grid gap-3 md:grid-cols-2">
        <div>
          <h4 className="text-xs font-semibold uppercase text-slate-500">Steps (tool results)</h4>
          {Object.entries(r.steps).map(([k, s]) => (
            <div key={k} className="text-sm">
              <Chip tone={s.status === "passed" ? "good" : s.status === "failed" ? "bad" : "warn"}>{s.status.replace("_", " ")}</Chip> {k}
              {s.detail && <div className="ml-1 text-xs text-slate-500">{s.detail}</div>}
            </div>
          ))}
        </div>
        {r.risk && (
          <div>
            <h4 className="text-xs font-semibold uppercase text-slate-500">Risk before → after</h4>
            <div className="text-sm">Before ({r.risk.before.findings} findings, top score {r.risk.before.top_score ?? "n/a"}): <Levels levels={r.risk.before.levels} /></div>
            <div className="text-sm">After ({r.risk.after.findings} findings, top score {r.risk.after.top_score ?? "n/a"}): <Levels levels={r.risk.after.levels} /></div>
          </div>
        )}
      </div>
      {fd && (
        <div className="mt-3 grid gap-3 md:grid-cols-3 text-sm">
          <div><b>Resolved ({fd.resolved.length})</b>{fd.resolved.slice(0, 8).map((f) => <div key={f.id} className="font-mono text-xs">{f.component}@{f.version} {f.advisories[0] ?? f.type}</div>)}</div>
          <div><b>Remaining ({fd.remaining.length})</b>{fd.remaining.slice(0, 8).map((f) => <div key={f.id} className="font-mono text-xs">{f.component}@{f.version} {f.level}</div>)}</div>
          <div><b className={fd.new.length ? "text-red-700" : ""}>New ({fd.new.length})</b>{fd.new.slice(0, 8).map((f) => <div key={f.id} className="font-mono text-xs">{f.component}@{f.version} {f.level}</div>)}</div>
        </div>
      )}
      {r.sbom_diff && (
        <details className="mt-3 text-sm">
          <summary className="cursor-pointer font-semibold">SBOM diff: {r.sbom_diff.components_before} → {r.sbom_diff.components_after} components, +{r.sbom_diff.added.length} −{r.sbom_diff.removed.length}, {r.sbom_diff.version_changed.length} changed</summary>
          <div className="grid gap-2 md:grid-cols-3 font-mono text-xs">
            <div><b>Added</b>{r.sbom_diff.added.slice(0, 40).map((x) => <div key={x}>{x}</div>)}</div>
            <div><b>Removed</b>{r.sbom_diff.removed.slice(0, 40).map((x) => <div key={x}>{x}</div>)}</div>
            <div><b>Version changed</b>{r.sbom_diff.version_changed.slice(0, 40).map((x) => <div key={x}>{x}</div>)}</div>
          </div>
        </details>
      )}
      {r.diff && <pre className="mt-3 overflow-x-auto rounded bg-slate-900 p-2 text-xs text-slate-100">{r.diff}</pre>}
      <div className="mt-2 text-xs text-slate-500">
        Final confidence {r.final_confidence}. Branch {r.branch?.branch ?? "none"} {r.branch?.commit?.slice(0, 10)}. Approved by {r.approval?.approver} at {r.approval?.at}. Validated {r.at}.
      </div>
    </Card>
  );
}

// One proposal: details, human approval, validation, and (own-repo mode) push and rescan.
function Detail({ run, id, onChange, mode, onRescan }: { run: string; id: string; onChange: () => void; mode: "public" | "own"; onRescan: (repo: string, branch: string) => void }) {
  const [exported, setExported] = useState<ExportResult | null>(null);
  const [confirm, setConfirm] = useState("");
  const [pushed, setPushed] = useState<{ branch: string; compare_url: string; default_branch_moved: boolean } | null>(null);
  const [caps, setCaps] = useState<Capabilities | null>(null);
  useEffect(() => { api.capabilities().then(setCaps).catch(() => setCaps(null)); }, []);
  const [p, setP] = useState<Proposal | null>(null);
  // Remember the approver name between sessions (browser storage may be unavailable).
  const [approver, setApprover] = useState(() => { try { return localStorage.getItem("guardian.approver") ?? ""; } catch { return ""; } });
  useEffect(() => { try { localStorage.setItem("guardian.approver", approver); } catch { /* storage blocked */ } }, [approver]);
  const [copied, setCopied] = useState(false);
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const load = useCallback(() => api.proposal(run, id).then(setP).catch((e: Error) => setError(e.message)), [run, id]);
  useEffect(() => { void load(); }, [load]);
  const running = p?.validating?.state === "running";
  useEffect(() => {
    if (!running) return;
    const t = setInterval(() => { void load(); }, 2000);
    return () => clearInterval(t);
  }, [running, load]);
  const finished = p?.validating?.state === "done" || p?.validating?.state === "error";
  useEffect(() => { if (finished) onChange(); }, [finished]); // eslint-disable-line react-hooks/exhaustive-deps

  // Ask the server to write the patch and metadata; nothing is pushed yet.
  async function prepare() {
    setError("");
    setBusy(true);
    try {
      const { token } = await api.approvalToken();
      setExported(await api.exportFix(run, id, token));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  // Push the new branch (needs the typed repo name), then rescan that branch.
  async function push() {
    setError("");
    setBusy(true);
    try {
      const { token } = await api.approvalToken();
      const done = await api.pushFix(run, id, confirm.trim(), token);
      setPushed(done);
      if (exported) onRescan(exported.repo, done.branch);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  // Approve, reject or validate. Fetches the per-server token first; the server logs the approver.
  async function act(kind: "approve" | "reject" | "validate") {
    setError("");
    setBusy(true);
    try {
      const { token } = await api.approvalToken();
      if (kind === "validate") await api.validate(run, id, token);
      else await api.decide(run, id, kind, approver.trim(), note, token);
      await load();
      onChange();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  if (!p) return <Empty title="Loading…" hint={error} />;
  const last = p.approvals[p.approvals.length - 1];
  const report = [...p.validations].reverse().find((v) => v.steps) as ValidationReport | undefined;
  return (
    <div className="space-y-3">
      <Card title={`${p.id}: ${p.action.replaceAll("_", " ")}`} right={<span className="flex gap-1"><Chip tone={STATUS_TONE[p.status]}>{p.status}</Chip><Chip>confidence {p.confidence}</Chip></span>}>
        <p className="text-sm">{p.summary}</p>
        <p className="text-xs text-slate-500">Computed from tool-reported fix versions. Finding {p.finding_id}; evidence {p.evidence_refs.join(", ")}.</p>
        {p.justification && <p className="mt-2 rounded bg-violet-50 p-2 text-sm"><b>Agent justification (inference, checked against the finding's data):</b> {p.justification}</p>}
        <div className="mt-3 grid gap-3 md:grid-cols-2 text-sm">
          <div>
            <h4 className="text-xs font-semibold uppercase text-slate-500">Expected risk reduction</h4>
            Resolves {p.expected_risk_reduction.findings_resolved.length ? p.expected_risk_reduction.findings_resolved.join(", ") : "nothing automatically"}
            {p.expected_risk_reduction.highest_level_resolved && <> (highest <RiskBadge level={p.expected_risk_reduction.highest_level_resolved} score={p.expected_risk_reduction.highest_score_resolved} />)</>}
            <div className="text-xs text-slate-500">{p.expected_risk_reduction.note}</div>
          </div>
          <div>
            <h4 className="text-xs font-semibold uppercase text-slate-500">Compatibility impact: {p.compatibility.level}</h4>
            <ul className="list-disc pl-5 text-xs">{p.compatibility.reasons.map((x) => <li key={x}>{x}</li>)}</ul>
          </div>
          <div>
            <h4 className="text-xs font-semibold uppercase text-slate-500">Rollback</h4>
            <ul className="list-disc pl-5 text-xs">{p.rollback.map((x) => <li key={x}>{x}</li>)}</ul>
          </div>
          <div>
            <h4 className="text-xs font-semibold uppercase text-slate-500">Alternatives considered</h4>
            <ul className="list-disc pl-5 text-xs">{p.alternatives_considered.map((a) => <li key={a.action + a.why_not_chosen}><b>{a.action}</b>: {a.why_not_chosen}</li>)}</ul>
          </div>
        </div>
        {p.edits.length > 0 && (
          <pre className="mt-3 overflow-x-auto rounded bg-slate-900 p-2 text-xs text-slate-100">
            {p.edits.map((e) => `${e.file}: ${e.section}.${e.package}  ${e.from_spec ?? "(new)"}  →  ${e.to_spec}`).join("\n")}
          </pre>
        )}
        {p.needs.length > 0 && <div className="mt-2 rounded bg-amber-50 p-2 text-xs text-amber-900">Not applicable automatically. Needs: {p.needs.join("; ")}</div>}
      </Card>

      <Card title="Human approval">
        {p.approvals.length > 0 && (
          <ul className="mb-2 text-sm">
            {p.approvals.map((a, i) => <li key={i}><Chip tone={a.decision === "approved" ? "good" : "bad"}>{a.decision}</Chip> by <b>{a.approver}</b> at {a.at}{a.note ? ` — ${a.note}` : ""} <span className="font-mono text-xs text-slate-400">{a.proposal_sha.slice(0, 10)}</span></li>)}
          </ul>
        )}
        {p.applicable ? (
          <div className="flex flex-wrap items-end gap-2 text-sm">
            <label className="flex flex-col text-xs text-slate-600">Your name (logged)
              <input className="rounded border border-slate-300 px-2 py-1 text-sm" value={approver} onChange={(e) => setApprover(e.target.value)} maxLength={80} />
            </label>
            <label className="flex min-w-[12rem] flex-1 flex-col text-xs text-slate-600">Note
              <input className="rounded border border-slate-300 px-2 py-1 text-sm" value={note} onChange={(e) => setNote(e.target.value)} maxLength={500} />
            </label>
            <button type="button" disabled={busy || !approver.trim() || last?.decision === "approved"} onClick={() => void act("approve")} className="rounded bg-emerald-700 px-3 py-1.5 text-white disabled:opacity-50">Approve</button>
            <button type="button" disabled={busy || !approver.trim() || last?.decision === "rejected"} onClick={() => void act("reject")} className="rounded bg-red-700 px-3 py-1.5 text-white disabled:opacity-50">Reject</button>
            <button type="button" disabled={busy || running || last?.decision !== "approved" || caps?.validation.ready === false} onClick={() => void act("validate")} className="rounded bg-slate-900 px-3 py-1.5 text-white disabled:opacity-50">{running ? "Validating…" : "Validate on a branch"}</button>
          </div>
        ) : <div className="text-sm text-slate-600">This proposal changes no file, so there is nothing to approve for application. It records a recommendation for a human reviewer.</div>}
        {caps?.validation.ready === false && <div className="mt-2 rounded bg-amber-50 p-2 text-xs text-amber-900">Validate is disabled: {caps.validation.detail}.</div>}
        {running && <div className="mt-2 text-sm text-sky-800">{p.validating?.step}</div>}
        {p.validating?.error && <div className="mt-2 rounded bg-red-50 p-2 text-sm text-red-800">{p.validating.error}</div>}
        {error && <div className="mt-2 rounded bg-red-50 p-2 text-sm text-red-800">{error}</div>}
        <p className="mt-2 text-xs text-slate-500">Agents cannot approve. Nothing is merged: validation works on an isolated copy and branch. Build and tests run only in a sandbox container; when none is configured they are reported as “not run” and the verdict cannot be “verified”.</p>
      </Card>
      {report && <Report r={report} />}
      {mode === "own" && report && (report.verdict === "verified" || report.verdict === "partially_verified") && (
        <Card title="Push this fix to your repository, then rescan it">
          <p className="text-sm">Guardian never pushes and never holds your git credentials. It prepares a patch; you run one command in a terminal with your own git login. It pushes a new <code>guardian/fix-…</code> branch only, never the default branch, and nothing is merged.</p>
          <button type="button" disabled={busy} onClick={() => void prepare()} className="mt-2 rounded bg-slate-900 px-3 py-1.5 text-sm text-white disabled:opacity-50">Push fix to my repo…</button>
          {exported && caps?.push.ready && !pushed && (
            <div className="mt-3 rounded border border-amber-300 bg-amber-50 p-2 text-sm">
              <div>Push <b>{exported.branch}</b> to <b>{exported.repo}</b> now, using the token in the server's <code>.env</code>. Type <code>{exported.repo.replace("https://github.com/", "")}</code> to confirm.</div>
              <div className="mt-1 flex gap-2">
                <input aria-label="Repository to confirm" className="flex-1 rounded border border-slate-300 px-2 py-1" value={confirm} onChange={(e) => setConfirm(e.target.value)} />
                <button type="button" disabled={busy || confirm.trim() !== exported.repo.replace("https://github.com/", "")} onClick={() => void push()} className="rounded bg-red-700 px-3 py-1 text-white disabled:opacity-50">Push branch</button>
              </div>
            </div>
          )}
          {exported && caps && !caps.push.ready && <div className="mt-2 text-xs text-slate-600">Server push is off ({caps.push.detail}).</div>}
          {pushed && <div className="mt-2 rounded bg-emerald-50 p-2 text-sm text-emerald-900">Pushed <b>{pushed.branch}</b>{pushed.default_branch_moved ? " (the default branch had moved since the scan; the patch still applied)" : ""}. <a className="underline" href={pushed.compare_url} target="_blank" rel="noreferrer">Open the pull request</a> and merge it yourself. Rescanning the pushed branch now: the new run appears in the Run list.</div>}
          {exported && (
            <div className="mt-2 text-sm">
              <div>Branch <b>{exported.branch}</b> on {exported.repo}{exported.lockfile_origin !== "repository" ? ` (lockfile ${exported.lockfile_origin} by Guardian)` : ""}. Run from the project folder:</div>
              <div className="mt-1 flex items-start gap-2">
                <pre className="flex-1 overflow-x-auto rounded bg-slate-900 p-2 text-xs text-slate-100">{exported.command}</pre>
                <button type="button" onClick={() => { void navigator.clipboard.writeText(exported.command).then(() => setCopied(true)).catch(() => setCopied(false)); }} className="rounded border border-slate-300 px-2 py-1 text-xs">{copied ? "Copied" : "Copy"}</button>
              </div>
            </div>
          )}
        </Card>
      )}
    </div>
  );
}

// Proposal list on the left, the selected proposal's detail on the right.
export function RemediationView({ run, onOpenFinding, mode, onRescan }: { run: string; onOpenFinding: (id: string) => void; mode: "public" | "own"; onRescan: (repo: string, branch: string) => void }) {
  const [rows, setRows] = useState<Proposal[] | null>(null);
  const [sel, setSel] = useState("");
  const [error, setError] = useState("");
  const load = useCallback(() => api.proposals(run).then((r) => { setRows(r.proposals); setSel((s) => s || r.proposals[0]?.id || ""); }).catch((e: Error) => setError(e.message)), [run]);
  useEffect(() => { void load(); }, [load]);

  if (error) return <Empty title="Could not load proposals" hint={error} />;
  if (!rows) return <Empty title="Loading…" />;
  if (!rows.length) return <Empty title="No remediation proposals yet" hint="Ask the agents to fix the findings, e.g. run with the goal “assess and propose remediations”. Proposals appear here for human approval." />;
  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-[22rem_1fr]">
      <aside className="space-y-1">
        {rows.map((p) => (
          <button key={p.id} type="button" onClick={() => setSel(p.id)} className={`block w-full rounded border p-2 text-left text-sm ${sel === p.id ? "border-slate-900 bg-white" : "border-slate-200 bg-slate-50 hover:bg-white"}`}>
            <div className="flex items-center justify-between"><b>{p.id}</b><Chip tone={STATUS_TONE[p.status]}>{p.status}</Chip></div>
            <div className="text-xs text-slate-600">{p.summary}</div>
            <div className="mt-1 text-xs"><span className="text-slate-500">{p.finding_id}</span> <span role="link" tabIndex={0} className="text-sky-700 underline" onClick={(e) => { e.stopPropagation(); onOpenFinding(p.finding_id); }} onKeyDown={(e) => { if (e.key === "Enter") onOpenFinding(p.finding_id); }}>open finding</span></div>
          </button>
        ))}
      </aside>
      <main>{sel && <Detail key={sel} mode={mode} onRescan={onRescan} run={run} id={sel} onChange={() => void load()} />}</main>
    </div>
  );
}
