import type { ReactNode } from "react";
import { advisoryUrl, type FindingDetail, type GraphElements, type Proposal } from "./api";
import { PathGraph } from "./PathGraph";

const LEVEL_STYLE: Record<string, string> = {
  Critical: "bg-red-700 text-white",
  High: "bg-orange-500 text-white",
  Medium: "bg-amber-300 text-slate-900",
  Low: "bg-slate-200 text-slate-800",
  Unknown: "bg-slate-100 text-slate-600",
};

export function LevelBadge({ level, score }: { level: string | null; score?: number | null }) {
  return (
    <span className={`rounded px-1.5 py-0.5 text-xs font-semibold ${LEVEL_STYLE[level ?? "Unknown"] ?? ""}`}>
      {level ?? "Unscored"}
      {score !== undefined && score !== null ? ` ${score.toFixed(1)}` : ""}
    </span>
  );
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <tr className="border-t border-slate-200 align-top">
      <th className="w-44 py-2 pr-3 text-left text-sm font-medium text-slate-600">{label}</th>
      <td className="py-2 text-sm">{children}</td>
    </tr>
  );
}

// Evidence card, following the PDF section 10 layout. All text renders escaped (React default).
export function EvidenceCard({
  detail, graph, proposals = [], onOpenRemediation,
}: { detail: FindingDetail; graph: GraphElements | null; proposals?: Proposal[]; onOpenRemediation?: () => void }) {
  const validations = proposals.flatMap((p) => p.validations);
  const { finding: f, evidence, explanation } = detail;
  const scannerTools = [...new Set(evidence.map((e) => e.tool))].filter(
    (t) => !["dependency-graph", "epss", "cisa-kev", "oci-layout"].includes(t),
  );
  return (
    <article className="rounded-lg border border-slate-200 bg-white p-4 shadow-sm">
      <header className="mb-2 flex items-start justify-between gap-3">
        <div>
          <div className="text-xs text-slate-500">
            {f.id} · {f.type.replaceAll("_", " ")}
          </div>
          <h2 className="text-lg font-semibold">{f.title}</h2>
        </div>
        <LevelBadge level={f.risk?.level ?? null} score={f.risk?.score ?? null} />
      </header>
      <table className="w-full">
        <tbody>
          <Row label="What was detected">
            {f.type.replaceAll("_", " ")}, severity {f.severity}; source tools: {scannerTools.join(", ") || "n/a"}
            <div className="mt-1 flex flex-wrap gap-1">
              {f.advisory_ids.map((id) => {
                const url = advisoryUrl(id);
                return url ? (
                  <a key={id} href={url} target="_blank" rel="noopener noreferrer"
                     className="rounded bg-slate-100 px-1.5 text-xs text-blue-700 underline">
                    {id}
                  </a>
                ) : (
                  <span key={id} className="rounded bg-slate-100 px-1.5 text-xs">{id}</span>
                );
              })}
            </div>
          </Row>
          <Row label="Affected component">
            <code>{f.component.name}{f.component.version ? `@${f.component.version}` : ""}</code>
            <div className="text-xs text-slate-500">
              {f.component.purl ?? "no purl"} · {f.component.ecosystem ?? "unknown ecosystem"}
            </div>
          </Row>
          <Row label="Dependency path">
            {f.dependency_path.length > 0 ? (
              <div className="mb-2 font-mono text-xs break-all">{f.dependency_path.join("  →  ")}</div>
            ) : (
              <div className="mb-2 text-xs text-slate-500">Not a package dependency.</div>
            )}
            {f.introduced_by.length > 0 && (
              <div className="mb-2 text-xs text-slate-600">Introduced by: {f.introduced_by.join(", ")}</div>
            )}
            <PathGraph elements={graph} />
          </Row>
          <Row label="Supporting evidence">
            <table className="w-full text-xs">
              <thead className="text-left text-slate-500">
                <tr><th>ID</th><th>Tool</th><th>Ref</th><th>Location</th><th>Excerpt (untrusted data)</th></tr>
              </thead>
              <tbody>
                {evidence.map((e) => (
                  <tr key={e.id} className="border-t border-slate-100 align-top">
                    <td className="pr-2 font-mono">{e.id}</td>
                    <td className="pr-2">{e.tool}</td>
                    <td className="pr-2 font-mono">{e.ref ?? ""}</td>
                    <td className="pr-2 font-mono break-all">
                      {e.file ? `${e.file}${e.line ? `:${e.line}` : ""}` : e.graph_node ?? ""}
                    </td>
                    <td className="font-mono break-all text-slate-600">{e.excerpt ?? ""}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Row>
          <Row label="Risk level">
            {f.risk ? (
              <div>
                <div className="mb-1">
                  <LevelBadge level={f.risk.level} score={f.risk.score} />{" "}
                  <span className="text-xs text-slate-500">
                    factor coverage {(f.risk.weight_coverage * 100).toFixed(0)}%
                    {f.risk.override ? ` · override: ${f.risk.override}` : ""}
                  </span>
                </div>
                {f.risk.contributions.map((c) => (
                  <div key={c.factor} className="flex items-center gap-2 text-xs">
                    <span className="w-24 text-slate-600">{c.factor}</span>
                    <div className="h-2 w-40 rounded bg-slate-100">
                      <div className="h-2 rounded bg-blue-600"
                           style={{ width: `${Math.min(100, ((c.contribution ?? 0) / 100) * 100 * 2)}%` }} />
                    </div>
                    <span className="text-slate-500">
                      {c.value === null ? "unknown (left out)" : `${c.value} × ${c.effective_weight} = ${c.contribution}`}
                    </span>
                  </div>
                ))}
                <div className="mt-1 text-xs text-slate-500">
                  Reachability {f.factors.reachability.replaceAll("_", " ")}, exposure{" "}
                  {f.factors.exposure.replaceAll("_", " ")}, KEV{" "}
                  {f.factors.kev === null ? "unknown" : f.factors.kev ? "yes" : "no"}
                </div>
              </div>
            ) : (
              "Not scored"
            )}
          </Row>
          {detail.confidence && (
            <Row label="Confidence">
              <span className="font-semibold">{detail.confidence.level}</span>
              <ul className="list-disc pl-5 text-xs text-slate-600">
                {detail.confidence.reasons.map((r) => <li key={r}>{r}</li>)}
              </ul>
              <div className="text-xs text-slate-500">Computed from tool agreement and factor coverage (a fact, not model opinion).</div>
            </Row>
          )}
          {detail.confidence && (
            <Row label="Confidence">
              <span className="font-semibold">{detail.confidence.level}</span>
              <ul className="list-disc pl-5 text-xs text-slate-600">
                {detail.confidence.reasons.map((r) => <li key={r}>{r}</li>)}
              </ul>
              <div className="text-xs text-slate-500">Computed from tool agreement and factor coverage (a fact, not model opinion).</div>
            </Row>
          )}
          <Row label="AI explanation">
            {explanation ? (
              <div>
                <p>{explanation.why_it_matters}</p>
                <p>{explanation.reachability}</p>
                <p>
                  Confidence {explanation.confidence}: {explanation.confidence_reason}
                </p>
                <p className="mt-1 text-xs text-slate-500">
                  Cites {explanation.cited_evidence.join(", ")} · {explanation.generator} (
                  {explanation.provider}:{explanation.model}) · passed the deterministic gate
                </p>
              </div>
            ) : (
              <span className="text-slate-500">No accepted explanation.</span>
            )}
            {detail.rejected_explanations > 0 && (
              <p className="mt-1 text-xs text-amber-700">
                {detail.rejected_explanations} explanation attempt(s) were rejected by the gate and are not shown.
              </p>
            )}
          </Row>
          <Row label="Recommended fix">
            <span className="text-slate-500">Tool-reported fix versions: </span>
            {f.fixed_in.length > 0
              ? f.fixed_in.map((x) => `${x.tool}: ${x.versions.join(", ")}`).join("; ")
              : "none reported"}
            {proposals.length > 0 ? (
              <ul className="mt-1 text-sm">
                {proposals.map((p) => (
                  <li key={p.id}>
                    <b>{p.id}</b> {p.summary} <span className="rounded bg-slate-100 px-1.5 py-0.5 text-xs">{p.status}</span>
                    {onOpenRemediation && <> <button type="button" className="text-sky-700 underline" onClick={onOpenRemediation}>review and approve</button></>}
                  </li>
                ))}
              </ul>
            ) : (
              <div className="text-xs text-slate-500">No proposal yet. Ask the agents to propose remediations.</div>
            )}
          </Row>
          <Row label="Validation">
            {validations.length > 0 ? (
              validations.map((v) => <div key={v.at}>{v.verdict.replaceAll("_", " ")} · {v.at}</div>)
            ) : (
              <span className="text-slate-500">Not validated. Validation runs only after a human approves a proposal.</span>
            )}
          </Row>
        </tbody>
      </table>
    </article>
  );
}
