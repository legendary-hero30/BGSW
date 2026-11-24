import { useEffect, useState } from "react";
import { api, type FindingDetail, type FindingRow, type GraphElements } from "../api";
import { EvidenceCard } from "../EvidenceCard";
import { Empty, RISK_ORDER, RiskBadge } from "../ui";

const TYPES = [
  "", "malicious_package", "vulnerable_direct", "vulnerable_transitive", "vulnerable_image_package",
  "typosquat", "install_script", "lockfile_change", "unexpected_dependency", "untrusted_image",
  "unpinned_ci", "misconfiguration",
];

export function FindingsView({ run, selected, onSelect }: { run: string; selected: string; onSelect: (id: string) => void }) {
  const [filters, setFilters] = useState({ type: "", level: "", q: "" });
  const [rows, setRows] = useState<{ total: number; items: FindingRow[] }>({ total: 0, items: [] });
  const [detail, setDetail] = useState<FindingDetail | null>(null);
  const [graph, setGraph] = useState<GraphElements | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    setError("");
    api.findings(run, { ...filters, limit: 300 })
      .then((r) => {
        setRows(r);
        if (!selected || !r.items.some((i) => i.id === selected)) {
          const first = r.items[0];
          if (first && !selected) onSelect(first.id);
        }
      })
      .catch((e: Error) => setError(e.message));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [run, filters]);

  useEffect(() => {
    if (!selected) {
      setDetail(null);
      return;
    }
    setDetail(null);
    setGraph(null);
    api.finding(run, selected).then(setDetail).catch((e: Error) => setError(e.message));
    api.graph(run, selected).then(setGraph).catch(() => setGraph(null));
  }, [run, selected]);

  if (error && rows.items.length === 0) return <Empty title="Could not load findings" hint={error} />;
  return (
    <div className="grid gap-4 lg:grid-cols-[23rem_1fr]">
      <aside>
        <div className="mb-2 flex flex-wrap gap-1">
          <button type="button" onClick={() => setFilters({ ...filters, level: "" })}
                  className={`rounded-full border px-2 py-0.5 text-xs ${filters.level === "" ? "border-slate-800 bg-slate-800 text-white" : "border-slate-300 bg-white"}`}>
            All
          </button>
          {RISK_ORDER.map((l) => (
            <button key={l} type="button" onClick={() => setFilters({ ...filters, level: filters.level === l ? "" : l })}
                    className={`rounded-full border px-2 py-0.5 text-xs ${filters.level === l ? "border-slate-800 bg-slate-800 text-white" : "border-slate-300 bg-white"}`}>
              {l}
            </button>
          ))}
        </div>
        <div className="mb-2 grid grid-cols-1 gap-2 text-sm">
          <select aria-label="Type" className="rounded border border-slate-300 bg-white px-1 py-1" value={filters.type} onChange={(e) => setFilters({ ...filters, type: e.target.value })}>
            {TYPES.map((t) => <option key={t} value={t}>{t ? t.replaceAll("_", " ") : "All types"}</option>)}
          </select>
          <input aria-label="Search" placeholder="Search package or title" maxLength={100} className="rounded border border-slate-300 px-2 py-1" value={filters.q} onChange={(e) => setFilters({ ...filters, q: e.target.value })} />
        </div>
        <p className="mb-1 text-xs text-slate-500">{rows.total} findings, ranked by risk{rows.total > rows.items.length ? ` (first ${rows.items.length})` : ""}</p>
        <ol className="max-h-[75vh] overflow-y-auto rounded-lg border border-slate-200 bg-white text-sm">
          {rows.items.map((r) => (
            <li key={r.id}>
              <button type="button" onClick={() => onSelect(r.id)}
                      className={`w-full border-b border-slate-100 px-2 py-1.5 text-left ${selected === r.id ? "bg-blue-50" : "hover:bg-slate-50"}`}>
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono text-xs text-slate-500">{r.id}</span>
                  <RiskBadge level={r.risk_level} score={r.risk_score} />
                </div>
                <div className="truncate font-medium">{r.component}{r.version ? `@${r.version}` : ""}</div>
                <div className="truncate text-xs text-slate-500">
                  {r.type.replaceAll("_", " ")} · {r.severity}{r.explained ? " · explained by the agents" : ""}
                </div>
              </button>
            </li>
          ))}
        </ol>
      </aside>
      <main>{detail ? <EvidenceCard detail={detail} graph={graph} /> : <Empty title="Select a finding" />}</main>
    </div>
  );
}
