// Dependency graph view with scope, risk and search filters.
import cytoscape from "cytoscape";
import { useEffect, useRef, useState } from "react";
import { api, type FindingRow, type GraphNodeData, type GraphOverview } from "../api";
import { Card, Chip, Empty, RISK_HEX, RiskBadge } from "../ui";

const LEGEND = ["Critical", "High", "Medium", "Low", "None"] as const;

export function GraphView({ run, onOpenFinding }: { run: string; onOpenFinding: (id: string) => void }) {
  const [scope, setScope] = useState<"runtime" | "all">("runtime");
  const [risk, setRisk] = useState("");
  const [q, setQ] = useState("");
  const [query, setQuery] = useState("");
  const [limit, setLimit] = useState(160);
  const [layout, setLayout] = useState<"tree" | "force">("tree");
  const [data, setData] = useState<GraphOverview | null>(null);
  const [error, setError] = useState("");
  const [selected, setSelected] = useState<GraphNodeData | null>(null);
  const [findings, setFindings] = useState<FindingRow[]>([]);
  const box = useRef<HTMLDivElement>(null);
  const cyRef = useRef<cytoscape.Core | null>(null);

  useEffect(() => {
    const id = setTimeout(() => setQuery(q), 300);
    return () => clearTimeout(id);
  }, [q]);

  useEffect(() => {
    setData(null);
    setError("");
    setSelected(null);
    api.graphOverview(run, { scope, risk: risk || undefined, q: query || undefined, limit })
      .then(setData)
      .catch((e: Error) => setError(e.message));
  }, [run, scope, risk, query, limit]);

  useEffect(() => {
    if (!selected || selected.role === "root") {
      setFindings([]);
      return;
    }
    api.findings(run, { q: selected.name, limit: 50 })
      .then((r) => setFindings(r.items.filter((f) => f.component === selected.name && f.version === selected.version)))
      .catch(() => setFindings([]));
  }, [run, selected]);

  useEffect(() => {
    if (!box.current || !data || data.nodes.length === 0) return;
    const cy = cytoscape({
      container: box.current,
      elements: [...data.nodes, ...data.edges],
      minZoom: 0.15,
      maxZoom: 1.4,
      wheelSensitivity: 0.25,
      style: [
        {
          selector: "node",
          style: {
            label: "data(label)",
            "font-size": 9,
            "text-wrap": "ellipsis",
            "text-max-width": "130px",
            "text-valign": "bottom",
            "text-margin-y": 3,
            color: "#334155",
            "background-color": (n: cytoscape.NodeSingular) => RISK_HEX[String(n.data("risk"))] ?? "#cbd5e1",
            width: (n: cytoscape.NodeSingular) => (n.data("role") === "root" ? 28 : 12 + Math.min(Number(n.data("findings")), 6) * 2),
            height: (n: cytoscape.NodeSingular) => (n.data("role") === "root" ? 28 : 12 + Math.min(Number(n.data("findings")), 6) * 2),
            "border-width": (n: cytoscape.NodeSingular) => (n.data("role") === "transitive" ? 1 : 3),
            "border-color": "#0f172a",
            "border-style": (n: cytoscape.NodeSingular) => (n.data("scope") === "dev" ? "dashed" : "solid"),
          },
        },
        { selector: 'node[role = "root"]', style: { "background-color": "#0f172a", shape: "round-rectangle" } },
        {
          selector: "edge",
          style: {
            width: 1,
            "line-color": "#cbd5e1",
            "target-arrow-color": "#cbd5e1",
            "target-arrow-shape": "triangle",
            "arrow-scale": 0.7,
            "curve-style": "bezier",
          },
        },
        { selector: ".dim", style: { opacity: 0.15 } },
        { selector: "edge.path", style: { width: 3, "line-color": "#2563eb", "target-arrow-color": "#2563eb" } },
        { selector: "node.path", style: { "border-color": "#2563eb", "border-width": 3 } },
      ],
      layout: (layout === "tree"
        ? // `roots` takes a selector at runtime; the bundled typings only list string[].
          { name: "breadthfirst", directed: true, roots: '[role = "root"]', spacingFactor: 1.1, padding: 20 }
        : { name: "cose", animate: false, nodeRepulsion: () => 9000, idealEdgeLength: () => 70, padding: 20 }) as unknown as cytoscape.LayoutOptions,
    });
    cyRef.current = cy;
    cy.on("tap", "node", (evt) => {
      const node = evt.target as cytoscape.NodeSingular;
      cy.elements().addClass("dim").removeClass("path");
      node.predecessors().add(node).removeClass("dim").addClass("path");
      setSelected(node.data() as GraphNodeData);
    });
    cy.on("tap", (evt) => {
      if (evt.target === cy) {
        cy.elements().removeClass("dim path");
        setSelected(null);
      }
    });
    return () => {
      cy.destroy();
      cyRef.current = null;
    };
  }, [data, layout]);

  const s = data?.stats;
  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-[1fr_20rem]">
      <div>
        <div className="mb-2 flex flex-wrap items-center gap-2 text-sm">
          <select aria-label="Scope" value={scope} onChange={(e) => setScope(e.target.value as "runtime" | "all")} className="rounded border border-slate-300 bg-white px-2 py-1">
            <option value="runtime">Runtime dependencies</option>
            <option value="all">Runtime + dev</option>
          </select>
          <select aria-label="Minimum risk" value={risk} onChange={(e) => setRisk(e.target.value)} className="rounded border border-slate-300 bg-white px-2 py-1">
            <option value="">Direct + any finding</option>
            <option value="Critical">Critical only</option>
            <option value="High">High and above</option>
            <option value="Medium">Medium and above</option>
            <option value="Low">Low and above</option>
          </select>
          <input aria-label="Find a package" placeholder="Find a package…" value={q} onChange={(e) => setQ(e.target.value)} maxLength={80} className="w-44 rounded border border-slate-300 px-2 py-1" />
          <label className="flex items-center gap-1 text-xs text-slate-600">
            max nodes
            <input type="range" min={40} max={400} step={20} value={limit} onChange={(e) => setLimit(Number(e.target.value))} />
            {limit}
          </label>
          <select aria-label="Layout" value={layout} onChange={(e) => setLayout(e.target.value as "tree" | "force")} className="rounded border border-slate-300 bg-white px-2 py-1">
            <option value="tree">Tree layout</option>
            <option value="force">Force layout</option>
          </select>
          <button type="button" onClick={() => cyRef.current?.fit(undefined, 30)} className="rounded border border-slate-300 bg-white px-2 py-1">Fit</button>
        </div>
        {error && <Empty title="Could not load the graph" hint={error} />}
        {!error && !data && <Empty title="Loading the dependency graph…" />}
        {data && data.nodes.length <= 1 && <Empty title="Nothing matches" hint="Try a different search or a lower risk threshold." />}
        {data && data.nodes.length > 1 && (
          <>
            <div ref={box} className="h-[36rem] w-full rounded-lg border border-slate-200 bg-white" />
            <div className="mt-2 flex flex-wrap items-center gap-3 text-xs text-slate-600">
              {LEGEND.map((l) => (
                <span key={l} className="flex items-center gap-1">
                  <span className="inline-block h-3 w-3 rounded-full" style={{ background: RISK_HEX[l] }} />
                  {l === "None" ? "no findings" : l}
                </span>
              ))}
              <span>thick border = direct dependency</span>
              <span>dashed = dev only</span>
              <span>bigger = more findings</span>
              <span>click a package to trace its path to the app</span>
            </div>
          </>
        )}
      </div>

      <aside className="space-y-3">
        {s && (
          <Card title="This view">
            <div className="text-sm text-slate-700">
              Showing <b>{s.shown_nodes}</b> of <b>{s.total_nodes}</b> {s.scope === "runtime" ? "runtime " : ""}packages: direct
              dependencies and packages with findings, each with its path from the app.
            </div>
            {s.truncated && <div className="mt-1"><Chip tone="warn">{s.focus_skipped} packages left out by the node limit</Chip></div>}
          </Card>
        )}
        <Card title="Selected package">
          {!selected ? (
            <div className="text-xs text-slate-500">Click a node.</div>
          ) : (
            <div className="space-y-1.5 text-sm">
              <div className="font-mono break-all">{selected.label}</div>
              <div className="flex flex-wrap gap-1">
                <Chip>{selected.role}</Chip>
                <Chip tone={selected.scope === "dev" ? "warn" : "neutral"}>{selected.scope}</Chip>
                <Chip>depth {selected.depth}</Chip>
                {selected.risk !== "None" && <RiskBadge level={selected.risk} />}
              </div>
              {findings.length > 0 && (
                <ul className="mt-1 space-y-1">
                  {findings.map((f) => (
                    <li key={f.id}>
                      <button type="button" onClick={() => onOpenFinding(f.id)} className="w-full rounded border border-slate-200 px-2 py-1 text-left text-xs hover:bg-slate-50">
                        <RiskBadge level={f.risk_level} score={f.risk_score} /> <span className="font-mono">{f.id}</span>{" "}
                        <span className="text-slate-500">{f.type.replaceAll("_", " ")}</span>
                      </button>
                    </li>
                  ))}
                </ul>
              )}
              {selected.role !== "root" && findings.length === 0 && <div className="text-xs text-slate-500">No findings on this package.</div>}
            </div>
          )}
        </Card>
      </aside>
    </div>
  );
}
