import cytoscape from "cytoscape";
import { useEffect, useRef } from "react";
import type { GraphElements } from "./api";

const ROLE_COLOR: Record<string, string> = {
  root: "#1e293b",
  path: "#2563eb",
  target: "#dc2626",
  context: "#94a3b8",
};

// Dependency path view: the finding's path is highlighted; other parents are shown for context.
export function PathGraph({ elements }: { elements: GraphElements | null }) {
  const container = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!container.current || !elements || elements.nodes.length === 0) return;
    const cy = cytoscape({
      container: container.current,
      elements: [...elements.nodes, ...elements.edges],
      layout: { name: "breadthfirst", directed: true, spacingFactor: 1.1, padding: 12 },
      userZoomingEnabled: true,
      maxZoom: 1.4,
      boxSelectionEnabled: false,
      style: [
        {
          selector: "node",
          style: {
            label: "data(label)",
            "font-size": 9,
            "text-wrap": "ellipsis",
            "text-max-width": "150px",
            "text-valign": "bottom",
            "text-margin-y": 4,
            width: 14,
            height: 14,
            "background-color": (n: cytoscape.NodeSingular) => ROLE_COLOR[n.data("role")] ?? "#94a3b8",
            color: "#334155",
          },
        },
        { selector: "node[?on_path]", style: { width: 18, height: 18, "font-weight": "bold" } },
        {
          selector: "edge",
          style: {
            width: 1,
            "line-color": "#cbd5e1",
            "target-arrow-color": "#cbd5e1",
            "target-arrow-shape": "triangle",
            "curve-style": "bezier",
          },
        },
        {
          selector: "edge[?on_path]",
          style: { width: 3, "line-color": "#2563eb", "target-arrow-color": "#2563eb" },
        },
      ],
    });
    return () => cy.destroy();
  }, [elements]);

  if (!elements) return <div className="text-sm text-slate-500">Loading graph…</div>;
  if (elements.nodes.length === 0)
    return <div className="text-sm text-slate-500">No dependency path for this finding type.</div>;
  return (
    <div>
      <div ref={container} className="h-72 w-full rounded border border-slate-200 bg-white" />
      <p className="mt-1 text-xs text-slate-500">
        Source: {elements.source}. Red = affected package, blue = path from the app, grey = other
        parents{elements.other_parents ? ` (${elements.other_parents} more not shown)` : ""}.
      </p>
    </div>
  );
}
