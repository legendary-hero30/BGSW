// Small shared UI pieces (chips, cards, risk badges, agent colours).
import type { ReactNode } from "react";

export const RISK_ORDER = ["Critical", "High", "Medium", "Low"] as const;

export const RISK_CHIP: Record<string, string> = {
  Critical: "bg-red-700 text-white",
  High: "bg-orange-500 text-white",
  Medium: "bg-amber-300 text-slate-900",
  Low: "bg-slate-200 text-slate-800",
  None: "bg-slate-100 text-slate-500",
  Unknown: "bg-slate-100 text-slate-600",
};
export const RISK_BAR: Record<string, string> = {
  Critical: "bg-red-700",
  High: "bg-orange-500",
  Medium: "bg-amber-400",
  Low: "bg-slate-400",
};
export const RISK_HEX: Record<string, string> = {
  Critical: "#b91c1c",
  High: "#ea580c",
  Medium: "#f59e0b",
  Low: "#64748b",
  None: "#cbd5e1",
};

// One consistent identity per agent. Full class names (Tailwind scans for them).
const AGENTS: Record<string, { chip: string; bar: string }> = {
  supervisor: { chip: "bg-slate-900 text-white", bar: "border-slate-900" },
  inventory: { chip: "bg-sky-100 text-sky-900", bar: "border-sky-400" },
  vulnerability: { chip: "bg-rose-100 text-rose-900", bar: "border-rose-400" },
  forensics: { chip: "bg-amber-100 text-amber-900", bar: "border-amber-400" },
  container_ci: { chip: "bg-teal-100 text-teal-900", bar: "border-teal-400" },
  risk: { chip: "bg-emerald-100 text-emerald-900", bar: "border-emerald-400" },
  verifier: { chip: "bg-violet-100 text-violet-900", bar: "border-violet-400" },
  remediation: { chip: "bg-orange-100 text-orange-900", bar: "border-orange-400" },
  validation: { chip: "bg-lime-100 text-lime-900", bar: "border-lime-500" },
};
const FALLBACK_AGENT = { chip: "bg-slate-100 text-slate-700", bar: "border-slate-300" };
export const agentStyle = (agent: string) => AGENTS[agent] ?? FALLBACK_AGENT;

export function AgentBadge({ agent }: { agent: string }) {
  return (
    <span className={`rounded px-1.5 py-0.5 text-[11px] font-semibold ${agentStyle(agent).chip}`}>
      {agent.replaceAll("_", " ")}
    </span>
  );
}

export function RiskBadge({ level, score }: { level: string | null | undefined; score?: number | null }) {
  const key = level ?? "Unknown";
  return (
    <span className={`inline-block rounded px-1.5 py-0.5 text-xs font-semibold ${RISK_CHIP[key] ?? RISK_CHIP.Unknown}`}>
      {level ?? "Unscored"}
      {score !== undefined && score !== null ? ` ${score.toFixed(1)}` : ""}
    </span>
  );
}

const TONES: Record<string, string> = {
  neutral: "bg-slate-100 text-slate-700",
  good: "bg-emerald-100 text-emerald-800",
  warn: "bg-amber-100 text-amber-900",
  bad: "bg-red-100 text-red-800",
  info: "bg-sky-100 text-sky-800",
  violet: "bg-violet-100 text-violet-800",
};
export function Chip({ children, tone = "neutral" }: { children: ReactNode; tone?: keyof typeof TONES }) {
  return <span className={`inline-block rounded px-1.5 py-0.5 text-xs font-medium ${TONES[tone]}`}>{children}</span>;
}

export function Card({
  title,
  right,
  children,
  className = "",
}: {
  title?: ReactNode;
  right?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`rounded-lg border border-slate-200 bg-white p-3 shadow-sm ${className}`}>
      {(title || right) && (
        <header className="mb-2 flex items-center justify-between gap-2">
          <h3 className="text-sm font-semibold text-slate-800">{title}</h3>
          {right}
        </header>
      )}
      {children}
    </section>
  );
}

export function Stat({ label, value, sub }: { label: string; value: ReactNode; sub?: ReactNode }) {
  return (
    <div className="rounded-lg border border-slate-200 bg-white px-3 py-2 shadow-sm">
      <div className="text-xs text-slate-500">{label}</div>
      <div className="text-xl font-semibold text-slate-900">{value}</div>
      {sub && <div className="text-xs text-slate-500">{sub}</div>}
    </div>
  );
}

export function Meter({ label, used, max, unit = "" }: { label: string; used: number; max: number | undefined; unit?: string }) {
  const pct = max ? Math.min(100, (used / max) * 100) : 0;
  const color = pct >= 90 ? "bg-red-500" : pct >= 70 ? "bg-amber-500" : "bg-sky-500";
  return (
    <div>
      <div className="flex justify-between text-xs text-slate-600">
        <span>{label}</span>
        <span>
          {used.toLocaleString()}
          {unit} / {max ? max.toLocaleString() : "—"}
          {unit}
        </span>
      </div>
      <div className="mt-0.5 h-1.5 rounded bg-slate-100">
        <div className={`h-1.5 rounded ${color}`} style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}

export function Empty({ title, hint }: { title: string; hint?: string }) {
  return (
    <div className="rounded-lg border border-dashed border-slate-300 bg-white p-8 text-center">
      <div className="text-sm font-medium text-slate-700">{title}</div>
      {hint && <div className="mt-1 text-xs text-slate-500">{hint}</div>}
    </div>
  );
}

export function fmtDuration(seconds: number): string {
  const s = Math.max(0, Math.round(seconds));
  return s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${String(s % 60).padStart(2, "0")}s`;
}

export function fmtTime(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleTimeString([], { hour12: false });
}
