import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import type { EntraBlocker, EntraDomainMeta, EntraMeta } from "../../api";

/**
 * Shared chrome for the Entra ID Support Agent.
 *
 * The governing rule for every screen in this area: render `meta` BEFORE the data. A tenant
 * where half the model could not be measured must say so at the top of the page, otherwise a
 * blind pillar reads as a clean one — the single worst failure mode this product can have.
 */

/**
 * Initial sub-tab taken from `?sub=`, consumed once and then stripped from the URL.
 *
 * Entra sub-tabs are component state rather than routes, so a bare /entra/:tab link always
 * opens the first one. The legacy /identity redirects need to land on a specific sub-tab to
 * arrive where the old bookmark pointed. The parameter is removed after it is read because
 * leaving it in the address bar would make the URL lie the moment the user clicked elsewhere.
 */
export function useInitialSubTab<T extends string>(valid: readonly T[], fallback: T): T {
  const [params, setParams] = useSearchParams();
  const [initial] = useState<T>(() => {
    const v = params.get("sub") as T | null;
    return v && valid.includes(v) ? v : fallback;
  });
  useEffect(() => {
    if (!params.has("sub")) return;
    const next = new URLSearchParams(params);
    next.delete("sub");
    setParams(next, { replace: true });
    // Mount-only: this consumes the incoming link, it must not re-run when the user
    // later edits other query parameters on the same screen.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  return initial;
}

export const SEV_STYLE: Record<string, { label: string; chip: string; dot: string; rank: number }> = {
  critical: { label: "Critical", chip: "bg-red-100 text-red-700", dot: "bg-red-500", rank: 4 },
  high: { label: "High", chip: "bg-orange-100 text-orange-700", dot: "bg-orange-500", rank: 3 },
  medium: { label: "Medium", chip: "bg-amber-100 text-amber-700", dot: "bg-amber-500", rank: 2 },
  low: { label: "Low", chip: "bg-sky-100 text-sky-700", dot: "bg-sky-500", rank: 1 },
  info: { label: "Info", chip: "bg-gray-100 text-gray-600", dot: "bg-gray-400", rank: 0 },
};

export function SevBadge({ sev }: { sev: string }) {
  const m = SEV_STYLE[sev] ?? SEV_STYLE.info;
  return <span className={`rounded px-1.5 py-0.5 text-[11px] font-medium ${m.chip}`}>{m.label}</span>;
}

const STATE_STYLE: Record<string, { label: string; chip: string }> = {
  measured: { label: "measured", chip: "bg-green-100 text-green-700" },
  ok: { label: "measured", chip: "bg-green-100 text-green-700" },
  partial: { label: "partial", chip: "bg-amber-100 text-amber-700" },
  blind: { label: "not permitted", chip: "bg-red-100 text-red-700" },
  unlicensed: { label: "not licensed", chip: "bg-violet-100 text-violet-700" },
  error: { label: "error", chip: "bg-red-100 text-red-700" },
  stale: { label: "stale", chip: "bg-amber-100 text-amber-700" },
  not_implemented: { label: "not in this build", chip: "bg-gray-100 text-gray-500" },
  not_collected: { label: "not collected", chip: "bg-gray-100 text-gray-500" },
};

export function StateChip({ state, title }: { state: string; title?: string }) {
  const m = STATE_STYLE[state] ?? STATE_STYLE.not_collected;
  return (
    <span title={title} className={`rounded px-1.5 py-0.5 text-[11px] font-medium ${m.chip}`}>
      {m.label}
    </span>
  );
}

export function agoText(seconds: number | null | undefined): string {
  if (seconds == null) return "never";
  if (seconds < 60) return "just now";
  const m = Math.floor(seconds / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

/** "refreshed 14m ago" + a refresh affordance. Amber past TTL, red past 24h. */
export function FreshnessBadge({
  meta,
  onRefresh,
  refreshing,
  canRefresh = true,
}: {
  meta?: EntraMeta;
  onRefresh?: () => void;
  refreshing?: boolean;
  canRefresh?: boolean;
}) {
  const age = meta?.age_seconds ?? null;
  const tone =
    age == null ? "text-gray-500" : age > 86400 ? "text-red-600" : meta?.stale ? "text-amber-600" : "text-gray-500";
  return (
    <div className="flex items-center gap-2 text-xs">
      <span className={tone}>
        {meta?.loaded ? `refreshed ${agoText(age)}` : "not loaded"}
        {meta?.truncated ? " · partial" : ""}
      </span>
      {canRefresh && onRefresh && (
        <button
          onClick={onRefresh}
          disabled={refreshing}
          className="rounded border px-2 py-1 text-xs font-medium text-gray-700 transition hover:bg-gray-50 disabled:opacity-50"
        >
          {refreshing ? "Refreshing…" : "Refresh"}
        </button>
      )}
    </div>
  );
}

/**
 * The coverage banner. Names the exact missing permission or licence rather than leaving a
 * screen mysteriously empty.
 */
export function CoverageBanner({ meta, onOpenSetup }: { meta?: EntraMeta; onOpenSetup?: () => void }) {
  // Collapsed by default. This banner appears on every screen, and expanded it consumed a
  // third of the viewport above the content the operator actually came for — which trains
  // people to scroll past it, defeating the point of showing coverage at all.
  const [open, setOpen] = useState(false);
  if (!meta || !meta.loaded) return null;
  const domains = Object.values(meta.domains ?? {});
  const blind = domains.filter((d) => d.status === "blind");
  const unlicensed = domains.filter((d) => d.status === "unlicensed");
  const errored = domains.filter((d) => d.status === "error");
  const truncated = domains.filter((d) => d.truncated);
  // A "partial" domain collected fine but lost a sub-call — usually a licence or permission
  // limit. Those notes are the difference between "we found nothing" and "we could not look".
  const limited = domains.filter((d) => d.status === "partial" && (d.notes ?? []).length > 0);
  const blockers = meta.blockers ?? [];
  // Domains whose limitation is already stated as a structured blocker must not ALSO have
  // their prose repeated, or the deduplication buys nothing.
  const explained = new Set(blockers.flatMap((b) => b.domains ?? []));
  const leftover = limited.filter((d) => !explained.has(d.name));
  // Only apps/ca/roles still cap without raising a blocker; those need the generic line.
  const cappedByBlocker = new Set(
    blockers.filter((b) => b.kind === "cap").flatMap((b) => b.domains ?? []));
  const uncappedExplained = truncated.filter((d) => !cappedByBlocker.has(d.name));
  if (!blind.length && !unlicensed.length && !errored.length && !truncated.length
      && !limited.length && !blockers.length) return null;

  const missing = Array.from(new Set(blind.flatMap((d) => d.missing_permissions ?? [])));
  // The collapsed headline names WHICH domains are affected, so it stays actionable
  // instead of being a vague warning nobody can act on without expanding.
  const affected = Array.from(new Set([
    ...blind.map((d) => d.name), ...unlicensed.map((d) => d.name),
    ...errored.map((d) => d.name), ...limited.map((d) => d.name),
    ...truncated.map((d) => d.name),
  ]));
  const tone = errored.length || blind.length
    ? "border-amber-300 bg-amber-50 text-amber-900"
    : "border-gray-200 bg-gray-50 text-gray-700";

  return (
    <div className={`mx-4 mt-3 rounded-lg border px-3 py-2 text-[13px] ${tone}`}>
      <button
        onClick={() => setOpen(!open)}
        className="flex w-full items-center gap-2 text-left"
        aria-expanded={open}
      >
        <span className="text-[11px] opacity-70">{open ? "▾" : "▸"}</span>
        <span className="shrink-0 font-medium">
          {meta.coverage != null
            ? `${Math.round(meta.coverage * 100)}% of the model was measured`
            : "Some checks could not run"}
        </span>
        <span className="truncate text-xs opacity-80">— limits in {affected.join(", ")}</span>
        <span className="ml-auto shrink-0 text-xs underline underline-offset-2 opacity-80">
          {open ? "hide" : "why"}
        </span>
      </button>

      {open && (
        <>
          <ul className="mt-1.5 space-y-0.5 text-xs">
            {blind.length > 0 && (
              <li>
                <span className="font-medium">Not permitted:</span> {blind.map((d) => d.name).join(", ")}
                {missing.length > 0 && <> — missing <code className="rounded bg-amber-100 px-1">{missing.join(", ")}</code></>}
              </li>
            )}
            {/* A whole domain lost to licensing never produces a blocker — the collector
                returns an unlicensed payload and never gets far enough to raise one. Without
                this row those domains appear in the headline with nothing explaining them. */}
            {unlicensed.length > 0 && (
              <li>
                <span className="font-medium">Not licensed:</span> {unlicensed.map((d) => `${d.name} (${d.error})`).join("; ")}
              </li>
            )}
            {errored.map((d) => (
              <li key={d.name}>
                <span className="font-medium">Collection failed:</span> {d.name} — {d.error}
              </li>
            ))}
          </ul>
          {/* Structured blockers replace the per-domain prose: one row per obstacle, naming
              every domain it affects, so a single missing permission is not repeated once
              per domain that wanted it. */}
          <BlockerList blockers={blockers} />
          {leftover.length > 0 && (
            <ul className="mt-1.5 space-y-0.5 text-xs">
              {leftover.map((d) => (
                <li key={d.name}>
                  <span className="font-medium">{d.name}:</span> {(d.notes ?? []).join(" · ")}
                </li>
              ))}
            </ul>
          )}
          {/* Not every collector raises a cap blocker yet. Anything capped without one still
              has to say so, or a truncated grid silently reads as a complete one. */}
          {uncappedExplained.length > 0 && (
            <ul className="mt-1.5 space-y-0.5 text-xs">
              <li>
                <span className="font-medium">Capped:</span>{" "}
                {uncappedExplained.map((d) => d.name).join(", ")} — counts are a lower bound.
              </li>
            </ul>
          )}
          {onOpenSetup && (
            <button onClick={onOpenSetup} className="mt-1.5 text-xs font-medium underline underline-offset-2">
              How to fix the blind spots →
            </button>
          )}
        </>
      )}
    </div>
  );
}

/**
 * Four distinct empty states. A generic "no data" message is how a blind screen gets
 * mistaken for a clean one.
 */
export function EntraEmpty({
  kind,
  detail,
  onRefresh,
  onOpenSetup,
  checked,
}: {
  kind: "cold" | "blind" | "unlicensed" | "clean";
  detail?: string;
  onRefresh?: () => void;
  onOpenSetup?: () => void;
  checked?: string;
}) {
  const copy = {
    cold: { icon: "⏳", title: "Not loaded yet", body: detail || "Nothing has been collected for this tenant yet." },
    blind: { icon: "🔒", title: "Not measured", body: detail || "The connection lacks the Microsoft Graph permission this needs." },
    unlicensed: { icon: "💠", title: "Not measured", body: detail || "This requires a higher Entra ID licence tier." },
    clean: { icon: "✅", title: "Nothing to report", body: detail || "No findings." },
  }[kind];
  return (
    <div className="flex flex-1 flex-col items-center justify-center px-6 py-16 text-center">
      <div className="text-3xl">{copy.icon}</div>
      <div className="mt-2 text-sm font-semibold text-gray-800">{copy.title}</div>
      <div className="mt-1 max-w-md text-[13px] text-gray-500">{copy.body}</div>
      {kind === "clean" && checked && (
        <div className="mt-2 max-w-md text-xs text-gray-400">Checked: {checked}</div>
      )}
      <div className="mt-3 flex gap-2">
        {kind === "cold" && onRefresh && (
          <button onClick={onRefresh} className="rounded bg-brand px-3 py-1.5 text-sm font-medium text-white">
            Refresh now
          </button>
        )}
        {(kind === "blind" || kind === "unlicensed") && onOpenSetup && (
          <button onClick={onOpenSetup} className="rounded border px-3 py-1.5 text-sm font-medium text-gray-700">
            Setup &amp; coverage
          </button>
        )}
      </div>
    </div>
  );
}

/** Deterministic SVG gauge — the score is a computed number, never an animation. */
export function ScoreRing({ score, coverage }: { score: number; coverage: number }) {
  const r = 46;
  const circ = 2 * Math.PI * r;
  const pct = Math.max(0, Math.min(100, score)) / 100;
  const colour = score >= 90 ? "#16a34a" : score >= 75 ? "#65a30d" : score >= 60 ? "#d97706" : score >= 40 ? "#ea580c" : "#dc2626";
  return (
    <svg viewBox="0 0 120 120" className="h-28 w-28" role="img" aria-label={`Identity posture ${score} out of 100`}>
      <circle cx="60" cy="60" r={r} fill="none" stroke="#e5e7eb" strokeWidth="10" />
      <circle
        cx="60" cy="60" r={r} fill="none" stroke={colour} strokeWidth="10" strokeLinecap="round"
        strokeDasharray={`${circ * pct} ${circ}`} transform="rotate(-90 60 60)"
      />
      <text x="60" y="58" textAnchor="middle" className="fill-gray-900" style={{ fontSize: 26, fontWeight: 700 }}>
        {score}
      </text>
      <text x="60" y="76" textAnchor="middle" className="fill-gray-400" style={{ fontSize: 11 }}>
        {Math.round(coverage * 100)}% measured
      </text>
    </svg>
  );
}

export function Bar({ value, max = 100, tone = "bg-brand" }: { value: number; max?: number; tone?: string }) {
  const pct = max > 0 ? Math.max(0, Math.min(100, (value / max) * 100)) : 0;
  return (
    <div className="h-2 w-full overflow-hidden rounded-full bg-gray-200">
      <div className={`h-full rounded-full ${tone}`} style={{ width: `${pct}%` }} />
    </div>
  );
}

export function domainNote(d: EntraDomainMeta): string {
  if (d.status === "blind") return `Missing ${(d.missing_permissions ?? []).join(", ") || "a Graph permission"}`;
  if (d.status === "unlicensed" || d.status === "error") return d.error;
  // The collector's own notes come FIRST. Returning the generic capped sentence before
  // reaching them threw away every specific thing a truncated domain had to say — the risk
  // domain knew it had stopped at 200,000 sign-in events and reported "counts are a lower
  // bound" instead, which is the one row on the page a reader could do nothing with.
  const notes = (d.notes ?? []).join(" · ");
  if (d.truncated) {
    return notes ? `${notes} · Counts are a lower bound.` : "Result was capped — counts are a lower bound.";
  }
  return notes;
}

// How each kind of obstacle is introduced, in the order the reader should act. Splitting
// them is the point: "grant this" and "buy this" and "this is a deliberate limit" were all
// rendered as the same amber prose, so nothing could be triaged.
const BLOCKER_META: Record<string, { label: string; chip: string; verb: string }> = {
  consent: { label: "Needs consent", chip: "bg-amber-100 text-amber-800", verb: "Grant" },
  azure_role: { label: "Needs an Azure role", chip: "bg-orange-100 text-orange-800", verb: "Assign" },
  licence: { label: "Needs a licence", chip: "bg-violet-100 text-violet-800", verb: "Requires" },
  cap: { label: "Deliberate limit", chip: "bg-sky-100 text-sky-800", verb: "Capped at" },
};

export function BlockerList({ blockers }: { blockers: EntraBlocker[] }) {
  if (!blockers.length) return null;
  return (
    <ul className="mt-1.5 space-y-1 text-xs">
      {blockers.map((b, i) => {
        const meta = BLOCKER_META[b.kind] ?? BLOCKER_META.cap;
        return (
          <li key={`${b.kind}-${b.scope}-${i}`} className="flex flex-wrap items-baseline gap-x-1.5">
            <span className={`rounded px-1.5 py-0.5 text-[10px] font-medium ${meta.chip}`}>
              {meta.label}
            </span>
            {b.scope && (
              <code className="rounded bg-white/70 px-1 text-[11px]">{b.scope}</code>
            )}
            {b.subject && <span className="text-[11px] opacity-80">on {b.subject}</span>}
            <span>{b.text}</span>
            {b.impact && <span className="opacity-80">{b.impact}</span>}
            {b.domains?.length ? (
              <span className="opacity-70">Affects {b.domains.join(", ")}.</span>
            ) : null}
          </li>
        );
      })}
    </ul>
  );
}
