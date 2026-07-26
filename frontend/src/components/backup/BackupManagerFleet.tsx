// Backup Manager — Fleet.
//
// One row per workload, showing the headline of its LAST analysis, and a bounded launcher that
// sweeps many workloads in the background. Two things make this different from the coverage
// fleets it mirrors:
//
//  1. An analysis is a detached server-side job, not a blocking request. Per-row state
//     therefore comes from the batched job endpoint (one poll for the whole grid) rather than
//     from an in-flight fetch registry.
//  2. A poll that doesn't mention a job we just started must NOT read as "idle" — that is
//     exactly how a running sweep ends up looking like nothing happened. Locally-launched
//     scopes are remembered until the server confirms them terminal, with a grace window.
import { useEffect, useMemo, useRef, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type BackupManagerFleetRow, type BackupManagerJobState } from "../../api";
import { queryKeys } from "../../queryKeys";
import { formatError } from "../../utils/format";
import { Skeleton } from "../../utils/perf";
import { enqueueFleet, fleetOutstanding, fleetQueuedKeys, useFleetQueue } from "../fleetScheduler";

/** Analyses are heavy (nine ARG sources per subscription + vault, cost and pricing calls), so
 *  the client launches fewer at once than a coverage scan and spaces the starts further. The
 *  server enforces its own cap as well; this just keeps the queue honest. */
const MAX_PARALLEL = 2;
const STAGGER_MS = 800;
const QUEUE_ID = "backupManagerFleet";
/** How long a locally-started scope stays "analyzing" while the server never reports it. */
const LOST_JOB_GRACE_MS = 30_000;

type SortKey =
  | "worst" | "name" | "protected" | "gaps" | "failed" | "rpo" | "posture" | "cost" | "run_at";
type SortDir = "asc" | "desc";

function jobKey(row: BackupManagerFleetRow): string {
  return `${row.connection_id || "default"}|workload|${row.workload_id.toLowerCase()}`;
}

function relTime(iso: string): string {
  if (!iso) return "never";
  const time = new Date(iso).getTime();
  if (Number.isNaN(time)) return "—";
  const seconds = Math.max(0, (Date.now() - time) / 1000);
  if (seconds < 60) return "just now";
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

function fmtMoney(value: number, currency: string): string {
  if (!value) return "—";
  try {
    return new Intl.NumberFormat(undefined, {
      style: "currency", currency: currency || "USD", maximumFractionDigits: 0,
    }).format(value);
  } catch {
    return `${Math.round(value)}`;
  }
}

function PercentPill({ value }: { value: number | null }) {
  if (value == null) return <span className="text-gray-400">n/a</span>;
  const tone = value >= 90 ? "bg-green-100 text-green-700"
    : value >= 60 ? "bg-amber-100 text-amber-700"
      : "bg-red-100 text-red-700";
  return <span className={`inline-block min-w-[3rem] rounded px-1.5 py-0.5 text-center font-semibold tabular-nums ${tone}`}>{value}%</span>;
}

export function BackupManagerFleet({ onOpenWorkload }: {
  onOpenWorkload: (workloadId: string, connectionId: string) => void;
}) {
  const qc = useQueryClient();
  useFleetQueue();
  const [started, setStarted] = useState<Map<string, number>>(new Map());
  const startedRef = useRef(started);
  useEffect(() => { startedRef.current = started; }, [started]);

  const fleetQ = useQuery({
    queryKey: queryKeys.backupManager.fleet,
    queryFn: api.backupManagerFleet,
    refetchOnWindowFocus: false,
  });
  const jobsQ = useQuery({
    queryKey: queryKeys.backupManager.analyzeJobs,
    queryFn: api.backupManagerAnalyzeJobs,
    staleTime: 0,
    refetchOnMount: "always",
    // Poll while anything is running server-side OR while we are waiting for a launch to show
    // up. Stopping the poll on a single quiet response is what makes a live sweep look dead.
    refetchInterval: (query) => {
      const jobs = query.state.data?.jobs ?? {};
      const running = Object.values(jobs).some((job) => job.status === "running");
      return running || startedRef.current.size > 0 ? 2000 : false;
    },
  });
  const jobs = useMemo(() => jobsQ.data?.jobs ?? {}, [jobsQ.data]);

  const rows = useMemo(() => fleetQ.data?.workloads ?? [], [fleetQ.data]);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [search, setSearch] = useState("");
  const [sortKey, setSortKey] = useState<SortKey>("worst");
  const [sortDir, setSortDir] = useState<SortDir>("desc");
  const [message, setMessage] = useState<string | null>(null);
  const queuedKeys = fleetQueuedKeys(QUEUE_ID);

  // Retire a locally-started scope once the server reports it finished (or it goes missing for
  // long enough that nobody is going to report it).
  const doneRef = useRef(new Set<string>());
  useEffect(() => {
    if (!started.size) return;
    let changed = false;
    const next = new Map(started);
    let finished = 0;
    for (const [key, at] of started) {
      const job = jobs[key] as BackupManagerJobState | undefined;
      if (job && job.status !== "running") {
        next.delete(key);
        changed = true;
        if (!doneRef.current.has(job.id)) { doneRef.current.add(job.id); finished += 1; }
      } else if (!job && Date.now() - at > LOST_JOB_GRACE_MS) {
        next.delete(key);
        changed = true;
      }
    }
    if (changed) setStarted(next);
    if (finished) {
      void qc.invalidateQueries({ queryKey: queryKeys.backupManager.fleet });
      void qc.invalidateQueries({ queryKey: queryKeys.backupManager.snapshotRoot });
      void qc.invalidateQueries({ queryKey: queryKeys.backupManager.cleanup });
    }
  }, [jobs, started, qc]);

  const stateOf = (row: BackupManagerFleetRow): { state: "running" | "queued" | "failed" | "idle"; error?: string } => {
    const key = jobKey(row);
    const job = jobs[key];
    if (job?.status === "running" || started.has(key)) return { state: "running" };
    if (queuedKeys.has(key)) return { state: "queued" };
    if (job?.status === "error") return { state: "failed", error: job.error };
    return { state: "idle" };
  };

  const filtered = useMemo(() => {
    const query = search.trim().toLowerCase();
    const list = query
      ? rows.filter((row) => `${row.name} ${row.environment} ${row.criticality}`.toLowerCase().includes(query))
      : rows;
    if (sortKey === "worst") return list; // the server already orders worst-first
    const direction = sortDir === "asc" ? 1 : -1;
    const value = (row: BackupManagerFleetRow): number => {
      if (!row.has_analysis) return -1;
      switch (sortKey) {
        case "protected": return row.pct_protected ?? -1;
        case "gaps": return row.gaps;
        case "failed": return row.failed_jobs;
        case "rpo": return row.rpo_attainment_pct ?? -1;
        case "posture": return row.posture_score;
        case "cost": return row.monthly_cost;
        default: return 0;
      }
    };
    return [...list].sort((a, b) => {
      if (sortKey === "name") return direction * a.name.localeCompare(b.name);
      if (sortKey === "run_at") return direction * (a.run_at || "").localeCompare(b.run_at || "");
      return direction * (value(a) - value(b));
    });
  }, [rows, search, sortKey, sortDir]);

  const launchable = filtered.filter((row) => !row.demo);
  const allSelected = launchable.length > 0 && launchable.every((row) => selected.has(row.workload_id));
  function toggleAll() {
    setSelected((current) => {
      const next = new Set(current);
      launchable.forEach((row) => (allSelected ? next.delete(row.workload_id) : next.add(row.workload_id)));
      return next;
    });
  }
  function toggleOne(id: string) {
    setSelected((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  }

  function enqueueRows(chosen: BackupManagerFleetRow[]) {
    const launching = chosen.filter((row) => !row.demo);
    if (!launching.length) return;
    enqueueFleet(QUEUE_ID, launching.map((row) => ({
      key: jobKey(row),
      run: () => {
        const key = jobKey(row);
        setStarted((current) => new Map(current).set(key, Date.now()));
        void api.backupManagerAnalyzeStart({
          connection_id: row.connection_id, workload_id: row.workload_id,
        }).then(() => {
          void jobsQ.refetch();
        }).catch(() => {
          // The job never started; drop the marker so the row doesn't spin forever.
          setStarted((current) => { const next = new Map(current); next.delete(key); return next; });
        });
      },
    })), {
      maxParallel: MAX_PARALLEL,
      staggerMs: STAGGER_MS,
      // A scope counts as running while the server says so OR while we are still waiting for
      // it to appear, so the scheduler never over-fills its slots.
      isRunning: (key) => startedRef.current.has(key) || jobs[key]?.status === "running",
      subscribe: (cb) => {
        const timer = window.setInterval(cb, 1500);
        return () => window.clearInterval(timer);
      },
    });
  }

  function launch() {
    const chosen = rows.filter((row) => selected.has(row.workload_id));
    if (!chosen.length) return;
    enqueueRows(chosen);
    setMessage(`Analyzing ${chosen.length} workload${chosen.length === 1 ? "" : "s"} — ${MAX_PARALLEL} at a time. Analyses continue on the server if you navigate away.`);
    setSelected(new Set());
  }

  const failedRows = rows.filter((row) => stateOf(row).state === "failed");
  function retryFailed() {
    enqueueRows(failedRows);
    setMessage(`Retrying ${failedRows.length} failed analysis${failedRows.length === 1 ? "" : "es"}…`);
  }

  function clickSort(key: SortKey, defaultDirection: SortDir = "desc") {
    if (sortKey === key) setSortDir((current) => (current === "asc" ? "desc" : "asc"));
    else { setSortKey(key); setSortDir(defaultDirection); }
  }
  const SortHeader = ({ label, value, defaultDirection = "desc" }: {
    label: string; value: SortKey; defaultDirection?: SortDir;
  }) => (
    <th onClick={() => clickSort(value, defaultDirection)}
      className={`cursor-pointer select-none px-2 py-2 font-medium hover:text-gray-700 ${sortKey === value ? "text-gray-700" : ""}`}>
      {label}<span className="ml-0.5 text-[9px] text-gray-400">{sortKey === value ? (sortDir === "asc" ? "▲" : "▼") : "↕"}</span>
    </th>
  );

  const analyzed = fleetQ.data?.analyzed ?? 0;
  const total = fleetQ.data?.total ?? rows.length;
  const outstanding = fleetOutstanding(QUEUE_ID) + started.size;

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="border-b bg-white px-5 py-3">
        <div className="flex flex-wrap items-center gap-3">
          <div className="min-w-0">
            <h2 className="text-sm font-semibold text-gray-900">Fleet backup posture</h2>
            <p className="text-[11px] text-gray-500">
              The last analysis of every workload, from cache. Select workloads to analyze them as one
              background sweep — {MAX_PARALLEL} run at a time so a large estate does not throttle Azure.
            </p>
          </div>
          <div className="ml-auto flex flex-wrap items-center gap-2">
            <span className="text-[11px] text-gray-500">
              {analyzed}/{total} analyzed{outstanding ? ` · ${outstanding} outstanding` : ""}
            </span>
            <input value={search} onChange={(event) => setSearch(event.target.value)}
              placeholder="Filter workloads…" aria-label="Filter workloads"
              className="w-44 rounded-md border px-2 py-1 text-xs" />
            <select value={sortKey} aria-label="Sort fleet"
              onChange={(event) => {
                const key = event.target.value as SortKey;
                setSortKey(key);
                setSortDir(key === "protected" || key === "name" || key === "rpo" || key === "posture" ? "asc" : "desc");
              }}
              className="rounded-md border px-2 py-1 text-xs text-gray-600">
              <option value="worst">Sort: worst first</option>
              <option value="protected">Sort: lowest protected</option>
              <option value="gaps">Sort: most gaps</option>
              <option value="failed">Sort: failing jobs</option>
              <option value="rpo">Sort: lowest RPO attainment</option>
              <option value="posture">Sort: weakest vault posture</option>
              <option value="cost">Sort: highest cost</option>
              <option value="run_at">Sort: newest analysis</option>
              <option value="name">Sort: name</option>
            </select>
            {failedRows.length > 0 && (
              <button onClick={retryFailed}
                className="rounded-md border border-red-300 bg-red-50 px-3 py-1.5 text-sm font-medium text-red-700 hover:bg-red-100">
                ↻ Retry failed ({failedRows.length})
              </button>
            )}
            <button onClick={launch} disabled={!selected.size}
              className="rounded-md bg-gray-900 px-3 py-1.5 text-sm text-white disabled:opacity-50">
              ▶ Analyze {selected.size || ""} selected
            </button>
          </div>
        </div>
        {message && <div className="mt-2 rounded-md border border-green-200 bg-green-50 px-3 py-1.5 text-xs text-green-700">{message}</div>}
      </div>

      <div className="min-h-0 flex-1 overflow-auto px-5 py-4">
        {fleetQ.isLoading ? <Skeleton rows={8} />
          : fleetQ.isError ? <div className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">{formatError(fleetQ.error)}</div>
            : !rows.length ? <div className="rounded-md border border-dashed bg-gray-50 px-4 py-10 text-center text-sm text-gray-500">No workloads exist yet.</div>
              : (
                <table className="w-full text-[12px]">
                  <thead className="sticky top-0 z-10 bg-gray-50 text-left text-gray-500">
                    <tr className="border-b">
                      <th className="w-8 px-2 py-2">
                        <input type="checkbox" checked={allSelected} onChange={toggleAll} aria-label="Select all shown workloads" />
                      </th>
                      <SortHeader label="Workload" value="name" defaultDirection="asc" />
                      <SortHeader label="Protected" value="protected" defaultDirection="asc" />
                      <SortHeader label="Items" value="gaps" />
                      <SortHeader label="Gaps" value="gaps" />
                      <SortHeader label="Failing jobs" value="failed" />
                      <SortHeader label="RPO" value="rpo" defaultDirection="asc" />
                      <SortHeader label="Vault posture" value="posture" defaultDirection="asc" />
                      <SortHeader label="Est. cost / mo" value="cost" />
                      <SortHeader label="Last analysis" value="run_at" />
                      <th className="px-2 py-2" />
                    </tr>
                  </thead>
                  <tbody>
                    {filtered.map((row) => {
                      const { state, error } = stateOf(row);
                      const key = jobKey(row);
                      const job = jobs[key];
                      return (
                        <tr key={row.workload_id} className={`border-b hover:bg-gray-50 ${selected.has(row.workload_id) ? "bg-brand/5" : ""}`}>
                          <td className="px-2 py-1.5">
                            <input type="checkbox" checked={selected.has(row.workload_id)} disabled={row.demo}
                              onChange={() => toggleOne(row.workload_id)} aria-label={`Select ${row.name}`} />
                          </td>
                          <td className="px-2 py-1.5">
                            <button onClick={() => onOpenWorkload(row.workload_id, row.connection_id)}
                              className="text-left font-medium text-gray-800 hover:text-brand hover:underline">{row.name}</button>
                            <div className="flex gap-1 text-[10px] text-gray-400">
                              {row.environment && <span>{row.environment}</span>}
                              {row.demo && <span className="rounded bg-indigo-50 px-1 text-indigo-600">demo</span>}
                              {row.partial && <span className="rounded bg-amber-50 px-1 text-amber-600" title={row.errors.join(", ")}>partial</span>}
                            </div>
                          </td>
                          <td className="px-2 py-1.5">
                            {state === "running" ? <span className="inline-flex items-center gap-1 text-brand"><span className="animate-spin">↻</span>analyzing…</span>
                              : state === "queued" ? <span className="text-gray-400">queued</span>
                                : state === "failed" ? <span className="rounded bg-red-50 px-1.5 py-0.5 font-medium text-red-700" title={error}>⚠ failed</span>
                                  : !row.has_analysis ? <span className="text-gray-400">never</span>
                                    : <PercentPill value={row.pct_protected} />}
                          </td>
                          <td className="px-2 py-1.5 tabular-nums text-gray-600">{row.has_analysis ? row.protected_items : "—"}</td>
                          <td className={`px-2 py-1.5 tabular-nums ${row.gaps ? "font-semibold text-red-600" : "text-gray-400"}`}>{row.has_analysis ? row.gaps : "—"}</td>
                          <td className={`px-2 py-1.5 tabular-nums ${row.failed_jobs ? "font-semibold text-red-600" : "text-gray-400"}`}>{row.has_analysis ? row.failed_jobs : "—"}</td>
                          <td className="px-2 py-1.5 tabular-nums text-gray-600">{row.has_analysis && row.rpo_attainment_pct != null ? `${row.rpo_attainment_pct}%` : "—"}</td>
                          <td className="px-2 py-1.5 tabular-nums text-gray-600">
                            {row.has_analysis ? <span title={`${row.red_vaults} vault(s) at risk`}>{row.posture_score}{row.red_vaults ? <span className="ml-1 text-red-600">· {row.red_vaults} red</span> : null}</span> : "—"}
                          </td>
                          <td className="px-2 py-1.5 tabular-nums text-gray-600">{row.has_analysis ? fmtMoney(row.monthly_cost, row.currency) : "—"}</td>
                          <td className="px-2 py-1.5 text-gray-500" title={job?.last_message || row.run_at}>
                            {state === "running" ? (job?.last_message ? job.last_message.slice(0, 42) : "starting…")
                              : state === "failed" ? "failed — retry"
                                : relTime(row.run_at)}
                          </td>
                          <td className="px-2 py-1.5">
                            <button onClick={() => onOpenWorkload(row.workload_id, row.connection_id)}
                              className="rounded border px-2 py-0.5 text-[11px] text-gray-600 hover:bg-gray-50">Open ▸</button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              )}
      </div>
    </div>
  );
}
