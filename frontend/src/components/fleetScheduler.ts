// Shared, MODULE-LEVEL fleet launch scheduler.
//
// Both the Performance Profiler and Change Explorer "Fleet" views mass-launch background jobs
// (profile / analyze) across many workloads at a bounded concurrency. Previously each view kept
// its pending queue in COMPONENT state + a scheduler useEffect — so switching tabs / navigating
// away unmounted the component and SILENTLY DROPPED every not-yet-started job (only the in-flight
// ones, held by the module-level run registries, survived). It also caused a refetch storm.
//
// This module hoists the queue to MODULE scope and SELF-DRIVES it: each active queue subscribes
// to its run-registry's change notifications and re-drains itself whenever a run starts/finishes,
// independent of any mounted component. The queue therefore survives navigation, and components
// only need to (a) call `enqueueFleet(...)` and (b) read `fleetQueuedKeys` / `fleetRunningCount`
// for display (reactive via `useFleetQueue`).
import { useSyncExternalStore } from "react";

export interface FleetJob {
  /** Unique scope key for the job, e.g. `workload:<id>`. Used for dedupe + running checks. */
  key: string;
  /** Start the job (fire-and-forget; must register itself so `isRunning(key)` flips true). */
  run: () => void;
}

interface QueueState {
  pending: FleetJob[];
  started: Set<string>;
  maxParallel: number;
  staggerMs: number;
  lastStartAt: number;
  draining: boolean;       // re-entrancy guard (a job's synchronous run() can re-trigger _drain)
  redrainRequested: boolean;
  isRunning: (key: string) => boolean;
  unsubscribe?: () => void;
}

const _queues = new Map<string, QueueState>();

// Ceiling on jobs in flight across ALL queues, not just one.
//
// Each queue caps ITSELF (maxParallel 2-3), but the caps were independent: launching the
// monitoring, telemetry and performance fleets together ran 9 estate scans at once. Every one
// of those scans hammers Azure Resource Graph, which meters ~15 queries per 5 seconds PER
// SECURITY PRINCIPAL — and workloads sharing a connection share that one budget. The result
// was self-inflicted 429s that surfaced as failed scans.
//
// The server-side limiter (app/azure/arg_throttle.py) is the authoritative defence, since it
// also sees other tabs, the scheduler and Mission Control. This cap is the client's half: it
// stops the browser queueing far more work than the backend can pace, which would otherwise
// just convert throttling into long unexplained waits.
const GLOBAL_MAX_PARALLEL = 4;

// Re-drain poll used when the global cap (not a queue's own cap) is what's blocking. Queues
// subscribe to their OWN run registry, so queue B is never notified when queue A's job frees a
// global slot; this timer closes that gap.
const GLOBAL_REDRAIN_MS = 250;
let _globalTimer: number | null = null;

let _version = 0;
const _subs = new Set<() => void>();
function _bump() {
  _version += 1;
  for (const s of _subs) s();
}

/** Subscribe a component to queue changes (queued keys / running counts). */
export function useFleetQueue(): number {
  return useSyncExternalStore(
    (cb) => {
      _subs.add(cb);
      return () => {
        _subs.delete(cb);
      };
    },
    () => _version,
    () => _version,
  );
}

/** The set of keys currently WAITING (not yet started) in a queue. */
export function fleetQueuedKeys(queueId: string): Set<string> {
  const q = _queues.get(queueId);
  return new Set(q ? q.pending.map((j) => j.key) : []);
}

/** How many jobs this queue has launched that are still running. */
export function fleetRunningCount(queueId: string): number {
  return _queues.get(queueId)?.started.size ?? 0;
}

/** Total jobs still outstanding (queued + running) — drives "N running" + button disable. */
export function fleetOutstanding(queueId: string): number {
  const q = _queues.get(queueId);
  return q ? q.pending.length + q.started.size : 0;
}

/** Drop finished jobs from a queue's started set (its run registry is the source of truth). */
function _reap(q: QueueState): void {
  for (const k of [...q.started]) {
    if (!q.isRunning(k)) q.started.delete(k);
  }
}

/** Live job count across every queue, reaping finished jobs first so the count is exact. */
function _runningTotal(): number {
  let total = 0;
  for (const q of _queues.values()) {
    _reap(q);
    total += q.started.size;
  }
  return total;
}

function _pendingAnywhere(): boolean {
  for (const q of _queues.values()) {
    if (q.pending.length > 0) return true;
  }
  return false;
}

/** Poll every queue again shortly — used when the GLOBAL cap is the blocker. */
function _scheduleGlobalRedrain(): void {
  if (_globalTimer != null || !_pendingAnywhere()) return;
  _globalTimer = window.setTimeout(() => {
    _globalTimer = null;
    for (const id of [..._queues.keys()]) _drain(id);
  }, GLOBAL_REDRAIN_MS);
}

/**
 * Enqueue jobs into a named queue and (re)start draining. Idempotent per key: a key already
 * queued or already running is skipped, so double-clicking Launch can't double-run a workload.
 *
 * @param subscribe the run-registry's change subscription — lets the queue self-drive (re-drain
 *                  when a run finishes) even while no component is mounted.
 */
export function enqueueFleet(
  queueId: string,
  jobs: FleetJob[],
  opts: {
    maxParallel: number;
    isRunning: (key: string) => boolean;
    subscribe: (cb: () => void) => () => void;
    /** Minimum gap between two job STARTS (ms) — spreads the launch herd so we don't hit Azure's
     *  per-tenant rate limit in the same instant. 0 = no stagger. */
    staggerMs?: number;
  },
): void {
  let q = _queues.get(queueId);
  if (!q) {
    q = {
      pending: [],
      started: new Set(),
      maxParallel: opts.maxParallel,
      staggerMs: opts.staggerMs ?? 0,
      lastStartAt: 0,
      draining: false,
      redrainRequested: false,
      isRunning: opts.isRunning,
    };
    _queues.set(queueId, q);
    // Self-drive: re-drain on every run-registry change until the queue empties.
    q.unsubscribe = opts.subscribe(() => _drain(queueId));
  }
  q.maxParallel = opts.maxParallel;
  q.staggerMs = opts.staggerMs ?? q.staggerMs;
  q.isRunning = opts.isRunning;
  for (const j of jobs) {
    if (q.pending.some((p) => p.key === j.key)) continue;
    if (q.started.has(j.key)) continue;
    if (opts.isRunning(j.key)) continue;
    q.pending.push(j);
  }
  _drain(queueId);
}

function _drain(queueId: string): void {
  const q = _queues.get(queueId);
  if (!q) return;
  // Re-entrancy guard: a job's run() synchronously notifies the run-registry, which synchronously
  // calls THIS queue's subscriber (-> _drain) again mid-loop. Without the guard the nested drain
  // over-fills (stale slot count) and the real concurrency blows past maxParallel — which throttled
  // Azure and dropped the tail of big batches. Coalesce nested calls into one re-drain pass.
  if (q.draining) {
    q.redrainRequested = true;
    return;
  }
  q.draining = true;
  try {
    do {
      q.redrainRequested = false;
      // Reap jobs we started that are no longer running.
      _reap(q);
      // Fill open slots ONE AT A TIME, re-reading started.size each iteration so the cap is exact.
      while (q.started.size < q.maxParallel && q.pending.length > 0) {
        // Respect the cross-queue ceiling as well as this queue's own. Another fleet may be
        // using the budget; wait for a slot rather than piling more scans onto Azure.
        if (_runningTotal() >= GLOBAL_MAX_PARALLEL) {
          _scheduleGlobalRedrain();
          break;
        }
        // Honor the start stagger: if not enough time has passed since the last start, defer the
        // next fill to a timer instead of bursting. (Re-drain fires again after the gap.)
        if (q.staggerMs > 0) {
          const now = Date.now();
          const wait = q.lastStartAt + q.staggerMs - now;
          if (wait > 0) {
            window.setTimeout(() => _drain(queueId), wait);
            break;
          }
        }
        const job = q.pending.shift();
        if (!job) break;
        q.started.add(job.key);
        q.lastStartAt = Date.now();
        try {
          // run() may synchronously re-enter _drain; the guard above turns that into redrainRequested.
          job.run();
        } catch {
          q.started.delete(job.key);
        }
      }
    } while (q.redrainRequested);
  } finally {
    q.draining = false;
  }
  // Tear the queue down once fully drained so a future batch re-subscribes cleanly.
  if (q.pending.length === 0 && q.started.size === 0) {
    q.unsubscribe?.();
    _queues.delete(queueId);
  }
  // This queue may have just freed a global slot another queue is waiting on.
  _scheduleGlobalRedrain();
  _bump();
}
