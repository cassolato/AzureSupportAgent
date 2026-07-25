/**
 * Projects a Backup Manager snapshot into a protection-flow graph.
 *
 * The chain the operator cares about is "what is protected, by which policy, into which
 * vault, and how is it ending up" — plus the resources that are protected by nothing at all.
 * Both branches are drawn in one picture, because coverage is only meaningful next to the
 * gaps, and a diagram that quietly omitted unprotected resources would look reassuring while
 * hiding the risk.
 *
 * Pure: no requests, no clock, no randomness. Everything comes from the snapshot the operator
 * already analyzed, so the flow never disagrees with the tabs beside it.
 */
import type { BackupSnapshot } from "../../api";

export type FlowDimension =
  | "subscription" | "workload" | "resource_group" | "resource_type"
  | "item" | "policy" | "vault" | "vault_kind" | "redundancy" | "region" | "outcome";

export type FlowWeight = "count" | "cost";

export const DIMENSION_LABELS: Record<FlowDimension, string> = {
  subscription: "Subscription",
  workload: "Workload",
  resource_group: "Resource group",
  resource_type: "Resource type",
  item: "Protected item",
  policy: "Policy",
  vault: "Vault",
  vault_kind: "Vault kind",
  redundancy: "Redundancy",
  region: "Region",
  outcome: "Outcome",
};

/** Six columns read comfortably on a laptop; the rest are opt-in. */
export const DEFAULT_CHAIN: FlowDimension[] = [
  "subscription", "workload", "resource_type", "policy", "vault", "outcome",
];

/** A chain shorter than this is not a flow, it is a bar chart. */
const MIN_CHAIN = 2;

/**
 * A named, reloadable configuration of the flow.
 *
 * The weighting travels with the columns on purpose: "Spend by policy" is a chain *and* a
 * weighting, so restoring only the columns would reload half a view and look broken.
 */
export type FlowPerspective = {
  chain: FlowDimension[];
  weight: FlowWeight;
  outcomes: Outcome[];
};

/**
 * Make a chain from storage safe to render.
 *
 * Unlike a stale filter string — which simply matches nothing — a stale *column* feeds graph
 * construction, so a dimension we later rename or drop would produce an empty or malformed
 * chart with no explanation. Unknown and duplicate entries are discarded, and a chain left too
 * short falls back to the default rather than rendering something degenerate.
 */
export function sanitizeChain(value: unknown): FlowDimension[] {
  const known = new Set(Object.keys(DIMENSION_LABELS));
  const chain = Array.isArray(value)
    ? value.filter((entry): entry is FlowDimension => typeof entry === "string" && known.has(entry))
    : [];
  const deduped = chain.filter((dimension, index) => chain.indexOf(dimension) === index);
  return deduped.length >= MIN_CHAIN ? deduped : [...DEFAULT_CHAIN];
}

/** Restore a stored perspective, tolerating anything an older version may have written. */
export function sanitizePerspective(value: unknown): FlowPerspective {
  const raw = (value ?? {}) as Partial<FlowPerspective>;
  const outcomes = Array.isArray(raw.outcomes)
    ? raw.outcomes.filter((outcome): outcome is Outcome => outcome in OUTCOME_LABELS)
    : [];
  return {
    chain: sanitizeChain(raw.chain),
    weight: raw.weight === "cost" ? "cost" : "count",
    outcomes,
  };
}

/** Everything an operator would want to act on — i.e. not "healthy". */
const PROBLEM_OUTCOMES: Outcome[] = ["unprotected", "orphaned", "stopped", "failing", "rpo_breached"];

/**
 * Starter perspectives, so the feature is useful before anyone has saved anything.
 *
 * Each answers a different question from the same data, which is the point of making the
 * columns configurable at all. Several carry an outcome filter, because "show me only the
 * broken items, grouped this way" is a different view from the same chain unfiltered.
 */
export const FLOW_PRESETS: { name: string; perspective: FlowPerspective }[] = [
  {
    name: "Coverage by workload",
    perspective: { chain: ["workload", "resource_type", "outcome"], weight: "count", outcomes: [] },
  },
  {
    name: "Spend by policy",
    perspective: { chain: ["resource_type", "policy", "vault"], weight: "cost", outcomes: [] },
  },
  {
    name: "Redundancy posture",
    perspective: { chain: ["vault", "redundancy", "outcome"], weight: "count", outcomes: [] },
  },
  {
    // Triage: drop the healthy majority and show what is actually wrong, item by item.
    name: "Needs attention",
    perspective: {
      chain: ["workload", "resource_type", "item", "outcome"],
      weight: "count",
      outcomes: PROBLEM_OUTCOMES,
    },
  },
  {
    // A remediation worklist: unprotected resources grouped the way ownership usually is.
    name: "Gaps to assign",
    perspective: {
      chain: ["workload", "resource_group", "resource_type"],
      weight: "count",
      outcomes: ["unprotected"],
    },
  },
  {
    // Chargeback: which subscription is paying for which vault, in real money.
    name: "Chargeback by subscription",
    perspective: { chain: ["subscription", "vault", "resource_type"], weight: "cost", outcomes: [] },
  },
  {
    // Consolidation: how many vaults and policies each region and vault kind carries.
    name: "Vault sprawl",
    perspective: { chain: ["region", "vault_kind", "vault", "policy"], weight: "count", outcomes: [] },
  },
];

export const NODE_COLORS: Record<string, string> = {
  subscription: "#2563eb",
  workload: "#7c3aed",
  resource_group: "#64748b",
  resource_type: "#0891b2",
  item: "#0ea5e9",
  policy: "#f59e0b",
  vault: "#16a34a",
  vault_kind: "#15803d",
  redundancy: "#0d9488",
  region: "#6366f1",
  outcome: "#475569",
  unprotected: "#dc2626",
};

/** Outcome buckets, worst first — an item is reported by its most serious problem. */
export type Outcome = "unprotected" | "orphaned" | "stopped" | "failing" | "rpo_breached" | "healthy";

export const OUTCOME_LABELS: Record<Outcome, string> = {
  unprotected: "Unprotected",
  orphaned: "Orphaned (still billing)",
  stopped: "Stopped (data retained)",
  failing: "Last backup failed",
  rpo_breached: "No recent recovery point",
  healthy: "Protected and healthy",
};

const OUTCOME_STATUS: Record<Outcome, string> = {
  unprotected: "error", orphaned: "error", stopped: "warning",
  failing: "error", rpo_breached: "warning", healthy: "ok",
};

/** Beyond this an item has no recent recovery point worth relying on. */
export const STALE_RECOVERY_POINT_HOURS = 48;

export type FlowFilters = {
  /** Restrict to these outcomes; empty means all. */
  outcomes?: Outcome[];
  vaultId?: string;
  resourceType?: string;
  /** Include the unprotected branch. */
  includeGaps?: boolean;
};

type Row = {
  key: string;
  values: Partial<Record<FlowDimension, { id: string; name: string }>>;
  outcome: Outcome;
  count: number;
  cost: number;
  itemId: string;
  gapId: string;
};

/**
 * A stable identity and label for an item's policy.
 *
 * Several protected items can carry a policy id but no display name; keying on the name alone
 * would draw them as a row of identical "No policy" bars that are actually different policies.
 * Items with genuinely no policy do collapse into one node, because that is one finding.
 */
function policyOf(policyId: string, policyName: string): { id: string; name: string } {
  const name = String(policyName || "").trim();
  const id = String(policyId || "").trim();
  if (name) return { id: `policy:${id || name}`, name };
  if (id) return { id: `policy:${id}`, name: id.split("/").filter(Boolean).pop() || "Unnamed policy" };
  return { id: "policy:none", name: "No policy" };
}

export function outcomeOf(item: BackupSnapshot["inventory"]["rows"][number]): Outcome {
  if (item.orphaned) return "orphaned";
  if (item.protection_stopped) return "stopped";
  if ((item.last_backup_status || "").toLowerCase() === "failed" || item.last_error_code) return "failing";
  const age = item.recovery_point_age_hours;
  if (age === null || age === undefined || age > STALE_RECOVERY_POINT_HOURS) return "rpo_breached";
  return "healthy";
}

/**
 * Workload membership for a resource, from the workloads catalog.
 *
 * A resource can belong to several workloads, or to none; both are real states an operator
 * needs to see rather than have silently folded into one bucket.
 */
export type WorkloadCatalogEntry = { id: string; name: string; resourceIds: string[] };

function workloadFor(datasourceId: string, catalog: WorkloadCatalogEntry[]): { id: string; name: string } {
  const needle = String(datasourceId || "").toLowerCase();
  if (!needle) return { id: "workload:unmapped", name: "Unmapped" };
  const hits = catalog.filter((workload) => workload.resourceIds.some((id) => {
    const candidate = id.toLowerCase();
    return candidate === needle || needle.startsWith(`${candidate}/`) || candidate.startsWith(`${needle}/`);
  }));
  if (!hits.length) return { id: "workload:unmapped", name: "Unmapped" };
  if (hits.length > 1) return { id: "workload:shared", name: "Shared across workloads" };
  return { id: `workload:${hits[0].id}`, name: hits[0].name };
}

function moneyFor(snapshot: BackupSnapshot, instanceId: string): number {
  const allocated = snapshot.cost?.allocation?.rows?.find((row) => row.instance_id === instanceId);
  if (allocated && Number.isFinite(allocated.allocated_cost)) return Number(allocated.allocated_cost);
  const estimated = snapshot.cost?.top_rows?.find((row) => row.instance_id === instanceId);
  return estimated && Number.isFinite(estimated.monthly_cost) ? Number(estimated.monthly_cost) : 0;
}

/** Every protected item and every gap, flattened into one row per flow. */
export function flowRows(
  snapshot: BackupSnapshot,
  catalog: WorkloadCatalogEntry[],
  filters: FlowFilters = {},
): Row[] {
  const rows: Row[] = [];
  const vaultById = new Map(
    (snapshot.vaults?.vaults ?? []).map((vault) => [String(vault.id).toLowerCase(), vault]),
  );

  for (const item of snapshot.inventory?.rows ?? []) {
    const outcome = outcomeOf(item);
    const vault = vaultById.get(String(item.vault_id).toLowerCase());
    const redundancy = item.vault_redundancy || vault?.redundancy || "Unknown redundancy";
    rows.push({
      key: `item:${item.id}`,
      itemId: item.id,
      gapId: "",
      outcome,
      count: 1,
      cost: moneyFor(snapshot, item.id),
      values: {
        subscription: { id: `sub:${item.subscription_id}`, name: item.subscription_id || "Unknown subscription" },
        workload: workloadFor(item.datasource_id, catalog),
        resource_group: { id: `rg:${item.resource_group}`, name: item.resource_group || "No resource group" },
        resource_type: { id: `type:${item.datasource_type}`, name: item.datasource_type || "Unknown type" },
        item: { id: `item:${item.id}`, name: item.friendly_name || item.name },
        policy: policyOf(item.policy_id, item.policy_name),
        vault: { id: `vault:${item.vault_id}`, name: item.vault_name },
        vault_kind: { id: `kind:${item.vault_kind}`, name: item.vault_kind === "backup" ? "Backup vault" : "Recovery Services vault" },
        redundancy: { id: `red:${redundancy}`, name: redundancy },
        region: { id: `region:${item.location}`, name: item.location || "Unknown region" },
        outcome: { id: `outcome:${outcome}`, name: OUTCOME_LABELS[outcome] },
      },
    });
  }

  if (filters.includeGaps !== false) {
    for (const gap of snapshot.gaps?.gaps ?? []) {
      rows.push({
        key: `gap:${gap.gap_id}`,
        itemId: "",
        gapId: gap.gap_id,
        outcome: "unprotected",
        count: 1,
        cost: 0,
        values: {
          subscription: { id: `sub:${gap.subscription_id}`, name: gap.subscription_id || "Unknown subscription" },
          workload: workloadFor(gap.resource_id, catalog),
          resource_group: { id: `rg:${gap.resource_group}`, name: gap.resource_group || "No resource group" },
          resource_type: { id: `type:${gap.display_type || gap.resource_type}`, name: gap.display_type || gap.resource_type },
          item: { id: `gapitem:${gap.resource_id}`, name: gap.resource_name },
          // A gap has no policy or vault; naming that explicitly is the point of the diagram.
          policy: { id: "policy:none", name: "No policy" },
          vault: { id: "vault:none", name: "No vault" },
          vault_kind: { id: "kind:none", name: "No vault" },
          redundancy: { id: "red:none", name: "No redundancy" },
          region: { id: `region:${gap.location}`, name: gap.location || "Unknown region" },
          outcome: { id: "outcome:unprotected", name: OUTCOME_LABELS.unprotected },
        },
      });
    }
  }

  return rows.filter((row) => {
    if (filters.outcomes?.length && !filters.outcomes.includes(row.outcome)) return false;
    if (filters.vaultId && row.values.vault?.id !== `vault:${filters.vaultId}`) return false;
    if (filters.resourceType && row.values.resource_type?.name !== filters.resourceType) return false;
    return true;
  });
}

export type BackupFlowGraph = {
  nodes: { id: string; name: string; kind: string; status?: string; resource_type?: string; meta?: Record<string, unknown> }[];
  links: { source: string; target: string; value: number; status?: string }[];
  totals: { rows: number; count: number; cost: number };
  byOutcome: Record<Outcome, number>;
};

/**
 * Build the Sankey graph for a chain of dimensions.
 *
 * Node ids are prefixed by their column so the same value appearing in two columns — a
 * subscription id used as both scope and region, say — cannot collapse into one node and
 * create a false loop.
 */
export function buildBackupFlowGraph(
  snapshot: BackupSnapshot,
  {
    chain = DEFAULT_CHAIN,
    weight = "count",
    catalog = [],
    filters = {},
  }: { chain?: FlowDimension[]; weight?: FlowWeight; catalog?: WorkloadCatalogEntry[]; filters?: FlowFilters } = {},
): BackupFlowGraph {
  const rows = flowRows(snapshot, catalog, filters);
  const nodes = new Map<string, BackupFlowGraph["nodes"][number]>();
  const links = new Map<string, BackupFlowGraph["links"][number]>();
  const byOutcome = {
    unprotected: 0, orphaned: 0, stopped: 0, failing: 0, rpo_breached: 0, healthy: 0,
  } as Record<Outcome, number>;
  let totalCount = 0;
  let totalCost = 0;

  const columns = chain.filter((dimension, index) => chain.indexOf(dimension) === index);

  for (const row of rows) {
    byOutcome[row.outcome] += 1;
    totalCount += row.count;
    totalCost += row.cost;
    // Cost-weighted links must never be zero-width, or an item with no attributable spend
    // would silently vanish from the diagram rather than showing as a hairline.
    const value = weight === "cost" ? Math.max(row.cost, 0.0001) : row.count;

    const present = columns
      .map((dimension) => ({ dimension, value: row.values[dimension] }))
      .filter((entry): entry is { dimension: FlowDimension; value: { id: string; name: string } } => !!entry.value);

    for (let index = 0; index < present.length; index += 1) {
      const { dimension, value: current } = present[index];
      const nodeId = `${dimension}::${current.id}`;
      const isUnprotected = dimension === "outcome" && row.outcome === "unprotected";
      if (!nodes.has(nodeId)) {
        nodes.set(nodeId, {
          id: nodeId,
          name: current.name,
          kind: isUnprotected ? "unprotected" : dimension,
          status: dimension === "outcome" ? OUTCOME_STATUS[row.outcome] : "ok",
          resource_type: dimension === "resource_type" || dimension === "item" ? row.values.resource_type?.name : undefined,
          meta: {
            dimension,
            outcome: dimension === "outcome" ? row.outcome : undefined,
            vault_id: dimension === "vault" ? current.id.replace(/^vault:/, "") : undefined,
            policy_id: dimension === "policy" ? current.id.replace(/^policy:/, "") : undefined,
            instance_id: dimension === "item" ? row.itemId : undefined,
          },
        });
      }
      if (index === 0) continue;
      const previous = `${present[index - 1].dimension}::${present[index - 1].value.id}`;
      const status = row.outcome === "unprotected" ? "error" : "ok";
      const key = `${previous}|${nodeId}|${status}`;
      const existing = links.get(key);
      if (existing) existing.value += value;
      else links.set(key, { source: previous, target: nodeId, value, status });
    }
  }

  return {
    nodes: [...nodes.values()],
    links: [...links.values()],
    totals: { rows: rows.length, count: totalCount, cost: Math.round(totalCost * 100) / 100 },
    byOutcome,
  };
}
